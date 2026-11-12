#!/usr/bin/env python3
"""Execute one untrusted WASI Preview 1 module.

This file is deliberately a standalone script: the API starts a fresh Python
interpreter for it for every request.  The uploaded module never receives host
paths, environment variables, preopened directories, or sockets.

Two modes share the same process-isolation guarantees:

legacy mode (3 arguments): ``runner.py MODULE LOG``
    Used by ``POST /api/v1/analyze``.  The full WASI preview-1 surface is
    linked (with no preopens, empty environment, stdin bound to the log).

restricted mode (6 arguments):
    ``runner.py MODULE LOG MODE RECORD_PATH RESULT_PATH``
    Used by the recording and replay endpoints.  Only four WASI imports are
    linkable -- ``fd_read``, ``fd_write``, ``proc_exit`` and ``random_get`` --
    and each is implemented in this file so that ``random_get`` can be either
    recorded (fresh entropy, captured) or replayed (recorded bytes injected).
    ``MODE`` is either ``record`` or ``replay``.  In replay mode RECORD_PATH
    is a JSON file holding the recorded calls; in record mode it is ignored.
    RESULT_PATH receives either the recording summary or a structured replay
    failure, so stdout/stderr stay the plugin's own undecorated output.

Exit codes:
    0   plugin returned normally (or called proc_exit(0))
    20  module failed validation/compilation
    21  instantiation or import linking failed
    22  the module trapped
    23  the module called proc_exit with a non-zero status
    24  the module has no _start export
    25  _start has the wrong signature
    26  unexpected runner failure
    27  a recording limit (256 calls / 32 KiB) was exceeded
    28  the module imports something outside the four allowed WASI functions
    29  deterministic replay diverged (a structured failure was written)
"""

import json
import os
import secrets
import sys

import wasmtime

EXIT_INVALID_MODULE = 20
EXIT_INSTANTIATE = 21
EXIT_TRAP = 22
EXIT_NONZERO_EXIT = 23
EXIT_NO_START = 24
EXIT_BAD_START = 25
EXIT_INTERNAL = 26
EXIT_RECORDING_LIMIT = 27
EXIT_IMPORT_NOT_ALLOWED = 28
EXIT_REPLAY_MISMATCH = 29

MEM_LIMIT = 64 * 1024 * 1024
TABLE_ELEMENT_LIMIT = 100_000

# Recording budgets, mirrored from app.config so the runner script has no
# import-time dependency on the package (it is launched with -I and cwd=/).
MAX_RANDOM_RECORDS = 256
MAX_RANDOM_BYTES = 32 * 1024

# WASI preview-1 errno values used by the four implemented imports.
ERRNO_SUCCESS = 0
ERRNO_BADF = 8

WASI_MODULE = "wasi_snapshot_preview1"
ALLOWED_IMPORTS = frozenset(
    {"fd_read", "fd_write", "proc_exit", "random_get"}
)


class _ProcExit(Exception):
    """Raised by the restricted proc_exit shim with the guest's exit code."""

    def __init__(self, code: int) -> None:
        super().__init__(f"proc_exit({code})")
        self.code = code


class _RecordingLimit(Exception):
    """Raised when a recording crosses the call-count or byte budget."""


class _ReplayDivergence(Exception):
    """Raised when replay cannot follow the recorded random_get sequence."""

    def __init__(self, reason: str, call_index: int) -> None:
        super().__init__(f"{reason} at random_get call {call_index}")
        self.reason = reason
        self.call_index = call_index


def fail(code: int, message: str) -> None:
    sys.stderr.write(f"runner: {message}\n")
    sys.stderr.flush()
    raise SystemExit(code)


def _new_engine_and_store() -> tuple[wasmtime.Engine, wasmtime.Store]:
    config = wasmtime.Config()
    config.wasm_component_model = False
    config.wasm_threads = False
    engine = wasmtime.Engine(config)

    store = wasmtime.Store(engine)
    store.set_limits(
        memory_size=MEM_LIMIT,
        table_elements=TABLE_ELEMENT_LIMIT,
        instances=1,
        tables=1,
        memories=1,
    )
    return engine, store


def _load_module(engine: wasmtime.Engine, module_path: str) -> wasmtime.Module:
    try:
        return wasmtime.Module.from_file(engine, module_path)
    except wasmtime.WasmtimeError:
        fail(EXIT_INVALID_MODULE, "module is not valid WebAssembly")
    except Exception:
        fail(EXIT_INVALID_MODULE, "module could not be read")


def _check_start_signature(instance: wasmtime.Instance, store: wasmtime.Store) -> None:
    try:
        exports = instance.exports(store)
        if "_start" not in exports:
            fail(EXIT_NO_START, "module has no _start export")
        start = exports["_start"]
        if not isinstance(start, wasmtime.Func):
            fail(EXIT_BAD_START, "_start is not a function")
        func_type = start.type(store)
        if len(func_type.params) != 0 or len(func_type.results) != 0:
            fail(EXIT_BAD_START, "_start must take no arguments and return nothing")
    except SystemExit:
        raise
    except Exception:
        fail(EXIT_INTERNAL, "could not inspect module exports")


def _run_legacy(module_path: str, log_path: str) -> None:
    """Full-WASI run used by /api/v1/analyze (unchanged behaviour)."""
    try:
        engine, store = _new_engine_and_store()

        wasi = wasmtime.WasiConfig()
        # No inherited environment, no inherited argument vector, and no
        # preopened directories.  argv[0] is a harmless fixed label.
        wasi.argv = ["endpoint-plugin"]
        wasi.env = []
        wasi.stdin_file = log_path
        # The parent owns these pipes and enforces the combined size limit.
        wasi.inherit_stdout()
        wasi.inherit_stderr()
        store.set_wasi(wasi)
        linker = wasmtime.Linker(engine)
        linker.define_wasi()
    except Exception as exc:  # noqa: BLE001 - translated to a runner code
        fail(EXIT_INTERNAL, f"could not initialize WASI: {exc.__class__.__name__}")

    module = _load_module(engine, module_path)

    try:
        instance = linker.instantiate(store, module)
    except wasmtime.ExitTrap as exc:
        # A start section is allowed to exit, but it must exit cleanly.
        raise SystemExit(0 if exc.code == 0 else EXIT_NONZERO_EXIT)
    except wasmtime.Trap:
        fail(EXIT_TRAP, "module trapped during instantiation")
    except wasmtime.WasmtimeError:
        fail(EXIT_INSTANTIATE, "module imports could not be linked")
    except Exception:
        fail(EXIT_INSTANTIATE, "module instantiation failed")

    _check_start_signature(instance, store)

    try:
        instance.exports(store)["_start"](store)
    except wasmtime.ExitTrap as exc:
        raise SystemExit(0 if exc.code == 0 else EXIT_NONZERO_EXIT)
    except wasmtime.Trap:
        fail(EXIT_TRAP, "module trapped")
    except wasmtime.WasmtimeError:
        # A WASI import can also fail with a runtime error rather than raising
        # wasmtime.Trap (for example, a missing exported memory).
        fail(EXIT_TRAP, "module trapped")
    except SystemExit:
        raise
    except Exception:
        fail(EXIT_INTERNAL, "unexpected failure while running module")


class _RestrictedRuntime:
    """Linker shims for the four permitted WASI preview-1 imports.

    Recording and replay use identical I/O and differ only in how random_get
    is served, so fd_read/fd_write/proc_exit are shared by both modes.
    """

    def __init__(self, log_bytes: bytes, mode: str, records: list[dict]) -> None:
        self._log = log_bytes
        self._stdin_pos = 0
        self._mode = mode
        # In record mode this queue is appended to; in replay mode it starts
        # with a private copy of the recorded calls and is consumed from the
        # front, leaving the caller's original list intact for the final
        # full-consumption check.
        self._queue = list(records)
        self._consumed = 0
        self._recorded_random_bytes = 0

    # -- helpers ---------------------------------------------------------

    def _memory(self, caller: wasmtime.Caller) -> wasmtime.Memory:
        memory = caller.get("memory")
        if not isinstance(memory, wasmtime.Memory):
            # A module calling an import that touches guest memory must export
            # a memory; wasmtime itself rejects the missing-export case, this
            # is a defensive guard.
            raise wasmtime.Trap("module does not export a memory")
        return memory

    def _read_iovs(
        self,
        memory: wasmtime.Memory,
        store: wasmtime.Store,
        iovs: int,
        iovs_len: int,
    ) -> list[tuple[int, int]]:
        pairs = []
        for i in range(iovs_len):
            base = iovs + i * 8
            # Memory.read takes an end index, not a length.
            ptr = int.from_bytes(memory.read(store, base, base + 4), "little")
            length = int.from_bytes(
                memory.read(store, base + 4, base + 8), "little"
            )
            pairs.append((ptr, length))
        return pairs

    # -- fd_read ---------------------------------------------------------

    def fd_read(
        self,
        caller: wasmtime.Caller,
        fd: int,
        iovs: int,
        iovs_len: int,
        nread: int,
    ) -> int:
        if fd != 0:
            return ERRNO_BADF
        memory = self._memory(caller)
        total = 0
        try:
            for ptr, length in self._read_iovs(memory, caller, iovs, iovs_len):
                if length == 0:
                    continue
                remaining = len(self._log) - self._stdin_pos
                chunk_len = min(length, remaining)
                chunk = self._log[self._stdin_pos : self._stdin_pos + chunk_len]
                memory.write(caller, chunk, ptr)
                self._stdin_pos += chunk_len
                total += chunk_len
                if chunk_len < length:
                    # Short read: stdin reached EOF in the middle of the iovec.
                    break
            memory.write(caller, total.to_bytes(4, "little"), nread)
        except wasmtime.Trap:
            raise
        except Exception as exc:  # noqa: BLE001 - out-of-bounds guest pointers
            raise wasmtime.Trap(f"fd_read memory error: {exc.__class__.__name__}")
        return ERRNO_SUCCESS

    # -- fd_write --------------------------------------------------------

    def fd_write(
        self,
        caller: wasmtime.Caller,
        fd: int,
        iovs: int,
        iovs_len: int,
        nwritten: int,
    ) -> int:
        if fd not in (1, 2):
            return ERRNO_BADF
        memory = self._memory(caller)
        total = 0
        try:
            for ptr, length in self._read_iovs(memory, caller, iovs, iovs_len):
                if length == 0:
                    continue
                payload = bytes(memory.read(caller, ptr, ptr + length))
                # os.write bypasses Python buffering so the parent sees the
                # exact guest byte stream and its own output cap applies.
                written = os.write(fd, payload)
                total += written
                if written != length:
                    break
            memory.write(caller, total.to_bytes(4, "little"), nwritten)
        except wasmtime.Trap:
            raise
        except Exception as exc:  # noqa: BLE001
            raise wasmtime.Trap(f"fd_write memory error: {exc.__class__.__name__}")
        return ERRNO_SUCCESS

    # -- proc_exit -------------------------------------------------------

    def proc_exit(self, _caller: wasmtime.Caller, code: int) -> None:
        raise _ProcExit(code)

    # -- random_get ------------------------------------------------------

    def random_get_record(
        self, caller: wasmtime.Caller, buf: int, buf_len: int
    ) -> int:
        index = len(self._queue)
        if (
            index >= MAX_RANDOM_RECORDS
            or self._recorded_random_bytes + buf_len > MAX_RANDOM_BYTES
        ):
            # The run is killed by the runner after this propagates; the
            # caller never receives a half-finished recording package.
            raise _RecordingLimit()

        payload = secrets.token_bytes(buf_len)
        self._recorded_random_bytes += buf_len
        try:
            self._memory(caller).write(caller, payload, buf)
        except wasmtime.Trap:
            raise
        except Exception as exc:  # noqa: BLE001
            raise wasmtime.Trap(f"random_get memory error: {exc.__class__.__name__}")

        self._queue.append(
            {
                "index": index,
                "length": buf_len,
                "errno": ERRNO_SUCCESS,
                "bytes": payload.hex(),
            }
        )
        return ERRNO_SUCCESS

    def random_get_replay(
        self, caller: wasmtime.Caller, buf: int, buf_len: int
    ) -> int:
        index = self._consumed
        if not self._queue:
            # The guest asks for more randomness than was ever recorded.
            raise _ReplayDivergence("random_records_exhausted", index)
        record = self._queue.pop(0)
        self._consumed += 1
        if record["length"] != buf_len:
            raise _ReplayDivergence("random_length_mismatch", index)

        errno = record["errno"]
        if errno == ERRNO_SUCCESS:
            payload = bytes.fromhex(record["bytes"])
            try:
                self._memory(caller).write(caller, payload, buf)
            except wasmtime.Trap:
                raise
            except Exception as exc:  # noqa: BLE001
                raise wasmtime.Trap(
                    f"random_get memory error: {exc.__class__.__name__}"
                )
        # A recorded non-zero errno is reproduced verbatim and nothing is
        # written, so no fresh entropy is ever consulted during replay.
        return errno

    def remaining_records(self) -> int:
        return len(self._queue)

    def recorded_records(self) -> list[dict]:
        return list(self._queue)


def _validate_restricted_imports(module: wasmtime.Module) -> None:
    """Reject anything but the four allowed function imports."""
    for imp in module.imports:
        if imp.module != WASI_MODULE or imp.name not in ALLOWED_IMPORTS:
            fail(
                EXIT_IMPORT_NOT_ALLOWED,
                f"import {imp.module}.{imp.name} is not permitted",
            )
        if not isinstance(imp.type, wasmtime.FuncType):
            fail(
                EXIT_IMPORT_NOT_ALLOWED,
                f"import {imp.module}.{imp.name} must be a function",
            )


def _build_restricted_linker(
    engine: wasmtime.Engine, runtime: _RestrictedRuntime, mode: str
) -> wasmtime.Linker:
    linker = wasmtime.Linker(engine)
    i32 = wasmtime.ValType.i32()

    linker.define_func(
        WASI_MODULE,
        "fd_read",
        wasmtime.FuncType([i32, i32, i32, i32], [i32]),
        runtime.fd_read,
        access_caller=True,
    )
    linker.define_func(
        WASI_MODULE,
        "fd_write",
        wasmtime.FuncType([i32, i32, i32, i32], [i32]),
        runtime.fd_write,
        access_caller=True,
    )
    linker.define_func(
        WASI_MODULE,
        "proc_exit",
        wasmtime.FuncType([i32], []),
        runtime.proc_exit,
        access_caller=True,
    )
    random_impl = (
        runtime.random_get_record
        if mode == "record"
        else runtime.random_get_replay
    )
    linker.define_func(
        WASI_MODULE,
        "random_get",
        wasmtime.FuncType([i32, i32], [i32]),
        random_impl,
        access_caller=True,
    )
    return linker


def _write_result(result_path: str, payload: dict) -> None:
    # The parent created this path inside the per-request temporary directory;
    # the restricted mode never writes the package anywhere else.
    with open(result_path, "w", encoding="utf-8") as result_file:
        json.dump(payload, result_file, separators=(",", ":"))
        result_file.flush()
        os.fsync(result_file.fileno())


def _run_restricted(
    module_path: str, log_path: str, mode: str, record_path: str, result_path: str
) -> None:
    if mode not in ("record", "replay"):
        fail(EXIT_INTERNAL, f"unknown restricted mode {mode!r}")

    with open(log_path, "rb") as log_file:
        log_bytes = log_file.read()

    engine, store = _new_engine_and_store()
    module = _load_module(engine, module_path)
    _validate_restricted_imports(module)

    records: list[dict] = []
    if mode == "replay":
        # The parent materialises the recorded random calls here so the
        # guest never receives fresh entropy.
        try:
            with open(record_path, "r", encoding="utf-8") as replay_file:
                replay_input = json.load(replay_file)
            records = list(replay_input["records"])
        except (OSError, ValueError, KeyError, TypeError):
            fail(EXIT_INTERNAL, "could not read the replay record file")
        for record in records:
            if (
                not isinstance(record, dict)
                or not isinstance(record.get("length"), int)
                or not isinstance(record.get("bytes"), str)
                or not isinstance(record.get("errno"), int)
            ):
                fail(EXIT_INTERNAL, "malformed replay record")

    original_record_count = len(records)
    runtime = _RestrictedRuntime(log_bytes, mode, records)
    linker = _build_restricted_linker(engine, runtime, mode)

    proc_exit_code: int | None = None

    def _handle_guest_exception(exc: BaseException, phase: str) -> None:
        nonlocal proc_exit_code
        if isinstance(exc, _ProcExit):
            if exc.code == 0:
                # A clean proc_exit(0) is a normal completion: fall through to
                # the shared finalisation below so recordings are still
                # emitted and replay full-consumption is still checked.
                proc_exit_code = 0
                return
            fail(EXIT_NONZERO_EXIT, f"proc_exit({exc.code})")
        if isinstance(exc, _RecordingLimit):
            fail(EXIT_RECORDING_LIMIT, "recording budget exhausted")
        if isinstance(exc, _ReplayDivergence):
            _write_result(
                result_path,
                {
                    "replay_failure": {
                        "reason": exc.reason,
                        "call_index": exc.call_index,
                    }
                },
            )
            raise SystemExit(EXIT_REPLAY_MISMATCH)
        if isinstance(exc, wasmtime.Trap):
            fail(EXIT_TRAP, f"module trapped during {phase}")
        if isinstance(exc, wasmtime.WasmtimeError):
            fail(EXIT_TRAP, f"module trapped during {phase}")
        fail(EXIT_INTERNAL, f"unexpected failure during {phase}")

    try:
        instance = linker.instantiate(store, module)
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - classified by the helper
        if isinstance(exc, wasmtime.WasmtimeError) and not isinstance(
            exc, (wasmtime.Trap, _ProcExit, _RecordingLimit, _ReplayDivergence)
        ):
            # Unknown imports are rejected earlier; anything reaching here is
            # a linking/engine failure.
            fail(EXIT_INSTANTIATE, "module imports could not be linked")
        _handle_guest_exception(exc, "instantiation")

    if proc_exit_code is None:
        _check_start_signature(instance, store)

        try:
            instance.exports(store)["_start"](store)
        except SystemExit:
            raise
        except BaseException as exc:  # noqa: BLE001
            _handle_guest_exception(exc, "execution")

    if mode == "replay":
        # Full consumption is mandatory: every recorded random_get call must
        # be replayed before the guest exits (including a clean proc_exit).
        remaining = runtime.remaining_records()
        if remaining:
            _write_result(
                result_path,
                {
                    "replay_failure": {
                        "reason": "random_records_remaining",
                        "call_index": original_record_count - remaining,
                    }
                },
            )
            raise SystemExit(EXIT_REPLAY_MISMATCH)
        # Output is compared byte-for-byte by the parent, which owns stdout.
        if proc_exit_code == 0:
            raise SystemExit(0)
        return

    _write_result(
        result_path,
        {
            "mode": "record",
            "random_calls": len(runtime.recorded_records()),
            "random_bytes": runtime._recorded_random_bytes,
            "records": runtime.recorded_records(),
        },
    )
    if proc_exit_code == 0:
        raise SystemExit(0)


def main() -> None:
    if len(sys.argv) == 3:
        _run_legacy(sys.argv[1], sys.argv[2])
        return
    if len(sys.argv) == 6:
        _run_restricted(
            sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
        )
        return
    fail(EXIT_INTERNAL, "expected MODULE LOG [MODE RECORD_PATH RESULT_PATH]")


if __name__ == "__main__":
    main()
