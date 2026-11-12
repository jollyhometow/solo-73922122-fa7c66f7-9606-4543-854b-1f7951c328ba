#!/usr/bin/env python3
"""Execute one untrusted WASI Preview 1 module.

This file is deliberately a standalone script: the API starts a fresh Python
interpreter for it for every request.  The uploaded module never receives host
paths, environment variables, preopened directories, or sockets.  Its only
stdin is the supplied log, and its only output paths are inherited stdout and
stderr, which the parent bounds and drains.

Exit codes:
    0   plugin returned normally (or called proc_exit(0))
    20  module failed validation/compilation
    21  instantiation or import linking failed
    22  the module trapped
    23  the module called proc_exit with a non-zero status
    24  the module has no _start export
    25  _start has the wrong signature
    26  unexpected runner failure
"""

import sys

import wasmtime

EXIT_INVALID_MODULE = 20
EXIT_INSTANTIATE = 21
EXIT_TRAP = 22
EXIT_NONZERO_EXIT = 23
EXIT_NO_START = 24
EXIT_BAD_START = 25
EXIT_INTERNAL = 26

MEMORY_LIMIT = 64 * 1024 * 1024
TABLE_ELEMENT_LIMIT = 100_000


def fail(code: int, message: str) -> None:
    sys.stderr.write(f"runner: {message}\n")
    sys.stderr.flush()
    raise SystemExit(code)


def main() -> None:
    if len(sys.argv) != 3:
        fail(EXIT_INTERNAL, "expected module and log paths")

    module_path, log_path = sys.argv[1], sys.argv[2]

    try:
        config = wasmtime.Config()
        config.wasm_component_model = False
        config.wasm_threads = False
        engine = wasmtime.Engine(config)

        wasi = wasmtime.WasiConfig()
        # No inherited environment, no inherited argument vector, and no
        # preopened directories.  argv[0] is a harmless fixed label.
        wasi.argv = ["endpoint-plugin"]
        wasi.env = []
        wasi.stdin_file = log_path
        # The parent owns these pipes and enforces the combined size limit.
        wasi.inherit_stdout()
        wasi.inherit_stderr()
    except Exception as exc:  # noqa: BLE001 - translated to a runner code
        fail(EXIT_INTERNAL, f"could not initialize WASI: {exc.__class__.__name__}")

    try:
        store = wasmtime.Store(engine)
        store.set_limits(
            memory_size=MEMORY_LIMIT,
            table_elements=TABLE_ELEMENT_LIMIT,
            instances=1,
            tables=1,
            memories=1,
        )
        store.set_wasi(wasi)
        linker = wasmtime.Linker(engine)
        linker.define_wasi()
    except Exception as exc:  # noqa: BLE001
        fail(EXIT_INTERNAL, f"could not configure sandbox: {exc.__class__.__name__}")

    try:
        module = wasmtime.Module.from_file(engine, module_path)
    except wasmtime.WasmtimeError:
        fail(EXIT_INVALID_MODULE, "module is not valid WebAssembly")
    except Exception:
        fail(EXIT_INVALID_MODULE, "module could not be read")

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

    try:
        start(store)
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


if __name__ == "__main__":
    main()
