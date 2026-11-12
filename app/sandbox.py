"""Subprocess supervisor around the one-shot WASI runner.

Every request gets a new temporary directory, a fresh runner interpreter and a
new process group.  The runner is confined by WASI itself (no preopens, empty
environment, no sockets, only fds 0/1/2), while this module confines the host
process with timeout, output-size limits, fd hygiene and process-group reaping.
"""

import asyncio
import os
import shutil
import signal
import sys
import tempfile
from pathlib import Path

from .config import MAX_PLUGIN_OUTPUT_BYTES, PLUGIN_TIMEOUT_SECONDS
from .errors import ApiError

RUNNER_PATH = Path(__file__).resolve().with_name("runner.py")
READ_CHUNK = 4096
POLL_INTERVAL = 0.01
REAP_GRACE_SECONDS = 1.0

_EXIT_CODES = {
    20: (422, "invalid_module", "The uploaded file is not a valid WebAssembly module."),
    21: (422, "plugin_instantiation_failed", "The module could not be instantiated or its imports could not be linked."),
    22: (422, "plugin_trap", "The plugin trapped while executing."),
    23: (422, "plugin_nonzero_exit", "The plugin exited with a non-zero status."),
    24: (422, "invalid_module", "The module does not export a WASI _start function."),
    25: (422, "invalid_module", "The module's _start export has an invalid signature."),
    26: (500, "sandbox_internal_error", "The sandbox runner failed."),
}


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    """Kill the runner and anything it may have created in its session."""
    if proc.returncode is not None:
        return

    # start_new_session=True makes the child the leader of its own process
    # group, so this cannot signal the API process.
    killed = False
    try:
        os.killpg(proc.pid, signal.SIGKILL)
        killed = True
    except OSError:
        pass

    if not killed:
        # Fallback for platforms without process groups.  The child may have
        # exited between the check above and the signal, which is harmless.
        try:
            proc.kill()
        except OSError:
            pass


async def _reap(proc: asyncio.subprocess.Process, wait_task: asyncio.Task) -> None:
    _kill_group(proc)
    if not wait_task.done():
        try:
            await asyncio.wait_for(asyncio.shield(wait_task), REAP_GRACE_SECONDS)
        except asyncio.TimeoutError:
            # A SIGKILLed child should leave immediately.  If it does not,
            # there is nothing more this supervisor can safely do.
            pass
    if wait_task.done():
        try:
            wait_task.result()
        except Exception:
            pass


async def _supervise(
    proc: asyncio.subprocess.Process,
    request,
) -> tuple[bytes, bytes, int, str | None]:
    """Drain output and wait for the child under the sandbox limits."""
    stdout = bytearray()
    stderr = bytearray()
    total = 0
    overflow = False

    async def read_stream(stream: asyncio.StreamReader, sink: bytearray) -> None:
        nonlocal total, overflow
        try:
            while True:
                chunk = await stream.read(READ_CHUNK)
                if not chunk:
                    return
                if overflow:
                    # Another reader has already found the limit and killed the
                    # child.  Keep draining until EOF so the pipe closes.
                    continue
                total += len(chunk)
                if total > MAX_PLUGIN_OUTPUT_BYTES:
                    overflow = True
                    _kill_group(proc)
                    return
                sink.extend(chunk)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Broken pipe while the child is being killed is expected.
            return

    stdout_task = asyncio.create_task(read_stream(proc.stdout, stdout))
    stderr_task = asyncio.create_task(read_stream(proc.stderr, stderr))
    wait_task = asyncio.create_task(proc.wait())
    reader_tasks = (stdout_task, stderr_task)

    deadline = asyncio.get_running_loop().time() + PLUGIN_TIMEOUT_SECONDS
    failure: str | None = None

    try:
        while True:
            try:
                if await request.is_disconnected():
                    failure = "client_disconnected"
                    break
            except asyncio.CancelledError:
                raise
            except Exception:
                # A request implementation that cannot answer does not get to
                # disable the timeout or output limit.
                pass

            if overflow:
                failure = "output_too_large"
                break
            if wait_task.done():
                break

            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                failure = "timeout"
                break
            await asyncio.sleep(min(POLL_INTERVAL, remaining))

        if failure is not None:
            _kill_group(proc)

        if not wait_task.done():
            try:
                await asyncio.wait_for(asyncio.shield(wait_task), REAP_GRACE_SECONDS)
            except asyncio.TimeoutError:
                _kill_group(proc)
                try:
                    await asyncio.wait_for(asyncio.shield(wait_task), REAP_GRACE_SECONDS)
                except asyncio.TimeoutError:
                    pass

        # EOF follows the child's death.  Do not wait forever on a pipe held by
        # an unexpected descendant.
        try:
            await asyncio.wait_for(
                asyncio.gather(stdout_task, stderr_task), REAP_GRACE_SECONDS
            )
        except asyncio.TimeoutError:
            for task in reader_tasks:
                task.cancel()
            await asyncio.gather(*reader_tasks, return_exceptions=True)

        if failure is None and (overflow or total > MAX_PLUGIN_OUTPUT_BYTES):
            failure = "output_too_large"

        return bytes(stdout), bytes(stderr), proc.returncode, failure
    finally:
        if failure is not None and proc.returncode is None:
            _kill_group(proc)
        if not wait_task.done():
            # This path is used when the coroutine is cancelled by the server.
            await _reap(proc, wait_task)
        for task in reader_tasks:
            if not task.done():
                task.cancel()
        if reader_tasks:
            await asyncio.gather(*reader_tasks, return_exceptions=True)


def _process_runner_failure(returncode: int) -> None:
    mapping = _EXIT_CODES.get(returncode)
    if mapping is None:
        raise ApiError(
            502,
            "sandbox_process_failed",
            "The sandbox runner ended unexpectedly.",
        )
    status_code, code, message = mapping
    raise ApiError(status_code, code, message)


async def execute_plugin(module_bytes: bytes, log_bytes: bytes, request) -> bytes:
    """Run one plugin in an isolated child and return its complete stdout."""
    temp_dir = tempfile.mkdtemp(prefix="wasm-endpoint-")
    module_path = os.path.join(temp_dir, "plugin.wasm")
    log_path = os.path.join(temp_dir, "input.json")
    proc: asyncio.subprocess.Process | None = None

    try:
        with open(module_path, "wb") as module_file:
            module_file.write(module_bytes)
        with open(log_path, "wb") as log_file:
            log_file.write(log_bytes)
        os.chmod(module_path, 0o600)
        os.chmod(log_path, 0o600)

        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-B",
            "-I",
            str(RUNNER_PATH),
            module_path,
            log_path,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/",
            env={},
            close_fds=True,
            start_new_session=True,
        )

        stdout, _stderr, returncode, failure = await _supervise(proc, request)

        if failure == "client_disconnected":
            raise ApiError(
                499,
                "client_disconnected",
                "The client disconnected before the plugin completed.",
            )
        if failure == "timeout":
            raise ApiError(
                504,
                "plugin_timeout",
                f"Plugin execution exceeded the {PLUGIN_TIMEOUT_SECONDS:g} second limit.",
            )
        if failure == "output_too_large":
            raise ApiError(
                413,
                "plugin_output_too_large",
                f"Plugin stdout and stderr exceeded {MAX_PLUGIN_OUTPUT_BYTES} bytes.",
            )

        if returncode != 0:
            _process_runner_failure(returncode)

        return stdout

    except ApiError:
        raise
    except Exception:
        raise ApiError(
            500,
            "sandbox_internal_error",
            "The sandbox could not complete the request.",
        )
    finally:
        if proc is not None and proc.returncode is None:
            _kill_group(proc)
        # Temporary input files are removed synchronously so cancellation and
        # disconnect paths cannot skip cleanup.
        shutil.rmtree(temp_dir, ignore_errors=True)
