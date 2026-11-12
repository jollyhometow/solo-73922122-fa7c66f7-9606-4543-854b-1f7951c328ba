"""API and sandbox regression tests.

Run with:  pytest -q
"""

import asyncio
import time
from pathlib import Path

import httpx
import pytest
import wasmtime

from app.main import app

HERE = Path(__file__).resolve().parent
DEMO = HERE.parent / "demo"


def _wat(source: str) -> bytes:
    return bytes(wasmtime.wat2wasm(source))


def _post(module: bytes, log: bytes, timeout: float = 30.0):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            timeout=timeout,
        ) as client:
            return await client.post(
                "/api/v1/analyze",
                files={
                    "module": ("plugin.wasm", module, "application/wasm"),
                    "log": ("input.json", log, "application/json"),
                },
            )

    return asyncio.run(run())


def _module(name: str) -> bytes:
    return (DEMO / f"{name}.wasm").read_bytes()


def _json(name: str) -> bytes:
    return (DEMO / name).read_bytes()


@pytest.mark.parametrize(
    ("log_name", "verdict", "score"),
    [
        ("sample-log.json", "allow", 0),
        ("suspicious-log.json", "review", 55),
        ("malicious-log.json", "block", 95),
    ],
)
def test_demo_classification(log_name: str, verdict: str, score: int) -> None:
    response = _post(_module("classify"), _json(log_name))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert payload["verdict"] == verdict
    assert payload["score"] == score


def test_invalid_module_is_explicit() -> None:
    response = _post(b"not wasm", b"{}")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_module"


def test_invalid_log_is_explicit() -> None:
    response = _post(_module("classify"), b'{"broken":')
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_log_json"


def test_non_utf8_log_is_explicit() -> None:
    response = _post(_module("classify"), b'{"x":"\xff"}')
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "log_not_utf8"


def test_trap_is_explicit() -> None:
    trap = _wat(
        """
        (module
          (func (export "_start") (unreachable))
        )
        """
    )
    response = _post(trap, b"{}")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "plugin_trap"


def test_nonzero_exit_is_explicit() -> None:
    nonzero = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $proc_exit (param i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            (call $proc_exit (i32.const 7)))
        )
        """
    )
    response = _post(nonzero, b"{}")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "plugin_nonzero_exit"


def test_invalid_plugin_json_is_explicit() -> None:
    bad_json = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 1024) "not json")
          (func (export "_start")
            (i32.store (i32.const 0) (i32.const 1024))
            (i32.store (i32.const 4) (i32.const 8))
            (drop (call $fd_write (i32.const 1) (i32.const 0)
                                  (i32.const 1) (i32.const 8))))
        )
        """
    )
    response = _post(bad_json, b"{}")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_plugin_json"


def test_output_limit_counts_stdout_and_stderr() -> None:
    oversized = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 2)
          (func (export "_start")
            (i32.store (i32.const 0) (i32.const 0))
            (i32.store (i32.const 4) (i32.const 32769))
            (drop (call $fd_write (i32.const 1) (i32.const 0)
                                  (i32.const 1) (i32.const 8)))
            (drop (call $fd_write (i32.const 2) (i32.const 0)
                                  (i32.const 1) (i32.const 8))))
        )
        """
    )
    response = _post(oversized, b"{}")
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "plugin_output_too_large"


def test_memory_limit_is_enforced() -> None:
    # 1025 pages = 64 MiB + 64 KiB; instantiation must fail under StoreLimits.
    over_memory = _wat(
        """
        (module
          (memory (export "memory") 1025)
          (func (export "_start"))
        )
        """
    )
    response = _post(over_memory, b"{}")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "plugin_instantiation_failed"


def test_no_host_directory_is_preopened() -> None:
    escape = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "path_open"
            (func $path_open
              (param i32 i32 i32 i32 i32 i64 i64 i32 i32)
              (result i32)))
          (memory (export "memory") 2)
          (data (i32.const 1024) "/etc/passwd")
          (data (i32.const 2048) "{\\"opened\\":false}")
          (data (i32.const 2080) "{\\"opened\\":true}")
          (func (export "_start")
            (if (i32.eqz
                  (call $path_open
                    (i32.const 3) (i32.const 0)
                    (i32.const 1024) (i32.const 11)
                    (i32.const 0)
                    (i64.const 0) (i64.const 0)
                    (i32.const 0) (i32.const 16)))
              (then
                (i32.store (i32.const 0) (i32.const 2080))
                (i32.store (i32.const 4) (i32.const 15))
                (drop (call $fd_write (i32.const 1) (i32.const 0)
                                      (i32.const 1) (i32.const 8)))
                (return)))
            (i32.store (i32.const 0) (i32.const 2048))
            (i32.store (i32.const 4) (i32.const 16))
            (drop (call $fd_write (i32.const 1) (i32.const 0)
                                  (i32.const 1) (i32.const 8))))
        )
        """
    )
    response = _post(escape, b"{}")
    assert response.status_code == 200
    assert response.json() == {"opened": False}


def test_module_size_limit() -> None:
    response = _post(b"\x00asm\x01\x00\x00\x00" + b"\x00" * (1024 * 1024), b"{}")
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "module_too_large"


def test_log_size_limit() -> None:
    too_large = b'{"padding":"' + b"x" * (64 * 1024) + b'"}'
    response = _post(_module("classify"), too_large)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "log_too_large"


def test_timeout() -> None:
    response = _post(_module("loop"), b"{}", timeout=60.0)
    assert response.status_code == 504
    assert response.json()["error"]["code"] == "plugin_timeout"


def test_stuck_plugin_does_not_block_another_request() -> None:
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver", timeout=60.0
        ) as client:
            files = lambda n: {  # noqa: E731
                "module": ("plugin.wasm", _module(n), "application/wasm"),
                "log": ("input.json", _json("sample-log.json"), "application/json"),
            }
            started = time.monotonic()
            slow = asyncio.create_task(
                client.post("/api/v1/analyze", files=files("loop"))
            )
            await asyncio.sleep(0.15)
            fast = await client.post("/api/v1/analyze", files=files("classify"))
            elapsed = time.monotonic() - started
            assert fast.status_code == 200
            assert elapsed < 4.0
            await slow

    asyncio.run(run())


def test_openapi_and_health() -> None:
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            health = await client.get("/healthz")
            docs = await client.get("/docs")
            schema = await client.get("/openapi.json")
            return health, docs, schema

    health, docs, schema = asyncio.run(run())
    assert health.status_code == 200
    assert docs.status_code == 200
    assert schema.status_code == 200
    assert "/api/v1/analyze" in schema.json()["paths"]


def test_wasi_environment_is_empty_and_argv_is_fixed() -> None:
    env_probe = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "environ_sizes_get"
            (func $environ_sizes_get (param i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "args_sizes_get"
            (func $args_sizes_get (param i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 2048) "{\\"empty_env\\":true,\\"one_arg\\":true}")
          (data (i32.const 2100) "{\\"empty_env\\":false,\\"one_arg\\":false}")
          (func $write (param i32) (param i32)
            (i32.store (i32.const 0) (local.get 0))
            (i32.store (i32.const 4) (local.get 1))
            (drop (call $fd_write (i32.const 1) (i32.const 0)
                                  (i32.const 1) (i32.const 8)))
          )
          (func (export "_start")
            (drop (call $environ_sizes_get (i32.const 32) (i32.const 36)))
            (drop (call $args_sizes_get (i32.const 40) (i32.const 44)))
            (if (i32.and
                  (i32.eqz (i32.load (i32.const 32)))
                  (i32.eq (i32.load (i32.const 40)) (i32.const 1)))
              (then (call $write (i32.const 2048) (i32.const 33)))
              (else (call $write (i32.const 2100) (i32.const 35))))
          )
        )
        """
    )
    response = _post(env_probe, b"{}")
    assert response.status_code == 200
    assert response.json() == {"empty_env": True, "one_arg": True}


def test_memory_growth_is_blocked_at_64_mib() -> None:
    # One page initially; growing by 1024 pages would be 64 MiB + 64 KiB.
    grow_probe = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 2048) "{\\"grow_blocked\\":true}")
          (data (i32.const 2100) "{\\"grow_blocked\\":false}")
          (func $write (param i32) (param i32)
            (i32.store (i32.const 0) (local.get 0))
            (i32.store (i32.const 4) (local.get 1))
            (drop (call $fd_write (i32.const 1) (i32.const 0)
                                  (i32.const 1) (i32.const 8)))
          )
          (func (export "_start")
            (if (i32.eq (memory.grow (i32.const 1024)) (i32.const -1))
              (then (call $write (i32.const 2048) (i32.const 21)))
              (else (call $write (i32.const 2100) (i32.const 22))))
          )
        )
        """
    )
    response = _post(grow_probe, b"{}")
    assert response.status_code == 200
    assert response.json() == {"grow_blocked": True}


def _pad_to_module_limit(module: bytes, target: int) -> bytes:
    payload_len = target - len(module) - 1  # section payload excluding ULEB size
    while True:
        name = b"pad"
        name_field = bytes([len(name)]) + name
        section_size = len(name_field) + (payload_len - len(name_field))
        size_field = bytearray()
        value = section_size
        while True:
            byte = value & 0x7F
            value >>= 7
            size_field.append(byte | (0x80 if value else 0))
            if not value:
                break
        total = len(module) + 1 + len(size_field) + section_size
        if total == target:
            return module + b"\x00" + bytes(size_field) + name_field + b"\x00" * (
                payload_len - len(name_field)
            )
        payload_len += target - total


def test_module_at_exact_size_limit_is_accepted() -> None:
    module = _pad_to_module_limit(_module("classify"), 1024 * 1024)
    assert len(module) == 1024 * 1024
    response = _post(module, _json("sample-log.json"))
    assert response.status_code == 200
    assert response.json()["verdict"] == "allow"


def test_log_at_exact_size_limit_is_accepted() -> None:
    log = b'{"p":"' + b"x" * (64 * 1024 - 8) + b'"}'
    assert len(log) == 64 * 1024
    response = _post(_module("classify"), log)
    assert response.status_code == 200
    assert response.json()["verdict"] == "allow"
