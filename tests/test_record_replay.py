"""Recording / replay API and deterministic-sandbox regression tests.

Run with:  pytest -q
"""

import asyncio
import base64
import copy
import json
from pathlib import Path

import httpx
import pytest
import wasmtime

from app.main import app
from app.config import MAX_PACKAGE_BYTES, MAX_RANDOM_BYTES, MAX_RANDOM_RECORDS

HERE = Path(__file__).resolve().parent
DEMO = HERE.parent / "demo"


def _wat(source: str) -> bytes:
    return bytes(wasmtime.wat2wasm(source))


def _module(name: str) -> bytes:
    return (DEMO / f"{name}.wasm").read_bytes()


def _json(name: str) -> bytes:
    return (DEMO / name).read_bytes()


def _call(path: str, files: dict, timeout: float = 60.0):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            timeout=timeout,
        ) as client:
            return await client.post(path, files=files)

    return asyncio.run(run())


def _record_files(module: bytes, log: bytes) -> dict:
    return {
        "module": ("plugin.wasm", module, "application/wasm"),
        "log": ("input.json", log, "application/json"),
    }


def _replay_files(module: bytes, log: bytes, package: dict | bytes) -> dict:
    payload = package if isinstance(package, bytes) else json.dumps(package).encode()
    files = _record_files(module, log)
    files["package"] = ("package.json", payload, "application/json")
    return files


@pytest.fixture(scope="module")
def recording() -> dict:
    response = _call(
        "/api/v1/record",
        _record_files(_module("random-classify"), _json("sample-log.json")),
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_record_package_shape(recording: dict) -> None:
    assert recording["format"] == "wasm-random-replay/1"
    assert len(recording["module_sha256"]) == 64
    assert len(recording["log_sha256"]) == 64
    assert recording["random_calls"] == 2
    assert recording["random_bytes"] == 5
    assert [record["index"] for record in recording["random_get"]] == [0, 1]
    assert [record["length"] for record in recording["random_get"]] == [1, 4]
    assert all(record["errno"] == 0 for record in recording["random_get"])
    # The recorded output is the plugin's exact stdout, base64-encoded.
    output = base64.b64decode(recording["output"])
    assert json.loads(output)["source"] == "random-classify"


def test_replay_reproduces_output_repeatedly(recording: dict) -> None:
    module = _module("random-classify")
    log = _json("sample-log.json")
    first = None
    for _ in range(3):
        response = _call(
            "/api/v1/replay", _replay_files(module, log, recording)
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["reproduced"] is True
        assert body["random_calls"] == 2
        assert body["random_bytes_consumed"] == 5
        if first is None:
            first = body["output"]
        else:
            # Deterministic: every replay returns identical bytes.
            assert body["output"] == first
    assert base64.b64decode(first) == base64.b64decode(recording["output"])


def test_replay_rejects_wrong_module_digest(recording: dict) -> None:
    response = _call(
        "/api/v1/replay",
        _replay_files(_module("classify"), _json("sample-log.json"), recording),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "replay_digest_mismatch"


def test_replay_rejects_wrong_log_digest(recording: dict) -> None:
    response = _call(
        "/api/v1/replay",
        _replay_files(
            _module("random-classify"), b'{"different":true}', recording
        ),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "replay_digest_mismatch"


def test_replay_reports_length_mismatch_position(recording: dict) -> None:
    tampered = copy.deepcopy(recording)
    tampered["random_get"][0]["length"] = 9
    tampered["random_get"][0]["bytes"] = "00" * 9
    response = _call(
        "/api/v1/replay",
        _replay_files(_module("random-classify"), _json("sample-log.json"), tampered),
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "replay_diverged"
    assert "position: 0" in error["message"]


def test_replay_reports_exhausted_records_position(recording: dict) -> None:
    tampered = copy.deepcopy(recording)
    tampered["random_get"].pop()  # module still makes two calls
    response = _call(
        "/api/v1/replay",
        _replay_files(_module("random-classify"), _json("sample-log.json"), tampered),
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "replay_diverged"
    assert "position: 1" in error["message"]


def test_replay_reports_remaining_records_position(recording: dict) -> None:
    tampered = copy.deepcopy(recording)
    tampered["random_get"].append(
        {"index": 2, "length": 1, "errno": 0, "bytes": "ab"}
    )
    response = _call(
        "/api/v1/replay",
        _replay_files(_module("random-classify"), _json("sample-log.json"), tampered),
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "replay_diverged"
    assert "position: 2" in error["message"]


def test_replay_detects_output_tampering(recording: dict) -> None:
    tampered = copy.deepcopy(recording)
    tampered["output"] = base64.b64encode(b'{"verdict":"block"}').decode()
    response = _call(
        "/api/v1/replay",
        _replay_files(_module("random-classify"), _json("sample-log.json"), tampered),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "replay_output_mismatch"


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda p: b"{broken-json", id="not-json"),
        pytest.param(lambda p: _mutate(p, "format", "unknown/1"), id="bad-format"),
        pytest.param(lambda p: _mutate(p, "output", None, delete=True), id="missing-field"),
        pytest.param(lambda p: _mutate(p, "module_sha256", "z" * 64), id="bad-hash-chars"),
        pytest.param(lambda p: _mutate(p, "output", "@@@"), id="bad-base64"),
        pytest.param(
            lambda p: _mutate(
                p,
                "random_get",
                [{**p["random_get"][0], "bytes": "zz"}, p["random_get"][1]],
            ),
            id="bad-hex",
        ),
        pytest.param(
            lambda p: _mutate(
                p,
                "random_get",
                [{**p["random_get"][0], "index": 5}, p["random_get"][1]],
            ),
            id="index-gap",
        ),
        pytest.param(
            lambda p: _mutate(
                p,
                "random_get",
                [{**p["random_get"][0], "length": 2}, p["random_get"][1]],
            ),
            id="length-bytes-mismatch",
        ),
    ],
)
def test_invalid_packages_are_rejected(recording: dict, mutate) -> None:
    result = mutate(copy.deepcopy(recording))
    payload = result if isinstance(result, bytes) else json.dumps(result).encode()
    response = _call(
        "/api/v1/replay",
        _replay_files(_module("random-classify"), _json("sample-log.json"), payload),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_replay_package"


def test_package_over_random_byte_budget_rejected(recording: dict) -> None:
    tampered = copy.deepcopy(recording)
    tampered["random_get"] = [
        {
            "index": 0,
            "length": MAX_RANDOM_BYTES + 1,
            "errno": 0,
            "bytes": "00" * (MAX_RANDOM_BYTES + 1),
        }
    ]
    response = _call(
        "/api/v1/replay",
        _replay_files(
            _module("random-classify"),
            _json("sample-log.json"),
            json.dumps(tampered).encode(),
        ),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_replay_package"


def test_package_too_many_records_rejected(recording: dict) -> None:
    tampered = copy.deepcopy(recording)
    tampered["random_get"] = [
        {"index": i, "length": 1, "errno": 0, "bytes": "00"}
        for i in range(MAX_RANDOM_RECORDS + 1)
    ]
    response = _call(
        "/api/v1/replay",
        _replay_files(
            _module("random-classify"),
            _json("sample-log.json"),
            json.dumps(tampered).encode(),
        ),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_replay_package"


def test_package_field_size_limit(recording: dict) -> None:
    tampered = copy.deepcopy(recording)
    tampered["padding"] = "x" * (
        MAX_PACKAGE_BYTES - len(json.dumps(tampered).encode()) + 64
    )
    response = _call(
        "/api/v1/replay",
        _replay_files(
            _module("random-classify"),
            _json("sample-log.json"),
            json.dumps(tampered).encode(),
        ),
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "package_too_large"


def test_disallowed_import_is_rejected_on_record() -> None:
    banned = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "path_open"
            (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
          (func (export "_start")))
        """
    )
    response = _call("/api/v1/record", _record_files(banned, b"{}"))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "import_not_allowed"


def test_non_wasi_import_is_rejected_on_record() -> None:
    banned = _wat(
        """
        (module
          (import "env" "thing" (func))
          (func (export "_start")))
        """
    )
    response = _call("/api/v1/record", _record_files(banned, b"{}"))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "import_not_allowed"


def test_recording_call_count_limit_terminates_without_package() -> None:
    many = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "random_get"
            (func $rg (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            (local $i i32)
            (loop $l
              (drop (call $rg (i32.const 0) (i32.const 1)))
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br_if $l (i32.lt_u (local.get $i) (i32.const 257))))))
        """
    )
    response = _call("/api/v1/record", _record_files(many, b"{}"))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "recording_limit_exceeded"


def test_recording_byte_budget_limit_terminates() -> None:
    over_budget = _wat(
        f"""
        (module
          (import "wasi_snapshot_preview1" "random_get"
            (func $rg (param i32 i32) (result i32)))
          (memory (export "memory") 2)
          (func (export "_start")
            (drop (call $rg (i32.const 65536)
                         (i32.const {MAX_RANDOM_BYTES + 1})))))
        """
    )
    response = _call("/api/v1/record", _record_files(over_budget, b"{}"))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "recording_limit_exceeded"


def test_recording_accepts_exact_budget() -> None:
    # 256 calls x 128 bytes = exactly 32 KiB and exactly 256 calls.
    exact = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "random_get"
            (func $rg (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            (local $i i32)
            (loop $l
              (drop (call $rg (i32.const 0) (i32.const 128)))
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br_if $l (i32.lt_u (local.get $i) (i32.const 256))))))
        """
    )
    response = _call("/api/v1/record", _record_files(exact, b"{}"))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["random_calls"] == MAX_RANDOM_RECORDS
    assert body["random_bytes"] == MAX_RANDOM_BYTES


def test_random_get_in_start_function_is_recorded() -> None:
    start_module = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "random_get"
            (func $rg (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (start $s)
          (func $s (drop (call $rg (i32.const 0) (i32.const 2))))
          (func (export "_start")
            (drop (call $rg (i32.const 0) (i32.const 3)))))
        """
    )
    recorded = _call("/api/v1/record", _record_files(start_module, b"{}"))
    assert recorded.status_code == 200, recorded.text
    package = recorded.json()
    assert [r["length"] for r in package["random_get"]] == [2, 3]

    # Replay injects the start-section call before _start as well.
    response = _call(
        "/api/v1/replay", _replay_files(start_module, b"{}", package)
    )
    assert response.status_code == 200, response.text


def test_proc_exit_zero_is_a_clean_recording() -> None:
    module = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "proc_exit" (func $pe (param i32)))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fw (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 1024) "{}")
          (func (export "_start")
            (i32.store (i32.const 0) (i32.const 1024))
            (i32.store (i32.const 4) (i32.const 2))
            (drop (call $fw (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
            (call $pe (i32.const 0))))
        """
    )
    response = _call("/api/v1/record", _record_files(module, b"{}"))
    assert response.status_code == 200, response.text
    assert response.json()["random_calls"] == 0
    assert base64.b64decode(response.json()["output"]) == b"{}"


def test_nonzero_proc_exit_is_rejected_in_record() -> None:
    module = _wat(
        """
        (module
          (import "wasi_snapshot_preview1" "proc_exit" (func $pe (param i32)))
          (func (export "_start") (call $pe (i32.const 3))))
        """
    )
    response = _call("/api/v1/record", _record_files(module, b"{}"))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "plugin_nonzero_exit"


def test_record_requires_valid_module_and_log() -> None:
    response = _call("/api/v1/record", _record_files(b"not wasm", b"{}"))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_module"

    response = _call(
        "/api/v1/record",
        _record_files(_module("random-classify"), b"{broken"),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_log_json"


def test_record_trap_is_explicit() -> None:
    trap = _wat(
        """
        (module
          (func (export "_start") (unreachable)))
        """
    )
    response = _call("/api/v1/record", _record_files(trap, b"{}"))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "plugin_trap"


def test_recorded_module_hash_matches_upload(recording: dict) -> None:
    import hashlib

    assert (
        recording["module_sha256"]
        == hashlib.sha256(_module("random-classify")).hexdigest()
    )
    assert (
        recording["log_sha256"]
        == hashlib.sha256(_json("sample-log.json")).hexdigest()
    )


def test_openapi_documents_all_routes() -> None:
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            schema = await client.get("/openapi.json")
            docs = await client.get("/docs")
            return schema, docs

    schema, docs = asyncio.run(run())
    assert docs.status_code == 200
    paths = schema.json()["paths"]
    assert {
        "/api/v1/analyze",
        "/api/v1/record",
        "/api/v1/replay",
    } <= set(paths)


def _mutate(package: dict, key: str, value, delete: bool = False):
    if delete:
        del package[key]
    else:
        package[key] = value
    return package
