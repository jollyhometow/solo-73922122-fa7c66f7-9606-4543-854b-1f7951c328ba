"""FastAPI surface for the isolated WASI endpoint-plugin sandbox."""

import base64
import binascii
import hashlib
import json
from typing import Annotated

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response

from .config import (
    MAX_LOG_BYTES,
    MAX_MODULE_BYTES,
    MAX_PACKAGE_BYTES,
    MAX_PLUGIN_OUTPUT_BYTES,
    MAX_RANDOM_BYTES,
    MAX_RANDOM_RECORDS,
    MAX_REPLAY_REQUEST_BYTES,
    MAX_REQUEST_BYTES,
    PLUGIN_MEMORY_BYTES,
    PLUGIN_TIMEOUT_SECONDS,
)
from .errors import ApiError
from .middleware import BodyLimitMiddleware
from .sandbox import execute_plugin, record_plugin, replay_plugin

PACKAGE_FORMAT = "wasm-random-replay/1"

API_DESCRIPTION = f"""
Runs a vendor-supplied **WASI Preview 1** endpoint-detection module against a
sanitised JSON log and returns the JSON that the module writes to stdout.

Two execution families share one subprocess sandbox:

* `POST /api/v1/analyze` — one-shot trial run with the full WASI preview-1
  import surface (no preopens, empty environment, stdin/stdout/stderr only).
* `POST /api/v1/record` and `POST /api/v1/replay` — deterministic
  record/replay for reproducing intermittent false positives.  These routes
  accept modules that import **only** `fd_read`, `fd_write`, `proc_exit` and
  `random_get` from `wasi_snapshot_preview1`; every other import is rejected
  before instantiation.

Sandbox guarantees:

* module upload: at most **1 MiB**; log upload: at most **64 KiB** of UTF-8 JSON
* one fresh subprocess per request, with an empty WASI environment, no preopened
  host directories, no sockets, and only stdin/stdout/stderr
* linear memory capped at **64 MiB**; wall-clock execution capped at
  **{PLUGIN_TIMEOUT_SECONDS:g} seconds**
* combined plugin stdout + stderr capped at **{MAX_PLUGIN_OUTPUT_BYTES} bytes**
* a recording captures at most **{MAX_RANDOM_RECORDS}** `random_get` calls and
  **{MAX_RANDOM_BYTES // 1024} KiB** of random bytes; crossing either limit
  terminates the run and never returns a partial package
* timeout, output overflow, or client disconnect kills and reaps the process
  group and removes temporary files; partial output is never returned
* recording/replay packages are never persisted: they exist only inside the
  request's temporary directory, which is removed on every exit path

Demo artifacts are in the repository's `demo/` directory:

* `demo/classify.wasm` — reads stdin, then emits a JSON verdict
* `demo/random-classify.wasm` — verdict driven partly by `random_get`, used for
  the record/replay walkthrough below
* `demo/loop.wasm` — intentionally never returns (demonstrates the timeout)
* `demo/spam.wasm` — writes continuously (demonstrates the output limit)
* `demo/sample-log.json` — benign log used by the classifier demos
"""

app = FastAPI(
    title="WASM Endpoint Plugin Sandbox",
    version="2.0.0",
    description=API_DESCRIPTION,
)
app.add_middleware(
    BodyLimitMiddleware,
    max_body_bytes=MAX_REQUEST_BYTES,
    replay_body_bytes=MAX_REPLAY_REQUEST_BYTES,
)

WASM_HEADER = b"\x00asm\x01\x00\x00\x00"
_NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


def _error(status_code: int, code: str, message: str) -> ApiError:
    return ApiError(status_code, code, message)


@app.exception_handler(ApiError)
async def _api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
        headers=_NO_STORE_HEADERS,
    )


@app.get("/", include_in_schema=False)
async def index() -> RedirectResponse:
    return RedirectResponse(url="/docs", status_code=307)


@app.get("/healthz", summary="Liveness probe")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


async def _read_upload(upload: UploadFile, limit: int, field: str) -> bytes:
    try:
        data = await upload.read(limit + 1)
        if len(data) > limit:
            raise _error(413, f"{field}_too_large", f"The {field} exceeds its size limit.")
        if len(data) == limit:
            # Distinguish "exactly at the limit" from "the limit plus more".
            if await upload.read(1):
                raise _error(413, f"{field}_too_large", f"The {field} exceeds its size limit.")
        return data
    except ApiError:
        raise
    except Exception:
        raise _error(400, "upload_read_failed", f"The {field} upload could not be read.")
    finally:
        try:
            await upload.close()
        except Exception:
            pass


def _validate_module(data: bytes) -> None:
    if len(data) < len(WASM_HEADER) or data[: len(WASM_HEADER)] != WASM_HEADER:
        raise _error(
            422,
            "invalid_module",
            "The module must be a binary WebAssembly 1.0 module (WASI Preview 1).",
        )
    if data[len(WASM_HEADER) :].lstrip(b"\x00") == b"":
        raise _error(422, "invalid_module", "The module is empty.")


def _reject_json_constant(value: str):
    raise ValueError(f"non-standard JSON constant: {value}")


def _validate_log(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _error(
            422,
            "log_not_utf8",
            "The log must be valid UTF-8.",
        ) from exc

    try:
        json.loads(text, parse_constant=_reject_json_constant)
    except (ValueError, RecursionError) as exc:
        raise _error(
            422,
            "invalid_log_json",
            "The log must contain exactly one valid JSON value.",
        ) from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_response(payload: dict, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=payload,
        headers=_NO_STORE_HEADERS,
    )


@app.post(
    "/api/v1/analyze",
    summary="Run a WASI detection module against a log",
    response_class=Response,
    responses={
        200: {
            "description": "The complete JSON value written to the plugin's stdout.",
            "content": {"application/json": {"schema": {}}},
        },
        413: {"description": "An upload or the plugin's output exceeded a size limit."},
        422: {"description": "Invalid module, invalid log JSON, plugin trap, or non-zero exit."},
        499: {"description": "The client disconnected; the plugin was terminated."},
        504: {"description": "The plugin exceeded the execution time limit."},
    },
    description="""
Upload a WASI Preview 1 command module and a JSON log. The service writes the
raw log bytes to the module's stdin and returns the exact JSON value written to
stdout after a clean exit. Use **Try it out** below with the files from the
repository's `demo/` directory. This legacy trial-run interface is unchanged.
""",
)
async def analyze(
    request: Request,
    module: Annotated[
        UploadFile,
        File(description="Binary WASI Preview 1 module, maximum 1 MiB."),
    ],
    log: Annotated[
        UploadFile,
        File(description="UTF-8 JSON log, maximum 64 KiB."),
    ],
) -> Response:
    module_bytes = await _read_upload(module, MAX_MODULE_BYTES, "module")
    log_bytes = await _read_upload(log, MAX_LOG_BYTES, "log")

    _validate_module(module_bytes)
    _validate_log(log_bytes)

    output = await execute_plugin(module_bytes, log_bytes, request)

    try:
        text = output.decode("utf-8")
        json.loads(text, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _error(
            422,
            "invalid_plugin_json",
            "The plugin's stdout is not exactly one valid UTF-8 JSON value.",
        ) from exc

    return Response(
        content=output,
        media_type="application/json",
        headers=_NO_STORE_HEADERS,
    )


@app.post(
    "/api/v1/record",
    summary="Record a run, capturing every random_get call",
    responses={
        200: {"description": "A self-contained recording package (JSON)."},
        413: {"description": "An upload exceeded a size limit."},
        422: {
            "description": (
                "Invalid module/log, a disallowed import, plugin trap, non-zero "
                "exit, or the 256-call / 32 KiB recording budget was exceeded."
            )
        },
        499: {"description": "The client disconnected; the plugin was terminated."},
        504: {"description": "The plugin exceeded the execution time limit."},
    },
    description=f"""
Upload a module that imports **only** `fd_read`, `fd_write`, `proc_exit` and
`random_get` from `wasi_snapshot_preview1`, plus a JSON log. The service runs
the module in the same isolated subprocess as `/analyze`, recording each
`random_get` call **in call order, including calls made during
instantiation** (for example from a WASI start function): the requested
buffer length, the returned errno and the exact bytes written to guest
memory. Fresh host entropy is used for the recorded run.

The response is a JSON package containing the module SHA-256, the log
SHA-256, the ordered `random_get` records and the plugin's raw stdout
(base64). At most **{MAX_RANDOM_RECORDS}** calls and **{MAX_RANDOM_BYTES // 1024}
KiB** of random bytes are captured; if the plugin crosses either limit the run
is terminated with `recording_limit_exceeded` and **no package** is returned.
Hand the returned package to the vendor for `POST /api/v1/replay`.
""",
)
async def record(
    request: Request,
    module: Annotated[
        UploadFile,
        File(description="Binary WASI Preview 1 module, maximum 1 MiB."),
    ],
    log: Annotated[
        UploadFile,
        File(description="UTF-8 JSON log, maximum 64 KiB."),
    ],
) -> Response:
    module_bytes = await _read_upload(module, MAX_MODULE_BYTES, "module")
    log_bytes = await _read_upload(log, MAX_LOG_BYTES, "log")

    _validate_module(module_bytes)
    _validate_log(log_bytes)

    output, capture = await record_plugin(module_bytes, log_bytes, request)

    package = {
        "format": PACKAGE_FORMAT,
        "module_sha256": _sha256_hex(module_bytes),
        "log_sha256": _sha256_hex(log_bytes),
        "random_calls": capture["random_calls"],
        "random_bytes": capture["random_bytes"],
        "random_get": capture["records"],
        "output": base64.b64encode(output).decode("ascii"),
    }
    return _json_response(package)


def _validate_package(data: bytes) -> dict:
    """Parse and structurally validate a client-supplied replay package."""
    try:
        package = json.loads(
            data.decode("utf-8"), parse_constant=_reject_json_constant
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _error(
            422,
            "invalid_replay_package",
            "The package must be one valid UTF-8 JSON value.",
        ) from exc

    if not isinstance(package, dict):
        raise _error(422, "invalid_replay_package", "The package must be a JSON object.")
    if package.get("format") != PACKAGE_FORMAT:
        raise _error(
            422,
            "invalid_replay_package",
            f"The package format must be {PACKAGE_FORMAT!r}.",
        )

    for key in ("module_sha256", "log_sha256", "random_get", "output"):
        if key not in package:
            raise _error(
                422,
                "invalid_replay_package",
                f"The package is missing the {key!r} field.",
            )

    for key in ("module_sha256", "log_sha256"):
        if not isinstance(package[key], str) or len(package[key]) != 64:
            raise _error(
                422,
                "invalid_replay_package",
                f"The package field {key!r} must be a SHA-256 hex digest.",
            )
        try:
            int(package[key], 16)
        except ValueError as exc:
            raise _error(
                422,
                "invalid_replay_package",
                f"The package field {key!r} must be a SHA-256 hex digest.",
            ) from exc

    records = package["random_get"]
    if not isinstance(records, list) or len(records) > MAX_RANDOM_RECORDS:
        raise _error(
            422,
            "invalid_replay_package",
            f"The package may contain at most {MAX_RANDOM_RECORDS} random_get records.",
        )

    total_bytes = 0
    for position, record in enumerate(records):
        if not isinstance(record, dict):
            raise _error(422, "invalid_replay_package", "Each random_get record must be an object.")
        if record.get("index") != position:
            raise _error(
                422,
                "invalid_replay_package",
                f"random_get record at position {position} has a mismatched index.",
            )
        length = record.get("length")
        errno = record.get("errno")
        hex_bytes = record.get("bytes")
        if not isinstance(length, int) or length < 0 or not isinstance(errno, int) or errno < 0:
            raise _error(
                422,
                "invalid_replay_package",
                f"random_get record at position {position} has an invalid length or errno.",
            )
        if not isinstance(hex_bytes, str):
            raise _error(
                422,
                "invalid_replay_package",
                f"random_get record at position {position} has invalid bytes.",
            )
        try:
            raw = bytes.fromhex(hex_bytes)
        except ValueError as exc:
            raise _error(
                422,
                "invalid_replay_package",
                f"random_get record at position {position} has non-hex bytes.",
            ) from exc
        if len(raw) != length:
            raise _error(
                422,
                "invalid_replay_package",
                f"random_get record at position {position} has bytes that do not match its length.",
            )
        total_bytes += length
        if total_bytes > MAX_RANDOM_BYTES:
            raise _error(
                422,
                "invalid_replay_package",
                f"The package exceeds the {MAX_RANDOM_BYTES // 1024} KiB random-byte budget.",
            )

    if not isinstance(package["output"], str):
        raise _error(
            422,
            "invalid_replay_package",
            "The package field 'output' must be base64 text.",
        )
    try:
        expected_output = base64.b64decode(package["output"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _error(
            422,
            "invalid_replay_package",
            "The package field 'output' is not valid base64.",
        ) from exc

    return package, expected_output, total_bytes


@app.post(
    "/api/v1/replay",
    summary="Replay a recording with injected randomness",
    responses={
        200: {"description": "The replay consumed every record and reproduced the output byte-for-byte."},
        413: {"description": "An upload exceeded a size limit."},
        422: {
            "description": (
                "Invalid module/log/package, digest mismatch, disallowed import, "
                "plugin trap, non-zero exit, replay divergence, or output mismatch."
            )
        },
        499: {"description": "The client disconnected; the plugin was terminated."},
        504: {"description": "The plugin exceeded the execution time limit."},
    },
    description="""
Upload the original module, the original log and the recording package from
`POST /api/v1/record` (all in their original wire formats). The service first
verifies that the SHA-256 digests of the uploaded module and log match the
digests embedded in the package, then reruns the module while injecting the
recorded `random_get` results **in call order** — no fresh randomness is ever
drawn. A mismatch is reported with the zero-based `random_get` call position:

* `random_length_mismatch` — the requested length differs from the recording;
* `random_records_exhausted` — the module keeps calling after records run out;
* `random_records_remaining` — the module exits with records still unused.

Replay reports success only when every record is consumed **and** stdout is
byte-for-byte identical to the package's recorded output. As with the other
routes, nothing is persisted after the response.
""",
)
async def replay(
    request: Request,
    module: Annotated[
        UploadFile,
        File(description="The original binary WASI module, maximum 1 MiB."),
    ],
    log: Annotated[
        UploadFile,
        File(description="The original UTF-8 JSON log, maximum 64 KiB."),
    ],
    package: Annotated[
        UploadFile,
        File(description="The recording package returned by /api/v1/record."),
    ],
) -> Response:
    module_bytes = await _read_upload(module, MAX_MODULE_BYTES, "module")
    log_bytes = await _read_upload(log, MAX_LOG_BYTES, "log")
    package_bytes = await _read_upload(package, MAX_PACKAGE_BYTES, "package")

    _validate_module(module_bytes)
    _validate_log(log_bytes)
    parsed_package, expected_output, _random_total = _validate_package(package_bytes)

    module_digest = _sha256_hex(module_bytes)
    log_digest = _sha256_hex(log_bytes)
    if module_digest != parsed_package["module_sha256"]:
        raise _error(
            422,
            "replay_digest_mismatch",
            "The uploaded module's SHA-256 does not match the recording package.",
        )
    if log_digest != parsed_package["log_sha256"]:
        raise _error(
            422,
            "replay_digest_mismatch",
            "The uploaded log's SHA-256 does not match the recording package.",
        )

    output = await replay_plugin(
        module_bytes,
        log_bytes,
        parsed_package["random_get"],
        expected_output,
        request,
    )

    return _json_response(
        {
            "reproduced": True,
            "module_sha256": module_digest,
            "log_sha256": log_digest,
            "random_calls": len(parsed_package["random_get"]),
            "random_bytes_consumed": sum(
                record["length"] for record in parsed_package["random_get"]
            ),
            "output_bytes": len(output),
            "output": base64.b64encode(output).decode("ascii"),
        }
    )


# Keep the documented limits visible to OpenAPI readers.
app.state.limits = {
    "module_bytes": MAX_MODULE_BYTES,
    "log_bytes": MAX_LOG_BYTES,
    "output_bytes": MAX_PLUGIN_OUTPUT_BYTES,
    "request_bytes": MAX_REQUEST_BYTES,
    "replay_request_bytes": MAX_REPLAY_REQUEST_BYTES,
    "package_bytes": MAX_PACKAGE_BYTES,
    "random_records": MAX_RANDOM_RECORDS,
    "random_bytes": MAX_RANDOM_BYTES,
    "memory_bytes": PLUGIN_MEMORY_BYTES,
    "timeout_seconds": PLUGIN_TIMEOUT_SECONDS,
}
