"""FastAPI surface for the isolated WASI endpoint-plugin sandbox."""

import json
from typing import Annotated

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response

from .config import (
    MAX_LOG_BYTES,
    MAX_MODULE_BYTES,
    MAX_PLUGIN_OUTPUT_BYTES,
    MAX_REQUEST_BYTES,
    PLUGIN_MEMORY_BYTES,
    PLUGIN_TIMEOUT_SECONDS,
)
from .errors import ApiError
from .middleware import BodyLimitMiddleware
from .sandbox import execute_plugin

API_DESCRIPTION = f"""
Runs a vendor-supplied **WASI Preview 1** endpoint-detection module against a
sanitised JSON log and returns the JSON that the module writes to stdout.

Sandbox guarantees:

* module upload: at most **1 MiB**; log upload: at most **64 KiB** of UTF-8 JSON
* one fresh subprocess per request, with an empty WASI environment, no preopened
  host directories, no sockets, and only stdin/stdout/stderr
* linear memory capped at **64 MiB**; wall-clock execution capped at
  **{PLUGIN_TIMEOUT_SECONDS:g} seconds**
* combined plugin stdout + stderr capped at **{MAX_PLUGIN_OUTPUT_BYTES} bytes**
* timeout, output overflow, or client disconnect kills and reaps the process
  group and removes temporary files; partial output is never returned

Demo artifacts are in the repository's `demo/` directory:

* `demo/classify.wasm` — reads stdin, then emits a JSON verdict
* `demo/loop.wasm` — intentionally never returns (demonstrates the timeout)
* `demo/spam.wasm` — writes continuously (demonstrates the output limit)
* `demo/sample-log.json` — benign log used by the classifier demo
"""

app = FastAPI(
    title="WASM Endpoint Plugin Sandbox",
    version="1.0.0",
    description=API_DESCRIPTION,
)
app.add_middleware(BodyLimitMiddleware, max_body_bytes=MAX_REQUEST_BYTES)

WASM_HEADER = b"\x00asm\x01\x00\x00\x00"


def _error(status_code: int, code: str, message: str) -> ApiError:
    return ApiError(status_code, code, message)


@app.exception_handler(ApiError)
async def _api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
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
repository's `demo/` directory.
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
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


# Keep the documented limits visible to OpenAPI readers.
app.state.limits = {
    "module_bytes": MAX_MODULE_BYTES,
    "log_bytes": MAX_LOG_BYTES,
    "output_bytes": MAX_PLUGIN_OUTPUT_BYTES,
    "request_bytes": MAX_REQUEST_BYTES,
    "memory_bytes": PLUGIN_MEMORY_BYTES,
    "timeout_seconds": PLUGIN_TIMEOUT_SECONDS,
}
