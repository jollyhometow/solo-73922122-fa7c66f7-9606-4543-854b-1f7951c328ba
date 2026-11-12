"""Request-body ceiling applied before multipart parsing."""

import json


class BodyLimitMiddleware:
    """Buffer a bounded request body, then replay it to the ASGI app.

    Starlette's multipart parser needs the whole body and may otherwise spool a
    client-controlled number of bytes to disk.  Here the body is capped before
    parsing, and the cap includes multipart framing in addition to the two
    payload limits.
    """

    def __init__(self, app, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value
            for key, value in scope.get("headers", [])
        }
        declared = headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > self.max_body_bytes:
                    await self._send_413(send)
                    return
            except ValueError:
                await self._send_413(send)
                return

        body = bytearray()
        while True:
            try:
                message = await receive()
            except Exception:
                return
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue

            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_body_bytes:
                await self._send_413(send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {
                    "type": "http.request",
                    "body": bytes(body),
                    "more_body": False,
                }
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _send_413(send) -> None:
        payload = {
            "error": {
                "code": "request_too_large",
                "message": "The request body exceeds the service limit.",
            }
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


__all__ = ["BodyLimitMiddleware"]
