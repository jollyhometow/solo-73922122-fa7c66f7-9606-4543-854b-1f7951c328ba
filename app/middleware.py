"""Request-body ceiling applied before multipart parsing."""

import json

# The replay endpoint carries a module, a log and a package that itself embeds
# copies of the first two, so its body ceiling is larger than the other routes.
_REPLAY_PATH = "/api/v1/replay"


class BodyLimitMiddleware:
    """Buffer a bounded request body, then replay it to the ASGI app.

    Starlette's multipart parser needs the whole body and may otherwise spool a
    client-controlled number of bytes to disk.  Here the body is capped before
    parsing, and the cap includes multipart framing in addition to the payload
    limits.
    """

    def __init__(self, app, max_body_bytes: int, replay_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.replay_body_bytes = replay_body_bytes

    def _limit_for(self, scope) -> int:
        if scope.get("path") == _REPLAY_PATH:
            return self.replay_body_bytes
        return self.max_body_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        body_limit = self._limit_for(scope)
        headers = {
            key.decode("latin-1").lower(): value
            for key, value in scope.get("headers", [])
        }
        declared = headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > body_limit:
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
            if len(body) + len(chunk) > body_limit:
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
