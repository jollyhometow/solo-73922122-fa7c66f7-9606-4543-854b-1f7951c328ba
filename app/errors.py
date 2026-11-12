"""Errors returned by the public API."""


class ApiError(Exception):
    """An intentional, client-visible API error.

    ``message`` is written by this service, never copied verbatim from an
    uploaded module or its output.
    """

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
