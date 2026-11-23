"""Safe HTTP error envelope; never serialize exception text or request values."""

from fastapi import Request
from fastapi.responses import JSONResponse

from packages.storage.service import DomainError


class RateLimited(DomainError):
    def __init__(self, retry_after: int):
        super().__init__("RATE_LIMITED", 429)
        self.retry_after = retry_after


def error_response(
    request: Request,
    code: str,
    status: int,
    retry_after: int | None = None,
    *,
    details: dict[str, list[str]] | None = None,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unavailable")
    headers = {"X-Request-ID": request_id}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return JSONResponse(
        status_code=status,
        headers=headers,
        content={
            "error": {
                "code": code,
                "message": code,
                "request_id": request_id,
                "details": details or {},
            }
        },
    )
