import math
import threading
import time

from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Receive, Scope, Send


class BodyLimit:
    """Count actual ASGI bytes, including requests without Content-Length."""

    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        total = 0

        async def limited_receive():
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    raise HTTPException(status_code=413, detail="UPLOAD_TOO_LARGE")
            return message

        await self.app(scope, limited_receive if scope["type"] == "http" else receive, send)


class RequestLimiter:
    """Single-process fixed windows; never evict an unexpired quota to admit a new key."""

    def __init__(self, read_limit: int, write_limit: int, max_identities: int):
        self.limits = {"read": read_limit, "write": write_limit}
        self.maximum = max_identities
        self.windows: dict[str, tuple[float, dict[str, int]]] = {}
        self.lock = threading.Lock()

    def check(self, identity: str, operation: str, *, at: float | None = None) -> int:
        instant = time.monotonic() if at is None else at
        with self.lock:
            self.windows = {key: value for key, value in self.windows.items() if value[0] > instant}
            if identity not in self.windows:
                if len(self.windows) >= self.maximum:
                    return max(1, math.ceil(min(v[0] for v in self.windows.values()) - instant))
                self.windows[identity] = (instant + 60, {"read": 0, "write": 0})
            end, counts = self.windows[identity]
            if counts[operation] >= self.limits[operation]:
                return max(1, math.ceil(end - instant))
            counts[operation] += 1
            return 0
