"""API authentication, local rate limiting, request IDs, and hardening headers."""

from __future__ import annotations

import hmac
import threading
import time
import uuid
from collections import defaultdict, deque

from fastapi import Request
from starlette.responses import JSONResponse

import config


class SecurityMiddleware:
    def __init__(self, app):
        self.app = app
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    @staticmethod
    def _client_id(request: Request) -> str:
        if config.TRUST_PROXY_HEADERS:
            forwarded = (
                request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
            )
            if forwarded:
                return forwarded
        return request.client.host if request.client else "unknown"

    @staticmethod
    def _provided_api_key(request: Request) -> str | None:
        direct = request.headers.get("x-api-key")
        if direct:
            return direct
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return None

    @staticmethod
    def _key_is_valid(provided: str | None) -> bool:
        if not config.API_KEYS:
            return True
        if not provided:
            return False
        return any(
            hmac.compare_digest(provided, expected) for expected in config.API_KEYS
        )

    def _rate_limited(self, client_id: str, now: float) -> bool:
        limit = int(config.RATE_LIMIT_REQUESTS_PER_MIN)
        with self._lock:
            bucket = self._requests[client_id]
            while bucket and bucket[0] <= now - 60.0:
                bucket.popleft()
            if len(bucket) >= limit:
                return True
            bucket.append(now)
            if len(self._requests) > 10_000:
                empty = [
                    key
                    for key, values in self._requests.items()
                    if not values or values[-1] <= now - 60.0
                ]
                for key in empty[:1000]:
                    self._requests.pop(key, None)
            return False

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = request_id
        protected = request.url.path.startswith("/api/v1") and request.url.path not in {
            "/api/v1/health",
            "/api/v1/ready",
        }
        if protected and not self._key_is_valid(self._provided_api_key(request)):
            response = JSONResponse(
                status_code=401,
                content={"detail": "valid API key required", "request_id": request_id},
                headers={"WWW-Authenticate": "Bearer", "X-Request-ID": request_id},
            )
            await response(scope, receive, send)
            return
        if protected and self._rate_limited(self._client_id(request), time.monotonic()):
            response = JSONResponse(
                status_code=429,
                content={"detail": "rate limit exceeded", "request_id": request_id},
                headers={"Retry-After": "60", "X-Request-ID": request_id},
            )
            await response(scope, receive, send)
            return

        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-request-id", request_id.encode("ascii", errors="ignore")),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"cache-control", b"no-store"),
                    ]
                )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
