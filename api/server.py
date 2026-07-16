import logging

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

import config
from api.metrics import metrics
from api.middleware import SecurityMiddleware
from api.routes import feedback, health, operations, scan, webhooks

_LOGGER = logging.getLogger("shieldnet.api")

app = FastAPI(
    title="ShieldNet",
    version=config.VERSION,
    description="Calibrated multi-evidence URL threat analysis API",
)
app.add_middleware(SecurityMiddleware)


@app.exception_handler(Exception)
async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort boundary: never leak internals, always correlate via request_id."""
    request_id = getattr(request.state, "request_id", None) or "unknown"
    _LOGGER.error(
        "unhandled error on %s %s (request_id=%s)",
        request.method,
        request.url.path,
        request_id,
        exc_info=exc,
    )
    metrics.record_error(type(exc).__name__)
    return JSONResponse(
        status_code=500,
        content={"detail": "internal server error", "request_id": request_id},
        headers={"X-Request-ID": request_id},
    )


app.include_router(scan.router, prefix="/api/v1", tags=["scan"])
app.include_router(feedback.router, prefix="/api/v1", tags=["feedback"])
app.include_router(webhooks.router, prefix="/api/v1", tags=["webhooks"])
app.include_router(operations.router, prefix="/api/v1", tags=["operations"])
app.include_router(health.router, prefix="/api/v1", tags=["health"])
