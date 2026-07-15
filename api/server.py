from fastapi import FastAPI

from api.middleware import SecurityMiddleware
from api.routes import feedback, health, operations, scan, webhooks

app = FastAPI(
    title="ShieldNet",
    version="1.0.0",
    description="Calibrated multi-evidence URL threat analysis API",
)
app.add_middleware(SecurityMiddleware)

app.include_router(scan.router, prefix="/api/v1", tags=["scan"])
app.include_router(feedback.router, prefix="/api/v1", tags=["feedback"])
app.include_router(webhooks.router, prefix="/api/v1", tags=["webhooks"])
app.include_router(operations.router, prefix="/api/v1", tags=["operations"])
app.include_router(health.router, prefix="/api/v1", tags=["health"])
