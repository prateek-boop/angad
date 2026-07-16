import os

from fastapi import APIRouter, Response, status

import config

router = APIRouter()


@router.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "shieldnet", "version": config.VERSION}


@router.get("/ready")
async def ready(response: Response) -> dict:
    checks = {
        "model_present": os.path.isfile(config.MODEL_PATH),
        "data_directory_writable": os.access(config.DATA_DIR, os.W_OK)
        if os.path.isdir(config.DATA_DIR)
        else os.access(os.path.dirname(config.DATA_DIR), os.W_OK),
        "live_fetch_enabled": config.LIVE_FETCH_ENABLED,
        "visual_analysis_enabled": config.VISUAL_ANALYSIS_ENABLED,
    }
    ready_state = checks["model_present"] and checks["data_directory_writable"]
    if not ready_state:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ready" if ready_state else "not_ready", "checks": checks}
