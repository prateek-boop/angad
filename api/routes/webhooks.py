from fastapi import APIRouter, HTTPException, Response, status

from api.deps import get_webhook_store
from api.models.schemas import WebhookRegisterRequest, WebhookRegisterResponse
from ml_engine.fetch.ssrf_guard import SSRFBlocked
from api.worker_pool import WorkerPoolBusy, worker_pool

router = APIRouter()


@router.post("/webhooks", response_model=WebhookRegisterResponse, status_code=201)
async def register_webhook(request: WebhookRegisterRequest) -> WebhookRegisterResponse:
    try:
        webhook_id = await worker_pool.run(
            get_webhook_store().register,
            url=request.url,
            secret=request.secret,
            min_threat_level=request.min_threat_level,
        )
    except WorkerPoolBusy as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (SSRFBlocked, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return WebhookRegisterResponse(webhook_id=webhook_id)


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_webhook(webhook_id: str) -> Response:
    if not await worker_pool.run(get_webhook_store().deactivate, webhook_id):
        raise HTTPException(status_code=404, detail="webhook not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
