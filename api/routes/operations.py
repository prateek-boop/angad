from fastapi import APIRouter

from api.deps import get_drift_monitor, get_feedback_store
from api.metrics import metrics
from api.worker_pool import worker_pool

router = APIRouter()


@router.get("/operations/drift")
async def drift_report() -> dict:
    return await worker_pool.run(get_drift_monitor().report)


@router.get("/operations/feedback")
async def feedback_summary() -> dict:
    return await worker_pool.run(get_feedback_store().summary)


@router.get("/operations/metrics")
async def metrics_snapshot() -> dict:
    return metrics.snapshot()
