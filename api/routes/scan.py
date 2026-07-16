"""Single and bounded-concurrency batch scan endpoints."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, BackgroundTasks, HTTPException

from api.deps import get_orchestrator, get_webhook_dispatcher
from api.metrics import metrics
from api.models.schemas import (
    BatchScanRequest,
    BatchScanResponse,
    ScanRequest,
    ScanResponse,
)
from api.worker_pool import WorkerPoolBusy, worker_pool
from pipeline.validation import InvalidURL, validate_url_format

router = APIRouter()


def _scan_sync(orchestrator, request: ScanRequest) -> dict:
    return orchestrator.scan(
        request.url, depth=request.depth, timeout_ms=request.timeout_ms
    )


def _dispatch_threat_event_sync(result: dict) -> None:
    if result["decision"] != "block":
        return
    payload = {
        key: result[key]
        for key in (
            "scan_id",
            "category",
            "confidence",
            "risk_score",
            "threat_level",
            "decision",
            "reasons",
            "probabilities",
        )
    }
    get_webhook_dispatcher().dispatch(
        "threat.detected", payload, result["threat_level"]
    )


async def _dispatch_threat_event(result: dict) -> None:
    await worker_pool.run(_dispatch_threat_event_sync, result)


@router.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest, background_tasks: BackgroundTasks) -> ScanResponse:
    try:
        validate_url_format(request.url)
        # TensorFlow must finish initializing on this thread before dispatch.
        orchestrator = get_orchestrator()
        result = await worker_pool.run(_scan_sync, orchestrator, request)
    except WorkerPoolBusy as exc:
        metrics.record_error("worker_pool_busy")
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (InvalidURL, ValueError) as exc:
        metrics.record_error("invalid_request")
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    metrics.record_scan(
        category=result["category"],
        depth=request.depth,
        decision=result["decision"],
        elapsed_ms=result["scan_time_ms"],
    )
    if result["decision"] == "block":
        background_tasks.add_task(_dispatch_threat_event, result)
    return ScanResponse.model_validate(result)


@router.post("/scan/batch", response_model=BatchScanResponse)
async def scan_batch(request: BatchScanRequest) -> BatchScanResponse:
    try:
        for url in request.urls:
            validate_url_format(url)
    except InvalidURL as exc:
        metrics.record_error("invalid_request")
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    semaphore = asyncio.Semaphore(min(4, len(request.urls)))
    orchestrator = get_orchestrator()

    async def run_one(url: str) -> ScanResponse:
        async with semaphore:
            item = ScanRequest(
                url=url, depth=request.depth, timeout_ms=request.timeout_ms
            )
            try:
                result = await worker_pool.run(_scan_sync, orchestrator, item)
            except WorkerPoolBusy as exc:
                metrics.record_error("worker_pool_busy")
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            except (InvalidURL, ValueError) as exc:
                metrics.record_error("invalid_request")
                raise HTTPException(
                    status_code=422, detail=f"{url[:120]}: {exc}"
                ) from exc
            metrics.record_scan(
                category=result["category"],
                depth=request.depth,
                decision=result["decision"],
                elapsed_ms=result["scan_time_ms"],
            )
            return ScanResponse.model_validate(result)

    results = await asyncio.gather(*(run_one(url) for url in request.urls))
    return BatchScanResponse(results=results)
