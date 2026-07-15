from fastapi import APIRouter, HTTPException

from api.deps import get_feedback_store
from api.models.schemas import FeedbackRequest, FeedbackResponse
from api.worker_pool import WorkerPoolBusy, worker_pool
from pipeline.validation import InvalidURL, validate_url_format

router = APIRouter()


@router.post("/feedback", response_model=FeedbackResponse, status_code=201)
async def submit_feedback(request: FeedbackRequest) -> FeedbackResponse:
    try:
        url = validate_url_format(request.url) if request.url else None
        feedback_id = await worker_pool.run(
            get_feedback_store().submit,
            scan_id=request.scan_id,
            url=url,
            correct_label=request.correct_label,
            notes=request.notes,
            submitted_by=request.submitted_by,
        )
    except WorkerPoolBusy as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (InvalidURL, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return FeedbackResponse(feedback_id=feedback_id)
