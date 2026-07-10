from fastapi import APIRouter, Depends, HTTPException
from app.models.schemas import AnalyzeRequest, TaskResponse, AnalysisResult
from app.tasks.celery_app import analyze_domain_task
from app.core.security import get_current_user

router = APIRouter()

@router.post("/domain", response_model=TaskResponse)
async def analyze_domain(request: AnalyzeRequest, user: str = Depends(get_current_user)):
    task = analyze_domain_task.delay(request.url)
    return TaskResponse(task_id=task.id, status="processing")

@router.get("/result/{task_id}", response_model=AnalysisResult)
async def get_result(task_id: str, user: str = Depends(get_current_user)):
    from celery.result import AsyncResult
    from app.tasks.celery_app import celery_app
    result = AsyncResult(task_id, app=celery_app)
    if not result.ready():
        return AnalysisResult(task_id=task_id, status="processing", score=None, details="Aún en proceso")
    if result.failed():
        raise HTTPException(status_code=500, detail=str(result.result))
    return result.result
