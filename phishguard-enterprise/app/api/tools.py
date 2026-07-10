from fastapi import APIRouter, Depends, HTTPException
from app.models.schemas import EmailAnalyzeRequest, EmailAnalysisResponse
from app.core.security import get_current_user
from app.analysis.email_analyzer import analyze_email

router = APIRouter(prefix="/tools", tags=["Herramientas gratuitas"])

@router.post("/analyze-email", response_model=EmailAnalysisResponse)
async def analyze_email_endpoint(request: EmailAnalyzeRequest, user: str = Depends(get_current_user)):
    if not request.raw_email.strip():
        raise HTTPException(status_code=400, detail="El correo no puede estar vacío")
    result = await analyze_email(request.raw_email)
    return result
