from pydantic import BaseModel, HttpUrl
from typing import Optional

class Token(BaseModel):
    access_token: str
    token_type: str

class AnalyzeRequest(BaseModel):
    url: HttpUrl

class TaskResponse(BaseModel):
    task_id: str
    status: str

class AnalysisResult(BaseModel):
    task_id: str
    status: str
    score: Optional[float] = None
    details: Optional[str] = None

# --- Esquemas adicionales para análisis de correo electrónico ---

class EmailAnalyzeRequest(BaseModel):
    raw_email: str

class EmailHeaderInfo(BaseModel):
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    from_domain: Optional[str] = None

class EmailAnalysisResponse(BaseModel):
    risk_score: float
    risk_level: str
    headers: EmailHeaderInfo
    urls_found: list[str]
    domain_analysis: list[dict]  # resultados rápidos de cada dominio
    summary: str
