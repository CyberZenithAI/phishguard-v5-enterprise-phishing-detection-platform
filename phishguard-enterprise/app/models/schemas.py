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
