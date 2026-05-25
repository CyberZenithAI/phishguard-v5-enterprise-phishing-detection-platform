from typing import Any
from pydantic import BaseModel, Field


class PipelineResult(BaseModel):

    url: str

    is_phishing: bool

    score: float = Field(..., ge=0, le=100)

    confidence: float = Field(..., ge=0, le=1)

    timestamp: str

    engine: str

    pipeline_stage: str

    correlation_id: str

    execution_time_ms: float

    details: dict[str, Any]
