# app/api/routes.py

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from pydantic import BaseModel

from app.auth import verify
from app.core.pipeline import analyze

router = APIRouter()


class ScanRequest(BaseModel):
    domain: str


@router.get("/")
async def api_root():

    return {
        "api": "online"
    }


@router.get("/health")
async def api_health():

    return {
        "status": "ok"
    }


@router.post("/scan", dependencies=[Depends(verify)])
async def scan(payload: ScanRequest):

    domain = payload.domain.strip().lower()

    if not domain:
        raise HTTPException(
            status_code=400,
            detail="invalid_domain"
        )

    results = await analyze(domain)

    return {
        "target": domain,
        "results": results
    }
