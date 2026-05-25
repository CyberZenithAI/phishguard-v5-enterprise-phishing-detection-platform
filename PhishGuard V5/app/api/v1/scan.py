from fastapi import APIRouter

from app.core.pipeline import analyze

router = APIRouter()


@router.post("/scan")
async def scan(url: str):

    return await analyze(url)
