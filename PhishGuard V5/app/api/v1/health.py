from fastapi import APIRouter


router = APIRouter()


@router.get("/health/live")
async def liveness():

    return {
        "status": "alive",
    }


@router.get("/health/ready")
async def readiness():

    return {
        "status": "ready",
    }
