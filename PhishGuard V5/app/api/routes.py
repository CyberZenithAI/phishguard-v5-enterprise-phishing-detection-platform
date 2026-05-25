from fastapi import APIRouter

from app.api.v1.health import router as health_router
from app.api.v1.scan import router as scan_router

router = APIRouter()

router.include_router(health_router, tags=["health"])

router.include_router(scan_router, tags=["analysis"])
