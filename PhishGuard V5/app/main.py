from fastapi import FastAPI
from app.api.routes import router
from app.core.logger import setup

setup()

app = FastAPI(title="PhishGuard V4")

app.include_router(router, prefix="/scan")