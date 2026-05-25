from fastapi import FastAPI
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.logging_config import configure_logging
from app.core.pipeline import analyze


configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup
    yield
    # shutdown


app = FastAPI(
    title="PhishGuard AI V5",
    version="5.0",
    lifespan=lifespan
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get(f"{settings.API_V1_PREFIX}/analyze")
async def analyze_endpoint(url: str):
    return await analyze(url)
