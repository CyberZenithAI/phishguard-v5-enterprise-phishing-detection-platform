from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.auth import router as auth_router
from app.api.analysis import router as analysis_router
from app.monitoring.metrics import MetricsMiddleware, metrics_router

app = FastAPI(
    title="PhishGuard Enterprise",
    version="0.9.0",
    description="Plataforma de detección de phishing con inteligencia DNS"
)

# CORS básico
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware de métricas
app.add_middleware(MetricsMiddleware)

# Routers
app.include_router(auth_router, prefix="/auth", tags=["Autenticación"])
app.include_router(analysis_router, prefix="/analyze", tags=["Análisis"])
app.include_router(metrics_router)
