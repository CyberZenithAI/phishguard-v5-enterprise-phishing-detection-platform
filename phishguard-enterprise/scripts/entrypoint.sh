#!/bin/sh
set -e

# Lanzar la API con Uvicorn
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
