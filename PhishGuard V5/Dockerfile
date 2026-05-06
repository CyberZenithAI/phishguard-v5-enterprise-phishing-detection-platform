# Imagen base ligera
FROM python:3.11-slim

# Variables de entorno (mejor práctica)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Crear usuario no-root (seguridad)
RUN adduser --disabled-password --gecos "" appuser

# Directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema mínimas
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements primero (cache eficiente)
COPY requirements.txt .

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar proyecto
COPY . .

# Cambiar permisos
RUN chown -R appuser:appuser /app

# Cambiar a usuario seguro
USER appuser

# Exponer puerto API
EXPOSE 8000

# Comando por defecto (API)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]