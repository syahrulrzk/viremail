FROM python:3.12-slim AS base

# System deps for psycopg2, cryptography, OCR (tesseract)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Default env
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# --- Backend (API) ---
FROM base AS api
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

# --- Celery Worker ---
FROM base AS worker
CMD ["celery", "-A", "app.core.celery_app", "worker", "--loglevel=info", "--concurrency=4"]
