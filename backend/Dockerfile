# Backend image. Not built or run in the development environment used for this
# release; see docs/DEPLOYMENT.md for what has and has not been verified.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# libmagic is used by python-magic; the platform's own detector does not depend on it.
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY backend/tests ./tests
# Detection rules live at the repository root (see app/detection/query_loader.py).
COPY threat_hunting_queries /threat_hunting_queries

# Non-root user; quarantine storage is created at runtime with 0700 permissions.
RUN useradd --create-home appuser && mkdir -p /app/quarantine && chown appuser /app/quarantine
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
