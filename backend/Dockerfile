# Backend image (FastAPI). Built and run as the `backend` service with the `app` profile;
# see docs/DEPLOYMENT.md.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# libmagic is used by python-magic; the platform's own detector does not depend on it.
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# TLS trust. Networks that intercept TLS (corporate proxies) re-sign certificates with
# their own CA. Put that CA (PEM, *.crt) in backend/certs/ before building; the
# directory is git-ignored except .gitkeep, so CA files are never committed.
# One bundle (public roots + any extra CA) is used by pip, requests and Python's
# default SSL context, so provider calls, RDAP and URL analysis all trust the same CAs.
COPY backend/certs/ /certs/
RUN python -c "import shutil; from pip._vendor import certifi; shutil.copy(certifi.where(), '/certs/ca-bundle.pem')" \
    && for f in /certs/*.crt; do [ -f "$f" ] && cat "$f" >> /certs/ca-bundle.pem; done; true
ENV REQUESTS_CA_BUNDLE=/certs/ca-bundle.pem SSL_CERT_FILE=/certs/ca-bundle.pem PIP_CERT=/certs/ca-bundle.pem

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
