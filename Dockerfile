FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_PROGRESS_BAR=off

WORKDIR /app

COPY requirements-api.txt requirements.txt pyproject.toml setup.py README.md alembic.ini ./
COPY src ./src

RUN pip install --no-cache-dir -r requirements-api.txt \
    && pip install --no-cache-dir --no-deps -e .

EXPOSE 8000

# The slim image has no curl, so the health check uses the Python standard library.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

# The app writes its own JSON access log with route templates. Uvicorn's access log is off
# because it prints raw paths, which contain document IDs.
# Proxy headers are handled by the app (ENCRYPTED_IR_TRUSTED_PROXIES), not by uvicorn.
CMD ["sh", "-c", "alembic upgrade head && uvicorn encrypted_ir.api.main:create_app --factory --host 0.0.0.0 --port 8000 --no-access-log --no-proxy-headers"]
