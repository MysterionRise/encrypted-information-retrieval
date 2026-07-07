FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_PROGRESS_BAR=off

WORKDIR /app

COPY requirements-api.txt requirements.txt pyproject.toml setup.py README.md alembic.ini ./
COPY src ./src
COPY alembic ./alembic

RUN pip install --no-cache-dir -r requirements-api.txt \
    && pip install --no-cache-dir --no-deps -e .

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn encrypted_ir.api.main:create_app --factory --host 0.0.0.0 --port 8000"]
