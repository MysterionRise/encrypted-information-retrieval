# Encrypted IR API image: the API and the migrations CLI, with boto3 for the AWS KMS path.
# Dependencies come from requirements-docker.txt, which pins every package with hashes
# (pip-compile --extra aws --generate-hashes; see CONTRIBUTING.md). The base image is pinned by
# digest; Dependabot proposes updates.

ARG PYTHON_IMAGE=python:3.11-slim@sha256:673719e071ecf27434fd2635bbd8d00f49f4fdd81f243143438a42ced8bedf60

FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_PROGRESS_BAR=off

WORKDIR /build
COPY requirements-docker.txt ./
RUN pip wheel --require-hashes --wheel-dir /wheels -r requirements-docker.txt

COPY pyproject.toml setup.py README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-deps --wheel-dir /wheels .


FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Install exactly the wheels built above (hash-checked in the builder) without keeping them in a
# layer, then check that their requirements are consistent.
RUN --mount=type=bind,from=builder,source=/wheels,target=/wheels \
    pip install --no-index --no-deps /wheels/*.whl \
    && pip check

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin app
USER 10001:10001
WORKDIR /tmp

EXPOSE 8000

# The slim image has no curl, so the health check uses the Python standard library.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

# Schema migrations are a separate step: `python -m encrypted_ir.migrations upgrade head`
# (the Compose `migrate` service). The app writes its own JSON access log with route templates;
# uvicorn's access log is off because it prints raw paths, which contain document IDs. Proxy
# headers are handled by the app (ENCRYPTED_IR_TRUSTED_PROXIES), not by uvicorn.
CMD ["uvicorn", "encrypted_ir.api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-proxy-headers"]
