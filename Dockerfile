FROM python:3.14-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry

COPY pyproject.toml poetry.lock ./

# Install only runtime dependencies into /app/.venv
RUN poetry install --only main --no-root \
    && rm -rf "$POETRY_CACHE_DIR"


# ---------- test ----------
FROM builder AS test

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

COPY . .

# Install test/dev dependencies, then run tests
RUN poetry install --with dev --no-root \
    && rm -rf "$POETRY_CACHE_DIR"

RUN find . -name "*.pyc" -delete && find . -name "__pycache__" -delete

RUN ./.venv/bin/pytest -q \
    && touch /tmp/tests-passed


# ---------- runtime ----------
FROM python:3.14-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN addgroup --system app && adduser --system --ingroup app app

# Copy the prebuilt virtualenv from builder
COPY --chown=app:app --from=builder /app/.venv /app/.venv

# Force test stage to run before final image is produced
COPY --from=test /tmp/tests-passed /tmp/tests-passed

# Copy only runtime application files
COPY --chown=app:app app /app/app
COPY --chown=app:app pyproject.toml poetry.lock /app/
USER app:app

EXPOSE 8000

HEALTHCHECK --interval=120s --timeout=5s --start-period=30s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
