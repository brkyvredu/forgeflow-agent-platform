FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system forgeflow && useradd --system --gid forgeflow --home /app forgeflow

COPY pyproject.toml README.md ./
COPY forgeflow ./forgeflow
COPY forgeflow_mcp ./forgeflow_mcp
RUN pip install .

USER forgeflow
EXPOSE 8000

CMD ["adk", "api_server", "--host", "0.0.0.0", "--port", "8000", "."]
