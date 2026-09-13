FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/wwfi

COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts ./scripts

RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install ".[web]"

RUN mkdir -p /data/config /data/certs /data/dns

EXPOSE 8000 8087 9090

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD bash /opt/wwfi/scripts/healthcheck.sh || exit 1

ENTRYPOINT ["bash", "/opt/wwfi/scripts/docker_entrypoint.sh"]