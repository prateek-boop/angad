FROM python:3.12-slim

ARG INSTALL_VISUAL=0
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    HOME=/tmp/shieldnet-home

WORKDIR /app
COPY . /app

RUN if [ "$INSTALL_VISUAL" = "1" ]; then \
      python -m pip install ".[visual]" && \
      python -m playwright install --with-deps chromium; \
    else \
      python -m pip install .; \
    fi && \
    groupadd --system shieldnet && \
    useradd --system --gid shieldnet --home-dir /nonexistent shieldnet && \
    mkdir -p /app/data /tmp/shieldnet-home /opt/ms-playwright && \
    chown -R shieldnet:shieldnet /app/data /tmp/shieldnet-home /opt/ms-playwright && \
    find /app -type f -exec chmod a+r {} + && \
    find /app -type d -exec chmod a+rx {} +

USER shieldnet
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import json, urllib.request; json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3))"

CMD ["python", "main.py", "serve", "--host", "0.0.0.0", "--port", "8000"]
