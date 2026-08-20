FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    CUDA_VISIBLE_DEVICES=-1 \
    TF_CPP_MIN_LOG_LEVEL=2 \
    HOME=/tmp/shieldnet-home

WORKDIR /app
COPY . /app

# iptables is needed by the netguard service (direct subprocess calls, no
# Shizuku/ADB indirection) - harmless for the shieldnet API image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Playwright is a base dependency (all five tiers run by default), so the
# headless Chromium browser ships in every image.
RUN python -m pip install . && \
    python -m playwright install --with-deps chromium && \
    groupadd --system shieldnet && \
    useradd --system --gid shieldnet --home-dir /nonexistent shieldnet && \
    mkdir -p /app/data /tmp/shieldnet-home /opt/ms-playwright && \
    chown -R shieldnet:shieldnet /app/data /tmp/shieldnet-home /opt/ms-playwright && \
    find /app -type f -exec chmod a+r {} + && \
    find /app -type d -exec chmod a+rx {} +

# Fail the image build when a bundled model is absent, incompatible, or below
# the minimum recorded validation contract used at runtime.
RUN python scripts/verify_models.py

USER shieldnet
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import json, urllib.request; json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3))"

CMD ["python", "main.py", "serve", "--host", "0.0.0.0", "--port", "8000"]
