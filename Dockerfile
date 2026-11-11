FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    WORKER_NAME=worker1 \
    CERT_DB_PATH=/data/certs.db \
    HTTPS_PORT=8443 \
    INTERNAL_PORT=18080

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

VOLUME /data
EXPOSE 8443

HEALTHCHECK --interval=15s --timeout=5s --start-period=25s --retries=5 \
    CMD ["python", "-m", "app.healthcheck"]

# 每个容器是一个独立 HTTPS 工作进程：对外只暴露 TLS 前置层，uvicorn 仅监听回环地址。
CMD ["python", "-m", "app.worker"]
