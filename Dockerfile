FROM python:3.11.15-slim

ARG APP_UID=1000
ARG APP_GID=1000

ENV OPS_DEBUG=0 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=Asia/Shanghai \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/ops

WORKDIR /app

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gosu \
    tzdata \
    fonts-wqy-zenhei \
    fonts-wqy-microhei \
    fonts-dejavu \
    fonts-freefont-ttf \
    fontconfig \
    && fc-cache -fv \
    && fc-list | grep -i -E "(wqy|dejavu|freefont)" \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd --gid "${APP_GID}" ops \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home --home-dir /home/ops ops

COPY --chown=ops:ops . .

RUN mkdir -p logs reports data /home/ops/.ssh \
    && chown -R ops:ops /app /home/ops \
    && chmod 700 /home/ops/.ssh

RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 1999

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:1999/login', timeout=5)" || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["gunicorn", "--worker-class", "gthread", "--workers", "1", "--threads", "16", "--timeout", "180", "--graceful-timeout", "30", "--keep-alive", "5", "--bind", "0.0.0.0:1999", "--access-logfile", "-", "--error-logfile", "-", "wsgi:application"]
