FROM python:3.13.5-slim-bookworm
WORKDIR /opt/trace
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements-dev.lock ./
RUN pip install --no-cache-dir -r requirements-dev.lock \
    && groupadd -g 10001 trace && useradd -u 10001 -g trace trace \
    && mkdir -p /data/raw /data/staging \
    && chown -R trace:trace /data
COPY apps/__init__.py apps/__init__.py
COPY apps/api apps/api
COPY apps/worker apps/worker
COPY packages packages
COPY migrations migrations
COPY rules rules
COPY knowledge knowledge
COPY scripts/__init__.py scripts/container_health.py scripts/
USER 10001:10001
CMD ["python", "-m", "apps.api.main"]
