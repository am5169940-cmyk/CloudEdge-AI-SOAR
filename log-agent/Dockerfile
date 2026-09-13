# CloudEdge-AI-SOAR log-agent
# Multi-stage build: compile deps in a full image, ship a slim runtime.

FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-slim
LABEL org.opencontainers.image.title="cloudedge-ai-soar-log-agent"
LABEL org.opencontainers.image.description="Multi-threaded Linux log collector for CloudEdge-AI-SOAR"

# Non-root user — this process reads sensitive auth logs, don't run it as root
# unless your log files genuinely require root to read (then use ACLs instead).
RUN groupadd --system cloudedge && useradd --system --gid cloudedge --home /app cloudedge

WORKDIR /app
COPY --from=builder /root/.local /home/cloudedge/.local
COPY src/ ./src/
COPY config/ ./config/

RUN mkdir -p /var/lib/cloudedge-agent && chown -R cloudedge:cloudedge /var/lib/cloudedge-agent /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PATH="/home/cloudedge/.local/bin:${PATH}"

USER cloudedge

ENTRYPOINT ["python", "src/main.py"]
CMD ["--config", "config/config.yaml"]
