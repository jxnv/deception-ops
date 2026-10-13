# syntax=docker/dockerfile:1
# Hardened, Non-Root Dockerfile for DeceptionOps Canary Triage Service

FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Install security updates and curl for container health check
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-privileged system user for container execution (defense in depth)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

# Copy application source code
COPY webhook_receiver/ ./webhook_receiver/
COPY generator/ ./generator/

# Set file permissions
RUN chown -R appuser:appgroup /app

# Switch to non-root execution
USER appuser

EXPOSE 8000

# Container health monitoring
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/healthz || exit 1

ENTRYPOINT ["uvicorn", "webhook_receiver.app:app", "--host", "0.0.0.0", "--port", "8000"]
