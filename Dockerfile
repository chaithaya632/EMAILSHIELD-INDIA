# Dockerfile for EMAILSHIELD Sentinel External Worker
# Hardened, unprivileged container runtime for outbound-only worker service.

FROM python:3.12-slim

# Security: run as non-root user
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -s /bin/bash -m sentinel

WORKDIR /app

# Install dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy only worker and core modules (zero secrets, zero environment files, zero private keys)
COPY core/ /app/core/
COPY worker/ /app/worker/

# Set ownership
RUN chown -R sentinel:sentinel /app

# Switch to unprivileged user
USER sentinel

# Outbound-only service: no public ports exposed
# Environment secrets (SENTINEL_WORKER_DB_URL, SENTINEL_WORKER_PRIVATE_KEY, etc.)
# must be injected securely at runtime via orchestration / secret manager.

ENTRYPOINT ["python", "-m", "worker"]
