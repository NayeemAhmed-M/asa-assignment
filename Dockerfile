# Multi-stage build for minimal image size and zero build-time CVEs
FROM python:3.11-slim-bookworm AS builder

# Set build environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /install

# Install build dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install/deps -r requirements.txt

# =========================================================================
# Final runtime stage
# =========================================================================
FROM python:3.11-slim-bookworm AS runner

# Hardening: Run as non-root user with dedicated UID/GID
ARG UID=10001
ARG GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/install/deps/bin:$PATH" \
    PYTHONPATH="/install/deps/lib/python3.11/site-packages:$PYTHONPATH"

# Create unprivileged group and user
RUN groupadd -g ${GID} appgroup && \
    useradd -u ${UID} -g appgroup -s /sbin/nologin -d /app appuser

WORKDIR /app

# Copy dependencies from builder stage
COPY --from=builder /install/deps /install/deps

# Copy application source code
COPY app/ /app/

# Ensure non-root user owns the working directory (allows SQLite db creation)
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER ${UID}:${GID}

# Expose API port
EXPOSE 8000

# Container healthcheck using standard library urllib (no curl/wget package required)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

# Start FastAPI using uvicorn
ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
