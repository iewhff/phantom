# AI-Enhanced Pentesting Framework
# Multi-stage build for optimized image size

FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# ============================================
# Production image
# ============================================
FROM python:3.11-slim as runtime

LABEL maintainer="AI Pentest Team"
LABEL version="2.0.0"
LABEL description="AI-Enhanced Penetration Testing Framework"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools
    nmap \
    dnsutils \
    curl \
    wget \
    # Build tools for some Python packages
    libffi8 \
    libssl3 \
    # Chromium for headless browser (optional)
    chromium \
    chromium-driver \
    # Cleanup
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install external security tools
RUN mkdir -p /opt/tools

# Install Nuclei
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /opt/tools && \
    rm /tmp/nuclei.zip && \
    chmod +x /opt/tools/nuclei && \
    ln -s /opt/tools/nuclei /usr/local/bin/nuclei

# Install httpx
RUN curl -sL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip -o /tmp/httpx.zip && \
    unzip /tmp/httpx.zip -d /opt/tools && \
    rm /tmp/httpx.zip && \
    chmod +x /opt/tools/httpx && \
    ln -s /opt/tools/httpx /usr/local/bin/httpx-pd

# Install subfinder
RUN curl -sL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip -o /tmp/subfinder.zip && \
    unzip /tmp/subfinder.zip -d /opt/tools && \
    rm /tmp/subfinder.zip && \
    chmod +x /opt/tools/subfinder && \
    ln -s /opt/tools/subfinder /usr/local/bin/subfinder

# Create non-root user
RUN groupadd -r pentest && useradd -r -g pentest pentest

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY . .

# Create data directories
RUN mkdir -p /app/data/reports /app/data/checkpoints /app/data/logs && \
    chown -R pentest:pentest /app

# Switch to non-root user
USER pentest

# Update nuclei templates
RUN nuclei -update-templates || true

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV AI_PENTEST_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8080/health')" || exit 1

# Default command
ENTRYPOINT ["python", "-m", "cli.main"]
CMD ["--help"]
