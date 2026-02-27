FROM python:3.11-slim AS base

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup && \
    ln -s /root/.foundry/bin/forge /usr/local/bin/forge && \
    ln -s /root/.foundry/bin/cast /usr/local/bin/cast

# Install solc-select for version management
RUN pip install solc-select && \
    solc-select install 0.8.20 && \
    solc-select use 0.8.20

WORKDIR /app

# Install Python dependencies first (cache layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir hatch && \
    pip install --no-cache-dir -e ".[dev]"

# Copy source
COPY src/ ./src/
COPY config/ ./config/
COPY tests/ ./tests/

# Production stage
FROM base AS production
RUN pip install --no-cache-dir contract-audit
CMD ["contract-audit", "--help"]

# Development stage (with dev deps)
FROM base AS development
ENV PYTHONPATH=/app/src
CMD ["bash"]

# CI stage (optimized for GitHub Actions)
FROM base AS ci
COPY . .
RUN pip install -e ".[dev]"
CMD ["pytest", "tests/", "-v", "--tb=short"]
