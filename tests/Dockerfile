FROM python:3.11-slim

WORKDIR /app

# Install system dependencies and uv
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    xmlstarlet \
    pkg-config \
    libxml2-dev \
    libxmlsec1-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && pip install uv

# Copy project files for dependency installation
COPY pyproject.toml .

# Install dependencies using uv from pyproject.toml
RUN uv pip install --system --no-cache \
    pytest==7.4.0 \
    pytest-html==3.2.0 \
    pytest-json-report==1.5.0 \
    requests==2.31.0 \
    python-keycloak==3.7.0 \
    PyJWT==2.8.0 \
    cryptography==41.0.3 \
    lxml==4.9.3 \
    xmlsec==1.3.13 \
    python3-saml==1.15.0 \
    selenium==4.11.2 \
    webdriver-manager==4.0.0

# Copy test files
COPY . .

# Create results directory
RUN mkdir -p /app/results

# Default command
CMD ["python", "-m", "pytest", ".", "-v"]