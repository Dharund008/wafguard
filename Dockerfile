FROM python:3.12-slim

LABEL org.opencontainers.image.title="Cloudflare WAF Validation Framework"
LABEL org.opencontainers.image.version="1.0.0"

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application.
COPY pyproject.toml README.md ./
COPY waf_validator.py ./
COPY engine ./engine

# Install as a console entry point (provides the `waf-validator` command).
RUN pip install --no-cache-dir .

# Reports are written here; mount a volume to persist them on the host.
RUN mkdir -p /app/reports /app/zones
VOLUME ["/app/reports", "/app/zones"]

# The API token is supplied at runtime via -e CF_API_TOKEN=...
ENTRYPOINT ["waf-validator"]
CMD ["--help"]
