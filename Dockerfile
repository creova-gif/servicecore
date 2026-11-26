FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src
COPY evals ./evals
RUN pip install --no-cache-dir .

RUN addgroup --system servicecore && adduser --system --ingroup servicecore servicecore

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/readyz', timeout=3)"]
USER servicecore
CMD ["uvicorn", "servicecore.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
