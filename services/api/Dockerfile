FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app
COPY requirements.txt ./
COPY requirements-media.txt ./
COPY requirements-dev.txt ./
# OpenCV's OCR import requires libGL even for this server's raster workflow.
RUN apt-get update && apt-get install -y --no-install-recommends libgl1 tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*
# Optional trust bundle for package installs behind a managed TLS proxy.
# BuildKit mounts it only for this step; it is not copied into the image.
RUN --mount=type=secret,id=package_ca \
    if [ -f /run/secrets/package_ca ]; then export PIP_CERT=/run/secrets/package_ca; fi \
    && pip install --no-cache-dir -r requirements-dev.txt
COPY app ./app
COPY tests ./tests
RUN useradd --create-home --uid 10001 anonflow && chown -R anonflow:anonflow /app
USER anonflow
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
