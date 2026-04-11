FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Node.js is required for MCP stdio servers invoked via `npx`.
# tesseract-ocr is required for screenshot OCR preprocessing.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./

EXPOSE 8080

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]
