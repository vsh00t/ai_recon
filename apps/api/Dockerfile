FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY ai_recon /opt/ai_recon
COPY apps/api /app

RUN pip install -e /opt/ai_recon && pip install -e /app

EXPOSE 8000
CMD ["uvicorn", "ai_recon_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
