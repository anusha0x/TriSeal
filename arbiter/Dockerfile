FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY chambers/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY ledger/ /app/ledger/
COPY arbiter/ /app/arbiter/
ENV PYTHONPATH=/app

EXPOSE 8000
CMD ["uvicorn", "arbiter.server:app", "--host", "0.0.0.0", "--port", "8000"]
