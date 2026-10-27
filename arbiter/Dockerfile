FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY chambers/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY ledger/ /app/ledger/
COPY arbiter/ /app/arbiter/
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN useradd -u 1000 -m triseal_arbiter
USER triseal_arbiter

EXPOSE 8000
CMD ["uvicorn", "arbiter.server:app", "--host", "0.0.0.0", "--port", "8000"]
