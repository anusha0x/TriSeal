FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY chambers/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY chambers/red/ /app/
ENV PYTHONPATH=/app

RUN useradd -u 1001 -m triseal_red
USER triseal_red

EXPOSE 8003
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8003"]
