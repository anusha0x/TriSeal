FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY chambers/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY chambers/llm/ /app/
ENV PYTHONPATH=/app

RUN useradd -u 1003 -m triseal_llm
USER triseal_llm

EXPOSE 8002
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8002"]
