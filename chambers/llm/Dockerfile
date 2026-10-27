FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libgomp1 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY chambers/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY chambers/llm/ /app/
ENV PYTHONPATH=/app
ENV LD_LIBRARY_PATH=/app/bin
ENV PATH=/app/bin:$PATH
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN chmod -R 755 /app/bin 2>/dev/null || true
RUN useradd -u 1003 -m triseal_llm
USER triseal_llm

EXPOSE 8002
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8002"]
