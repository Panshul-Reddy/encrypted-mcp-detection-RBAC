FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY client.py .

ENV PYTHONUNBUFFERED=1
# Disable SSL cert verification for self-signed lab cert
ENV PYTHONHTTPSVERIFY=0

CMD ["python", "client.py"]