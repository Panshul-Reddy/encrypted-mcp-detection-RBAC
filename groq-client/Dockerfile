FROM python:3.11-slim

RUN pip install requests openai urllib3

WORKDIR /app
COPY groq_mcp_client.py /app/groq_mcp_client.py

CMD ["python", "/app/groq_mcp_client.py"]
