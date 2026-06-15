FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY tls_proxy.py /app/tls_proxy.py
COPY tool_policy.yaml /app/tool_policy.yaml
CMD ["python", "-u", "/app/tls_proxy.py", "--cert", "/etc/nginx/ssl/mcp.crt", "--key", "/etc/nginx/ssl/mcp.key", "--backend-host", "10.11.0.10", "--mappings", "8440:3000,8441:3001,8442:3002,8443:3003,8444:3004,8445:3005", "--control-port", "9999", "--policy", "/app/tool_policy.yaml"]
