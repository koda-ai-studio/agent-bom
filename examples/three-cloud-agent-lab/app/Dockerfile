FROM python:3.12.16-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY pinned-packages.txt .
RUN pip install --no-cache-dir -r pinned-packages.txt
COPY agent.py mcp.json ./
USER 65534
CMD ["python", "agent.py"]
