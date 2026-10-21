# Standalone connector service image. Build from the repo root:
#   docker build -f connector/Dockerfile -t oqos-connector .
#
# Webhook mode (receive pushed batches):
#   docker run -p 8900:8900 -v $PWD/data:/data -e OQOS_DB_PATH=/data/harvest.db \
#     oqos-connector serve-webhook --host 0.0.0.0 --port 8900 --token "$SECRET"
#
# Poll mode (pull a source on an interval):
#   docker run -v $PWD/data:/data -e OQOS_DB_PATH=/data/harvest.db oqos-connector \
#     poll --source cloudflare --url "$URL" --token "$CF_TOKEN" --interval 300
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml ./
COPY connector ./connector
RUN pip install --no-cache-dir ".[url]"

ENV OQOS_DB_PATH=/data/harvest.db
VOLUME ["/data"]
EXPOSE 8900

ENTRYPOINT ["oqos-connector"]
CMD ["serve-webhook", "--host", "0.0.0.0", "--port", "8900"]
