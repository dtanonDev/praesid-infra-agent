#!/bin/bash
set -e

echo "➡️ Pull latest code"
git pull

echo "🐳 Build image"
docker build -t praesid-infra-agent:1 .

echo "♻️ Restart container"
docker rm -f praesid-infra-agent || true
docker run -d --restart=always \
  --env-file .env \
  --name praesid-infra-agent \
  praesid-infra-agent:1

echo "✅ Done"
