#!/bin/bash
set -euo pipefail

ENV_FILE="${1:-.env.production}"

if ! command -v pm2 >/dev/null 2>&1; then
  echo "pm2 is required (npm install -g pm2)" >&2
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "Environment file '$ENV_FILE' not found." >&2
  exit 1
fi

echo "📦 Installing dependencies (production-only)..."
npm install --production

echo "🚀 Starting agent via PM2 (env file: $ENV_FILE)"
AGENT_ENV_FILE="$ENV_FILE" pm2 start ecosystem.config.cjs --env production --update-env

echo "💾 Persisting PM2 process list"
pm2 save

echo "🪪 Ensuring PM2 restarts on boot"
pm2 startup systemd -u "$(whoami)" --hp "$HOME"

echo "✅ Agent deployed under PM2. Use 'pm2 status' to verify."
