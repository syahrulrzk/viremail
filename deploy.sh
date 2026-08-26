#!/bin/bash

# VIRE Deploy Script
# Pulls the latest images from GHCR and restarts containers.
#
# Usage:
#   ./deploy.sh              # uses "latest" tag
#   ./deploy.sh main         # uses branch name as tag
#   ./deploy.sh abc1234      # uses commit SHA as tag

set -euo pipefail

TAG="${1:-latest}"
COMPOSE_FILE="docker-compose.prod.yml"
REPO="${GITHUB_REPOSITORY:-}"

echo "🚀 Deploying VIRE with image tag: ${TAG}"

# Require GITHUB_REPOSITORY for proper image resolution
if [ -z "$REPO" ]; then
    echo "❌ Set GITHUB_REPOSITORY env var first, e.g.:"
    echo "   export GITHUB_REPOSITORY=your-org/vire"
    exit 1
fi

export IMAGE_TAG="$TAG"

echo "📦 Pulling images..."
docker compose -f "$COMPOSE_FILE" pull

echo "🔄 Restarting services..."
docker compose -f "$COMPOSE_FILE" up -d --force-recreate

echo ""
echo "✅ Deployed successfully!"
echo ""
echo "📊 Service status:"
docker compose -f "$COMPOSE_FILE" ps
echo ""
echo "💡 To check logs:"
echo "   docker compose -f $COMPOSE_FILE logs -f"
