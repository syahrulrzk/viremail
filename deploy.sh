#!/bin/bash

# VIRE Deploy Script
# Pulls the latest images from GHCR and restarts containers.
#
# Usage:
#   ./deploy.sh              # uses "latest" tag
#   ./deploy.sh main         # uses branch name as tag
#   ./deploy.sh abc1234      # uses commit SHA as tag

set -euo pipefail

echo "🚀 Deploying VIRE..."

echo "📦 Pulling images..."
docker compose pull

echo "🔄 Restarting services..."
docker compose up -d --force-recreate

echo ""
echo "✅ Deployed successfully!"
echo ""
echo "📊 Service status:"
docker compose ps
echo ""
echo "💡 To check logs:"
echo "   docker compose logs -f"
