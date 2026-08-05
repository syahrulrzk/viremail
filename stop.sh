#!/bin/bash

# OSINTMail - Stop all services (except PostgreSQL and Redis)
# This script stops: Backend API, Celery Workers, Frontend

echo "🛑 Stopping VIRE services (keeping DB running)..."

# Kill processes by PID if .pids file exists
if [ -f .pids ]; then
    echo "📋 Reading PIDs from .pids file..."
    while read pid; do
        if ps -p $pid > /dev/null; then
            echo "  - Killing process $pid"
            kill $pid
        fi
    done < .pids
    rm .pids
fi

# Also kill by process name to be sure
echo "🔍 Killing any remaining processes..."
pkill -f "uvicorn main:app"
pkill -f "celery -A app.core.celery_app worker"
pkill -f "next dev"

echo ""
echo "✅ VIRE services stopped!"
echo ""
echo "📊 Service Status:"
echo "  - PostgreSQL: Still running (Docker)"
echo "  - Redis: Still running (Docker)"
echo "  - Backend API: Stopped"
echo "  - Celery Workers: Stopped"
echo "  - Frontend: Stopped"
echo ""
echo "💡 To start services again, run: ./start.sh"
echo "💡 To stop DB services too, run: docker-compose down"
