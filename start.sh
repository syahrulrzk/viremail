#!/bin/bash

# OSINTMail - Start all services
# This script starts: PostgreSQL, Redis, Backend API, Celery Workers, Frontend

echo "🚀 Starting VIRE (Verified Intelligence & Recon Engine) services..."

# Start PostgreSQL and Redis (Docker Compose)
echo "📦 Starting PostgreSQL and Redis..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 5

# Start Backend API
echo "🔧 Starting Backend API..."
cd backend
source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
cd ..

# Start Celery Workers
echo "🔄 Starting Celery Workers..."
cd backend
source venv/bin/activate
celery -A app.core.celery_app worker --loglevel=info &
CELERY_PID=$!
cd ..

# Start Frontend
echo "🎨 Starting Frontend..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "✅ All VIRE services started!"
echo ""
echo "📊 Service Status:"
echo "  - PostgreSQL: Running (Docker)"
echo "  - Redis: Running (Docker)"
echo "  - Backend API: http://localhost:8000 (PID: $BACKEND_PID)"
echo "  - Celery Workers: Running (PID: $CELERY_PID)"
echo "  - Frontend: http://localhost:3001 (PID: $FRONTEND_PID)"
echo ""
echo "🛑 To stop all services (except DB), run: ./stop.sh"
echo ""
echo "💡 PIDs saved to .pids file"
echo $BACKEND_PID > .pids
echo $CELERY_PID >> .pids
echo $FRONTEND_PID >> .pids
