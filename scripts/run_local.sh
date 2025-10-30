#!/bin/bash

# AutoMCP IaC Demo - Local Startup Script

set -e  # Exit on any error

echo "Starting AutoMCP IaC Security Demo..."
echo "===================================="

# Check if .env exists
if [ ! -f .env ]; then
    echo "Error: .env file not found. Please copy .env.example to .env and fill in your values."
    echo "cp .env.example .env"
    exit 1
fi

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    echo "Activating virtual environment..."
    source .venv/bin/activate
fi

# Set Python path
export PYTHONPATH="$(pwd):$PYTHONPATH"

# Start the FastAPI server with reload
echo "Launching gateway on http://localhost:8080"
echo "Health check: curl http://localhost:8080/healthz"
echo "Webhook endpoint: POST http://localhost:8080/webhook/github"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python -m uvicorn src.gateway.main:app --reload --host 0.0.0.0 --port 8080
