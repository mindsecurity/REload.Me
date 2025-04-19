#!/bin/bash
# setup.sh - REloadAI Setup Script

echo "REloadAI Setup Script v2.0"
echo "=========================="
echo

# Check for required commands
for cmd in docker docker-compose python3 git; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is required but not installed."
        exit 1
    fi
done

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if [[ $(echo "$PYTHON_VERSION < 3.8" | bc -l) -eq 1 ]]; then
    echo "Error: Python 3.8+ is required. Found version $PYTHON_VERSION"
    exit 1
fi

# Create necessary directories
mkdir -p uploads data logs frontend/build

# Copy .env file if doesn't exist
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env file from template. Please configure your API keys."
    read -p "Press enter to edit .env file..."
    nano .env
fi

# Build Docker images
echo "Building Docker images..."
docker-compose build

# Initialize database
echo "Initializing database..."
docker-compose run --rm api python database.py

# Start services
echo "Starting services..."
docker-compose up -d

# Wait for services to be ready
echo "Waiting for services to be ready..."
sleep 10

# Check service health
echo "Checking service health..."
if curl -sf http://localhost:8000/health > /dev/null; then
    echo "✓ API is healthy"
else
    echo "✗ API is not responding. Check logs with: docker-compose logs api"
fi

if curl -sf http://localhost:3000 > /dev/null; then
    echo "✓ Frontend is healthy"
else
    echo "✗ Frontend is not responding. Check logs with: docker-compose logs frontend"
fi

echo
echo "REloadAI setup complete!"
echo "- API: http://localhost:8000"
echo "- Frontend: http://localhost:3000"
echo "- API Documentation: http://localhost:8000/docs"
echo
echo "To stop services: docker-compose down"
echo "To view logs: docker-compose logs -f"
echo "To rebuild after changes: docker-compose up -d --build"