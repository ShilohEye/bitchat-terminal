#!/bin/bash

# Build script for bitchat-terminal Docker container
set -e

echo "🔧 Building bitchat-terminal Docker image..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Build the Docker image
echo "📦 Building Docker image..."
docker build -t bitchat-terminal:latest .

# Show the built image
echo "✅ Build complete!"
docker images | grep bitchat-terminal

echo ""
echo "🚀 To run the container:"
echo "   docker-compose up"
echo ""
echo "🔍 To run with debug output:"
echo "   docker-compose run --rm bitchat-terminal -d"
echo ""
echo "🧪 To test the build:"
echo "   docker run --rm bitchat-terminal:latest --help"