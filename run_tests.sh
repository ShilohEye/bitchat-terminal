#!/bin/bash

# Test runner script for bitchat-terminal Noise protocol tests

set -e  # Exit on error

echo "🚀 Running Noise protocol tests in Docker..."

# Get absolute path to avoid Docker volume name issues
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default to all tests if no argument provided
TEST_FILTER=${1:-""}

echo "📝 Test filter: $TEST_FILTER"
echo "📁 Working directory: $CURRENT_DIR"

# Check if Docker is running
echo "🐳 Checking Docker..."
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "🔧 Building test container and running tests..."

# Build and run using the optimized test Dockerfile
docker build -f Dockerfile.test -t bitchat-test "$CURRENT_DIR"
docker run --rm bitchat-test cargo test $TEST_FILTER

echo "✅ Tests completed successfully!"