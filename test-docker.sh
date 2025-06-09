#!/bin/bash

# Test Docker Build and Run Script for Mini LLM Chat
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="mini-llm-chat:test"
CONTAINER_NAME="mini-llm-chat-test"
TEST_PORT="8080"

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    print_status "Cleaning up..."
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
}

# Trap to cleanup on exit
trap cleanup EXIT

main() {
    print_status "Testing Docker build and run for Mini LLM Chat..."
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    # Build the Docker image
    print_status "Building Docker image..."
    docker build -t $IMAGE_NAME .
    
    if [ $? -eq 0 ]; then
        print_status "Docker image built successfully!"
    else
        print_error "Docker build failed!"
        exit 1
    fi
    
    # Check if .env file exists
    if [ ! -f ".env" ]; then
        print_warning "No .env file found. Creating a minimal one for testing..."
        cat > .env.test << EOF
OPENAI_API_KEY=test-key-for-docker-build
JWT_SECRET_KEY=test-secret-key-change-in-production
DEBUG=true
EOF
        ENV_FILE=".env.test"
    else
        ENV_FILE=".env"
        print_status "Using existing .env file"
    fi
    
    # Run the container
    print_status "Starting container on port $TEST_PORT..."
    docker run -d \
        --name $CONTAINER_NAME \
        --env-file $ENV_FILE \
        -p $TEST_PORT:8080 \
        $IMAGE_NAME
    
    # Wait a moment for the container to start
    print_status "Waiting for container to start..."
    sleep 10
    
    # Test the health endpoint
    print_status "Testing health endpoint..."
    if curl -f http://localhost:$TEST_PORT/api/health >/dev/null 2>&1; then
        print_status "Health check passed!"
        
        # Show the health response
        echo ""
        echo "Health endpoint response:"
        curl -s http://localhost:$TEST_PORT/api/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:$TEST_PORT/api/health
        echo ""
        
    else
        print_error "Health check failed!"
        print_status "Container logs:"
        docker logs $CONTAINER_NAME
        exit 1
    fi
    
    # Show container status
    print_status "Container is running successfully!"
    print_status "Access the application at: http://localhost:$TEST_PORT"
    print_status "API documentation at: http://localhost:$TEST_PORT/api/docs"
    print_status "Health check at: http://localhost:$TEST_PORT/api/health"
    
    echo ""
    print_warning "Container will be stopped and removed when this script exits."
    print_warning "Press Ctrl+C to stop the test and cleanup."
    
    # Keep the script running so user can test
    echo ""
    read -p "Press Enter to stop the container and cleanup..."
    
    # Cleanup will happen automatically due to trap
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            TEST_PORT="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --port PORT     Port to run the test container on (default: 8080)"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main
