#!/bin/bash

# Mini LLM Chat - Google Cloud Run Deployment Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID=${GOOGLE_CLOUD_PROJECT:-""}
REGION=${REGION:-"us-central1"}
SERVICE_NAME=${SERVICE_NAME:-"mini-llm-chat"}
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

# Functions
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    print_status "Checking requirements..."
    
    # Check if gcloud is installed
    if ! command -v gcloud &> /dev/null; then
        print_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install it first."
        exit 1
    fi
    
    # Check if project ID is set
    if [ -z "$PROJECT_ID" ]; then
        PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
        if [ -z "$PROJECT_ID" ]; then
            print_error "Google Cloud Project ID is not set."
            print_error "Set it with: gcloud config set project YOUR_PROJECT_ID"
            exit 1
        fi
    fi
    
    print_status "Using project: $PROJECT_ID"
    print_status "Using region: $REGION"
    print_status "Service name: $SERVICE_NAME"
}

enable_apis() {
    print_status "Enabling required Google Cloud APIs..."
    
    gcloud services enable cloudbuild.googleapis.com \
        run.googleapis.com \
        containerregistry.googleapis.com \
        --project=$PROJECT_ID
}

build_and_push() {
    print_status "Building and pushing Docker image..."
    
    # Build the image
    docker build -t $IMAGE_NAME:latest .
    
    # Configure Docker to use gcloud as a credential helper
    gcloud auth configure-docker --quiet
    
    # Push the image
    docker push $IMAGE_NAME:latest
    
    print_status "Image pushed successfully: $IMAGE_NAME:latest"
}

deploy_to_cloud_run() {
    print_status "Deploying to Cloud Run..."
    
    # Check if .env file exists for environment variables
    ENV_VARS=""
    if [ -f ".env" ]; then
        print_warning "Found .env file. Remember to set environment variables in Cloud Run console for production."
        print_warning "This script will only set basic configuration."
    fi
    
    # Deploy to Cloud Run
    gcloud run deploy $SERVICE_NAME \
        --image=$IMAGE_NAME:latest \
        --platform=managed \
        --region=$REGION \
        --allow-unauthenticated \
        --port=8080 \
        --memory=1Gi \
        --cpu=1 \
        --max-instances=10 \
        --timeout=300 \
        --set-env-vars="PORT=8080" \
        --project=$PROJECT_ID
    
    # Get the service URL
    SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
        --platform=managed \
        --region=$REGION \
        --format="value(status.url)" \
        --project=$PROJECT_ID)
    
    print_status "Deployment completed successfully!"
    print_status "Service URL: $SERVICE_URL"
    print_status "Health check: $SERVICE_URL/api/health"
}

setup_environment_variables() {
    print_warning "IMPORTANT: Set the following environment variables in Cloud Run console:"
    echo ""
    echo "Required:"
    echo "  OPENAI_API_KEY=your_openai_api_key"
    echo "  JWT_SECRET_KEY=your_jwt_secret_key"
    echo ""
    echo "Optional (for full functionality):"
    echo "  DATABASE_URL=postgresql://user:pass@host:port/db"
    echo "  GOOGLE_CLIENT_ID=your_google_client_id"
    echo "  GOOGLE_CLIENT_SECRET=your_google_client_secret"
    echo "  REDIS_URL=redis://host:port"
    echo ""
    echo "You can set these in the Google Cloud Console:"
    echo "https://console.cloud.google.com/run/detail/$REGION/$SERVICE_NAME/variables?project=$PROJECT_ID"
}

main() {
    print_status "Starting deployment to Google Cloud Run..."
    
    check_requirements
    enable_apis
    build_and_push
    deploy_to_cloud_run
    setup_environment_variables
    
    print_status "Deployment process completed!"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --project)
            PROJECT_ID="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --service-name)
            SERVICE_NAME="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --project PROJECT_ID     Google Cloud Project ID"
            echo "  --region REGION          Deployment region (default: us-central1)"
            echo "  --service-name NAME      Cloud Run service name (default: mini-llm-chat)"
            echo "  --help                   Show this help message"
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
