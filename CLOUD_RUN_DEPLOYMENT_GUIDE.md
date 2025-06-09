# Google Cloud Run Deployment Guide

This guide will help you deploy the Mini LLM Chat application to Google Cloud Run.

## Prerequisites

1. **Google Cloud Account**: You need a Google Cloud account with billing enabled
2. **Google Cloud CLI**: Install the `gcloud` CLI tool
3. **Docker**: Install Docker on your local machine
4. **Project Setup**: Create or select a Google Cloud project

## Quick Start

### 1. Set up Google Cloud CLI

```bash
# Install gcloud CLI (if not already installed)
# Follow instructions at: https://cloud.google.com/sdk/docs/install

# Authenticate with Google Cloud
gcloud auth login

# Set your project ID
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable cloudbuild.googleapis.com run.googleapis.com containerregistry.googleapis.com
```

### 2. Deploy using the automated script

```bash
# Make the script executable (if not already done)
chmod +x deploy.sh

# Deploy to Cloud Run
./deploy.sh

# Or with custom options
./deploy.sh --project YOUR_PROJECT_ID --region us-west1 --service-name my-chat-app
```

### 3. Set Environment Variables

After deployment, you **must** set the following environment variables in the Cloud Run console:

#### Required Variables:
- `OPENAI_API_KEY`: Your OpenAI API key
- `JWT_SECRET_KEY`: A secure secret key for JWT tokens

#### Optional Variables (for full functionality):
- `DATABASE_URL`: PostgreSQL connection string (e.g., `postgresql://user:pass@host:port/db`)
- `GOOGLE_CLIENT_ID`: For Google OAuth authentication
- `GOOGLE_CLIENT_SECRET`: For Google OAuth authentication
- `REDIS_URL`: Redis connection string for rate limiting
- `CORS_ORIGINS`: Comma-separated list of allowed origins

## Manual Deployment

If you prefer to deploy manually:

### 1. Build and Push Docker Image

```bash
# Set your project ID
export PROJECT_ID=your-project-id

# Build the Docker image
docker build -t gcr.io/$PROJECT_ID/mini-llm-chat:latest .

# Configure Docker to use gcloud as credential helper
gcloud auth configure-docker

# Push the image
docker push gcr.io/$PROJECT_ID/mini-llm-chat:latest
```

### 2. Deploy to Cloud Run

```bash
gcloud run deploy mini-llm-chat \
  --image=gcr.io/$PROJECT_ID/mini-llm-chat:latest \
  --platform=managed \
  --region=us-central1 \
  --allow-unauthenticated \
  --port=8080 \
  --memory=1Gi \
  --cpu=1 \
  --max-instances=10 \
  --timeout=300 \
  --set-env-vars="PORT=8080"
```

## Using Cloud Build (CI/CD)

For automated deployments, you can use the included `cloudbuild.yaml`:

### 1. Connect your repository to Cloud Build

```bash
# Enable Cloud Build API
gcloud services enable cloudbuild.googleapis.com

# Create a trigger (replace with your repo details)
gcloud builds triggers create github \
  --repo-name=your-repo-name \
  --repo-owner=your-github-username \
  --branch-pattern="^main$" \
  --build-config=cloudbuild.yaml
```

### 2. Push to trigger deployment

Every push to the main branch will automatically build and deploy your application.

## Environment Configuration

### Setting Environment Variables in Cloud Run

1. Go to the [Cloud Run Console](https://console.cloud.google.com/run)
2. Click on your service
3. Click "Edit & Deploy New Revision"
4. Go to the "Variables & Secrets" tab
5. Add your environment variables

### Required Environment Variables

```bash
# OpenAI API Key (Required)
OPENAI_API_KEY=sk-your-openai-api-key

# JWT Secret (Required)
JWT_SECRET_KEY=your-very-secure-secret-key-change-this

# Database (Optional - will use in-memory if not provided)
DATABASE_URL=postgresql://username:password@host:port/database

# Google OAuth (Optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Redis for rate limiting (Optional)
REDIS_URL=redis://host:port

# CORS configuration (Optional)
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

## Database Setup

### Option 1: Cloud SQL (Recommended for Production)

1. Create a Cloud SQL PostgreSQL instance:
```bash
gcloud sql instances create mini-llm-chat-db \
  --database-version=POSTGRES_14 \
  --tier=db-f1-micro \
  --region=us-central1
```

2. Create a database and user:
```bash
gcloud sql databases create mini_llm_chat --instance=mini-llm-chat-db
gcloud sql users create chatuser --instance=mini-llm-chat-db --password=secure-password
```

3. Get the connection string and set it as `DATABASE_URL`

### Option 2: In-Memory Database (Development Only)

If you don't set `DATABASE_URL`, the application will use an in-memory database. This is fine for testing but data will be lost when the container restarts.

## Security Considerations

1. **Environment Variables**: Never commit sensitive environment variables to your repository
2. **IAM Permissions**: Use least-privilege access for your Cloud Run service
3. **HTTPS**: Cloud Run automatically provides HTTPS endpoints
4. **Authentication**: Consider enabling Cloud Run authentication for production

## Monitoring and Logging

### View Logs
```bash
gcloud logs read "resource.type=cloud_run_revision AND resource.labels.service_name=mini-llm-chat" --limit=50
```

### Monitor Performance
- Use the Cloud Run console to monitor CPU, memory, and request metrics
- Set up alerting for error rates and response times

## Troubleshooting

### Common Issues

1. **Build Failures**: Check that all dependencies are properly specified in `requirements.txt`
2. **Memory Issues**: Increase memory allocation if the app runs out of memory
3. **Timeout Issues**: Increase the timeout if requests take longer than 300 seconds
4. **Environment Variables**: Ensure all required environment variables are set

### Debug Commands

```bash
# Check service status
gcloud run services describe mini-llm-chat --region=us-central1

# View recent logs
gcloud logs read "resource.type=cloud_run_revision" --limit=20

# Test the health endpoint
curl https://your-service-url/api/health
```

## Cost Optimization

1. **CPU Allocation**: Use the minimum CPU allocation that meets your performance needs
2. **Memory**: Start with 1Gi and adjust based on usage
3. **Max Instances**: Set appropriate limits to control costs
4. **Request Timeout**: Use shorter timeouts for better resource utilization

## Scaling Configuration

Cloud Run automatically scales based on incoming requests. You can configure:

- **Min Instances**: Keep warm instances (costs more but reduces cold starts)
- **Max Instances**: Limit maximum concurrent instances
- **Concurrency**: Number of requests per instance (default: 80)

```bash
# Update scaling configuration
gcloud run services update mini-llm-chat \
  --min-instances=1 \
  --max-instances=10 \
  --concurrency=80 \
  --region=us-central1
```

## Custom Domain

To use a custom domain:

1. Verify domain ownership in Google Cloud Console
2. Map the domain to your Cloud Run service
3. Update DNS records as instructed

```bash
gcloud run domain-mappings create \
  --service=mini-llm-chat \
  --domain=chat.yourdomain.com \
  --region=us-central1
```

## Support

If you encounter issues:

1. Check the [Cloud Run documentation](https://cloud.google.com/run/docs)
2. Review the application logs for error messages
3. Ensure all environment variables are properly configured
4. Verify that your Google Cloud project has the necessary APIs enabled

## Next Steps

After successful deployment:

1. Set up monitoring and alerting
2. Configure a custom domain (optional)
3. Set up a CI/CD pipeline for automated deployments
4. Consider setting up a staging environment
5. Implement backup strategies for your database
