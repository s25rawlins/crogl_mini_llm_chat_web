# Mini LLM Chat - Installation Guide

## Overview

This guide provides step-by-step instructions for installing, configuring, and running the Mini LLM Chat application. The application is a secure, enterprise-ready interactive REPL for chatting with Large Language Models.

## System Requirements

- Python 3.8 or higher
- OpenAI API Key
- PostgreSQL (optional, for full features)
- Redis (optional, for caching)
- 512MB RAM minimum
- 1GB disk space

## Prerequisites Installation

### Ubuntu/Debian

```bash
# Update package list
sudo apt-get update

# Install Python and pip
sudo apt-get install python3 python3-pip python3-venv

# Install PostgreSQL (optional)
sudo apt-get install postgresql postgresql-contrib

# Install Redis (optional)
sudo apt-get install redis-server

# Start services
sudo systemctl start postgresql
sudo systemctl start redis-server
sudo systemctl enable postgresql
sudo systemctl enable redis-server
```

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python

# Install PostgreSQL (optional)
brew install postgresql

# Install Redis (optional)
brew install redis

# Start services
brew services start postgresql
brew services start redis
```

### Windows

1. **Install Python**:
   - Download Python 3.8+ from https://python.org/downloads/
   - Run installer and check "Add Python to PATH"

2. **Install PostgreSQL** (optional):
   - Download from https://www.postgresql.org/download/windows/
   - Run installer and note the password you set

3. **Install Redis** (optional):
   - Download from https://github.com/microsoftarchive/redis/releases
   - Or use Windows Subsystem for Linux (WSL)

## Installation Methods

### Method 1: From Source (Recommended for Development)

1. **Clone the repository**:
```bash
git clone <repository-url>
cd mini_llm_chat
```

2. **Create virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Install the package in development mode**:
```bash
pip install -e .
```

5. **Verify installation**:
```bash
mini-llm-chat --version
```

### Method 2: Using pip (Production)

1. **Create virtual environment**:
```bash
python3 -m venv mini-llm-chat-env
source mini-llm-chat-env/bin/activate  # On Windows: mini-llm-chat-env\Scripts\activate
```

2. **Install from PyPI**:
```bash
pip install mini-llm-chat
```

3. **Verify installation**:
```bash
mini-llm-chat --version
```

### Method 3: Using Docker

1. **Create Dockerfile** (if not provided):
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN pip install -e .

CMD ["mini-llm-chat"]
```

2. **Build and run**:
```bash
docker build -t mini-llm-chat .
docker run -it --env-file .env mini-llm-chat
```

## Configuration

### Environment Variables Setup

1. **Copy example environment file**:
```bash
cp .env.example .env
```

2. **Edit the .env file**:
```bash
# Required
OPENAI_API_KEY=sk-your-api-key-here

# Database (optional)
DATABASE_URL=postgresql://username:password@localhost:5432/mini_llm_chat

# Security
JWT_SECRET_KEY=your-secret-key-change-in-production

# Rate Limiting
RATE_LIMIT_MAX_CALLS=3
RATE_LIMIT_TIME_WINDOW=60

# Logging
LOG_LEVEL=INFO

# Redis (optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
```

### Database Setup (PostgreSQL)

1. **Create database and user**:
```bash
sudo -u postgres psql
```

```sql
CREATE DATABASE mini_llm_chat;
CREATE USER mini_llm_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE mini_llm_chat TO mini_llm_user;
\q
```

2. **Update DATABASE_URL in .env**:
```bash
DATABASE_URL=postgresql://mini_llm_user:secure_password@localhost:5432/mini_llm_chat
```

3. **Initialize database**:
```bash
mini-llm-chat --init-db
```

4. **Create admin user**:
```bash
mini-llm-chat --setup-admin
```

### Redis Setup (Optional)

1. **Configure Redis** (if needed):
```bash
sudo nano /etc/redis/redis.conf
```

2. **Set password** (recommended):
```
requirepass your_redis_password
```

3. **Restart Redis**:
```bash
sudo systemctl restart redis-server
```

4. **Update .env file**:
```bash
REDIS_PASSWORD=your_redis_password
```

## Running the Application

### Basic Usage

1. **Start the application**:
```bash
mini-llm-chat
```

2. **With specific options**:
```bash
mini-llm-chat --api-key sk-your-key --max-calls 5 --time-window 60
```

3. **Using environment variables**:
```bash
export OPENAI_API_KEY=sk-your-api-key-here
mini-llm-chat
```

### Database Backend Options

1. **Auto-detect (default)**:
```bash
mini-llm-chat --db-backend auto
```

2. **Force PostgreSQL**:
```bash
mini-llm-chat --db-backend postgresql
```

3. **Use in-memory only**:
```bash
mini-llm-chat --db-backend memory
```

4. **Custom database URL**:
```bash
mini-llm-chat --database-url postgresql://user:pass@host:5432/dbname
```

## Packaging and Distribution

### Creating a Package

1. **Build wheel package**:
```bash
python -m build
```

2. **Package contents will be in**:
```
dist/
├── mini_llm_chat-0.1.0-py3-none-any.whl
└── mini_llm_chat-0.1.0.tar.gz
```

### Installing from Package

1. **Install wheel file**:
```bash
pip install dist/mini_llm_chat-0.1.0-py3-none-any.whl
```

2. **Install tar.gz file**:
```bash
pip install dist/mini_llm_chat-0.1.0.tar.gz
```

### Creating Distribution Archive

1. **Create distribution directory**:
```bash
mkdir mini_llm_chat_distribution
```

2. **Copy necessary files**:
```bash
cp dist/mini_llm_chat-0.1.0-py3-none-any.whl mini_llm_chat_distribution/
cp dist/mini_llm_chat-0.1.0.tar.gz mini_llm_chat_distribution/
cp README.md mini_llm_chat_distribution/
cp INSTALLATION_GUIDE.md mini_llm_chat_distribution/
cp requirements.txt mini_llm_chat_distribution/
cp .env.example mini_llm_chat_distribution/
```

3. **Create archive**:
```bash
tar -czf mini_llm_chat_distribution.tar.gz mini_llm_chat_distribution/
```

## Testing the Installation

### Basic Functionality Test

1. **Test CLI help**:
```bash
mini-llm-chat --help
```

2. **Test version**:
```bash
mini-llm-chat --version
```

3. **Test database initialization**:
```bash
mini-llm-chat --init-db
```

4. **Test admin setup**:
```bash
mini-llm-chat --setup-admin
```

### Running Test Suite

1. **Install test dependencies**:
```bash
pip install pytest pytest-cov
```

2. **Run tests**:
```bash
python -m pytest mini_llm_chat/tests/
```

3. **Run with coverage**:
```bash
python -m pytest --cov=mini_llm_chat mini_llm_chat/tests/
```

## Troubleshooting

### Common Installation Issues

1. **Python version too old**:
```bash
python3 --version  # Should be 3.8+
```

2. **pip not found**:
```bash
python3 -m ensurepip --upgrade
```

3. **Permission errors**:
```bash
pip install --user mini-llm-chat
```

4. **Virtual environment issues**:
```bash
python3 -m venv --clear venv
source venv/bin/activate
pip install --upgrade pip
```

### Database Connection Issues

1. **PostgreSQL not running**:
```bash
sudo systemctl status postgresql
sudo systemctl start postgresql
```

2. **Connection refused**:
```bash
# Check if PostgreSQL is listening
sudo netstat -tlnp | grep 5432

# Check PostgreSQL configuration
sudo nano /etc/postgresql/*/main/postgresql.conf
```

3. **Authentication failed**:
```bash
# Reset PostgreSQL password
sudo -u postgres psql
\password postgres
```

### Redis Connection Issues

1. **Redis not running**:
```bash
sudo systemctl status redis-server
sudo systemctl start redis-server
```

2. **Connection refused**:
```bash
redis-cli ping
```

3. **Authentication failed**:
```bash
# Check Redis configuration
sudo nano /etc/redis/redis.conf
```

### API Key Issues

1. **Invalid API key format**:
   - Ensure key starts with 'sk-'
   - Check for extra spaces or characters

2. **API key not working**:
```bash
# Test API key
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

## Performance Optimization

### Database Optimization

1. **PostgreSQL tuning**:
```sql
-- Increase shared_buffers
shared_buffers = 256MB

-- Increase work_mem
work_mem = 4MB

-- Enable query optimization
random_page_cost = 1.1
```

2. **Connection pooling**:
```bash
# Install pgbouncer
sudo apt-get install pgbouncer
```

### Redis Optimization

1. **Memory optimization**:
```
# In redis.conf
maxmemory 256mb
maxmemory-policy allkeys-lru
```

2. **Persistence settings**:
```
# Disable persistence for cache-only usage
save ""
appendonly no
```

## Security Hardening

### Production Security

1. **Generate secure secrets**:
```bash
# Generate JWT secret
openssl rand -base64 32

# Generate database password
openssl rand -base64 24
```

2. **File permissions**:
```bash
chmod 600 .env
chmod 755 mini_llm_chat/
```

3. **Firewall configuration**:
```bash
# Allow only necessary ports
sudo ufw allow 22    # SSH
sudo ufw allow 5432  # PostgreSQL (if remote)
sudo ufw enable
```

### Database Security

1. **PostgreSQL security**:
```sql
-- Create restricted user
CREATE USER app_user WITH PASSWORD 'secure_password';
GRANT CONNECT ON DATABASE mini_llm_chat TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
```

2. **SSL configuration**:
```
# In postgresql.conf
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
```

## Monitoring and Maintenance

### Log Management

1. **Configure log rotation**:
```bash
sudo nano /etc/logrotate.d/mini-llm-chat
```

```
/var/log/mini-llm-chat/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 mini-llm-chat mini-llm-chat
}
```

### Health Checks

1. **Create health check script**:
```bash
#!/bin/bash
# health_check.sh

# Check if application is running
if pgrep -f "mini-llm-chat" > /dev/null; then
    echo "Application is running"
else
    echo "Application is not running"
    exit 1
fi

# Check database connection
if mini-llm-chat --db-backend postgresql --help > /dev/null 2>&1; then
    echo "Database connection OK"
else
    echo "Database connection failed"
    exit 1
fi
```

### Backup and Recovery

1. **Database backup**:
```bash
# Create backup
pg_dump mini_llm_chat > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore backup
psql mini_llm_chat < backup_20231201_120000.sql
```

2. **Configuration backup**:
```bash
# Backup configuration
tar -czf config_backup_$(date +%Y%m%d).tar.gz .env alembic.ini
```

## Support and Resources

### Getting Help

1. **Check logs**:
```bash
mini-llm-chat --log-level DEBUG
```

2. **Run diagnostics**:
```bash
mini-llm-chat --help
mini-llm-chat --version
```

3. **Test components**:
```bash
# Test database
mini-llm-chat --init-db

# Test authentication
mini-llm-chat --setup-admin
```

### Documentation

- README.md: Project overview and quick start
- API documentation: Available in source code
- Configuration examples: In .env.example


This installation guide provides comprehensive instructions for setting up Mini LLM Chat in various environments. Follow the appropriate sections based on your specific needs and environment.
