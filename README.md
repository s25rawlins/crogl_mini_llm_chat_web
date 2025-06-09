# Mini LLM Chat

A secure, enterprise-ready interactive REPL for chatting with Large Language Models. Features user authentication, role-based access control, database persistence, caching, and comprehensive security measures.

## Features

### Security & Authentication
- Token-based Authentication: JWT tokens for secure user sessions
- Role-Based Access Control: Admin and user roles with different permissions
- Logging Hygiene: Automatic scrubbing of sensitive data from logs
- Enhanced System Prompt: Stricter AI behavior controls and prompt injection protection
- Audit Logging: Security events tracking for compliance

### Performance & Reliability
- Flexible Database Backends: PostgreSQL for full features or in-memory for lightweight usage
- Redis Caching: Optional caching for improved performance and reduced API calls
- Token Truncation: Automatic conversation history management to stay within model limits
- Rate Limiting: Configurable API call limits to manage costs
- Automatic Fallback: Seamless fallback to in-memory mode if PostgreSQL is unavailable

### User Experience
- Streaming Responses: Real-time AI response display
- Interactive Authentication: Secure login flow with token management
- Conversation Management: Persistent chat history across sessions
- Status Monitoring: Real-time system status and usage information

## Prerequisites

- Python 3.8+
- OpenAI API Key
- PostgreSQL (optional, for full features)
- Redis (optional, for caching)

### Database Options

Mini LLM Chat supports two database backends:

#### PostgreSQL (Full Features)
- Persistent user accounts and authentication
- Conversation history across sessions
- Role-based access control
- Admin user management
- Database migrations

#### In-Memory (Lightweight)
- Basic chat functionality
- Session-based authentication
- Rate limiting and caching
- No data persistence between sessions
- No user management
- No conversation history

The application automatically detects available backends and can fallback gracefully.

## Installation

### Method 1: From Source (Recommended)

1. Clone the repository:
```bash
git clone <repository-url>
cd mini_llm_chat
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install the package:
```bash
pip install -e .
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env and add your OpenAI API key
```

5. Initialize database (optional, for PostgreSQL):
```bash
mini-llm-chat --init-db --setup-admin
```

### Method 2: Using pip

```bash
pip install mini-llm-chat
```

### Method 3: Using Docker

```bash
# Build the image
docker build -t mini-llm-chat .

# Run with environment variables
docker run -it --env-file .env mini-llm-chat
```

## Quick Start

1. Set your OpenAI API key:
```bash
export OPENAI_API_KEY=sk-your-api-key-here
```

2. Run the application:
```bash
mini-llm-chat
```

3. For first-time setup with PostgreSQL:
```bash
mini-llm-chat --init-db --setup-admin
```

## Usage

### Basic Usage
```bash
# Start with API key
mini-llm-chat --api-key sk-your-key-here

# Use environment variables
export OPENAI_API_KEY=sk-your-key-here
mini-llm-chat
```

### Database Backend Selection
```bash
# Use PostgreSQL (default, auto-detects and falls back to memory)
mini-llm-chat --db-backend auto

# Force PostgreSQL only
mini-llm-chat --db-backend postgresql

# Use in-memory database only
mini-llm-chat --db-backend memory

# Custom database URL
mini-llm-chat --database-url postgresql://user:pass@host:5432/dbname
```

### Advanced Configuration
```bash
# Custom rate limiting
mini-llm-chat --max-calls 10 --time-window 300

# Debug logging
mini-llm-chat --log-level DEBUG

# All options
mini-llm-chat --api-key sk-xxx --max-calls 5 --time-window 60 --log-level INFO
```

### Setup Commands
```bash
# Initialize database tables
mini-llm-chat --init-db

# Create admin user
mini-llm-chat --setup-admin

# Show help
mini-llm-chat --help
```

### Chat Commands
Once in the chat interface:
- `help` - Show available commands
- `status` - Display system status
- `clear` - Clear conversation history
- `exit` or `quit` - Exit the chat

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Required
OPENAI_API_KEY=sk-your-api-key-here
DATABASE_URL=postgresql://localhost:5432/mini_llm_chat

# Security
JWT_SECRET_KEY=your-secret-key-change-in-production

# Rate Limiting
RATE_LIMIT_MAX_CALLS=3
RATE_LIMIT_TIME_WINDOW=60

# Logging
LOG_LEVEL=INFO

# Redis (Optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
```

### Installing Prerequisites

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib redis-server
```

#### macOS
```bash
brew install postgresql redis
```

#### Windows
- Download PostgreSQL from https://www.postgresql.org/download/
- Download Redis from https://redis.io/download

## Development

### Running Tests
```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
python -m pytest

# Run with coverage
python -m pytest --cov=mini_llm_chat
```

### Code Quality
```bash
# Format code
black mini_llm_chat/

# Lint code
flake8 mini_llm_chat/

# Type checking
mypy mini_llm_chat/
```

### Database Migrations
```bash
# Create migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Downgrade
alembic downgrade -1
```

## Architecture

### Components

- **CLI Module** (`cli.py`): Command-line interface and argument parsing
- **Chat Module** (`chat.py`): Core chat functionality with streaming responses
- **Authentication** (`auth.py`): User authentication and session management
- **Database** (`database.py`): PostgreSQL models and operations
- **Cache** (`cache.py`): Redis caching for performance optimization
- **Logging Hygiene** (`logging_hygiene.py`): Sensitive data filtering
- **Rate Limiter** (`rate_limiter.py`): API call rate limiting

### Security Features

1. **Authentication Flow**
   - JWT token-based authentication
   - Secure password hashing with bcrypt
   - Session management with configurable expiration

2. **Role-Based Access Control**
   - Admin users: Full system access
   - Regular users: Chat access only
   - Permission checking for sensitive operations

3. **Logging Security**
   - Automatic scrubbing of API keys, passwords, tokens
   - Configurable sensitive data patterns
   - Audit logging for security events

4. **Input Validation**
   - Message length limits
   - API key format validation
   - SQL injection prevention through ORM

## Security Considerations

### Production Deployment

1. **Change Default Secrets**
```bash
# Generate secure JWT secret
JWT_SECRET_KEY=$(openssl rand -base64 32)
```

2. **Database Security**
- Use strong database passwords
- Enable SSL connections
- Restrict database access by IP

3. **Environment Security**
- Store secrets in secure environment variables
- Use proper file permissions for `.env` files
- Rotate API keys regularly

4. **Network Security**
- Use HTTPS in production
- Implement proper firewall rules
- Consider VPN for database access

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -h localhost -U postgres -d mini_llm_chat
```

2. **Authentication Errors**
```bash
# Reset admin user
mini-llm-chat --setup-admin

# Check JWT secret is set
echo $JWT_SECRET_KEY
```

3. **API Key Issues**
```bash
# Verify API key format
echo $OPENAI_API_KEY | grep "^sk-"

# Test API key
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

4. **Cache Issues**
```bash
# Check Redis connection
redis-cli ping

# Clear cache
redis-cli flushall
```