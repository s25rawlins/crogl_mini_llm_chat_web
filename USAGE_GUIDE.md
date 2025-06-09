# Mini LLM Chat - Installation and Usage Guide

## Installation

### Option 1: Install from Distribution Package (Recommended)

```bash
pip install mini_llm_chat-0.1.0.tar.gz
```

This will install the package and all its dependencies, making the `mini-llm-chat` command available system-wide.

### Option 2: Install from Wheel

```bash
pip install mini_llm_chat-0.1.0-py3-none-any.whl
```

### Option 3: Development Installation

```bash
pip install -e .
```

Use this if you want to modify the source code and have changes reflected immediately.

## Prerequisites

- Python 3.8 or higher
- OpenAI API key (get one from https://platform.openai.com/api-keys)
- Optional: PostgreSQL database for persistent storage

## Basic Usage

### 1. Default Running Option (Recommended for First-Time Users)

```bash
mini-llm-chat --api-key sk-your-openai-api-key-here
```

**What this does:**
- Uses automatic database backend selection (tries PostgreSQL first, falls back to in-memory)
- Sets rate limiting to 3 calls per 60 seconds (safe defaults)
- Uses INFO logging level
- Starts the interactive chat REPL

**When to use:** Perfect for getting started quickly with safe defaults.

### 2. In-Memory Database Backend

```bash
mini-llm-chat --api-key sk-your-key --db-backend memory
```

**What this does:**
- Forces use of in-memory storage (no persistence between sessions)
- Faster startup, no database setup required
- All conversation history is lost when the program exits

**When to use:** 
- Quick testing or temporary usage
- When you don't need conversation history to persist
- When PostgreSQL is not available or desired

### 3. PostgreSQL Database Backend

```bash
mini-llm-chat --api-key sk-your-key --db-backend postgresql --database-url postgresql://user:password@localhost:5432/mini_llm_chat
```

**What this does:**
- Uses PostgreSQL for persistent storage
- Conversation history survives between sessions
- Supports user authentication and advanced features
- Requires a running PostgreSQL database

**When to use:**
- Production usage where data persistence is important
- Multi-user scenarios
- When you need conversation history to persist

### 4. PostgreSQL with Automatic Fallback

```bash
mini-llm-chat --api-key sk-your-key --db-backend postgresql --fallback-to-memory --database-url postgresql://user:password@localhost:5432/mini_llm_chat
```

**What this does:**
- Tries to connect to PostgreSQL first
- Automatically falls back to in-memory storage if PostgreSQL fails
- Provides resilience against database connection issues

**When to use:**
- When you prefer PostgreSQL but want the program to work even if the database is unavailable
- Development environments where database availability might vary

## Advanced Usage Options

### Rate Limiting Configuration

```bash
# Allow 10 calls per 5 minutes (300 seconds)
mini-llm-chat --api-key sk-your-key --max-calls 10 --time-window 300

# Very conservative: 1 call per minute
mini-llm-chat --api-key sk-your-key --max-calls 1 --time-window 60
```

**What this does:**
- Controls how many API calls you can make within a time window
- Helps manage OpenAI API costs
- Prevents accidental high usage

**When to use:**
- When you want stricter cost control
- In shared environments where usage needs to be limited
- For testing with minimal API usage

### Logging Configuration

```bash
# Debug mode - detailed logging
mini-llm-chat --api-key sk-your-key --log-level DEBUG

# Quiet mode - only errors and warnings
mini-llm-chat --api-key sk-your-key --log-level WARNING
```

**What this does:**
- DEBUG: Shows detailed information about API calls, database operations, and internal processes
- INFO: Standard information about program operation (default)
- WARNING: Only warnings and errors
- ERROR: Only errors
- CRITICAL: Only critical errors

**When to use:**
- DEBUG: When troubleshooting issues or understanding program behavior
- WARNING/ERROR: When you want minimal output in scripts or automated usage

### Database Setup Commands

#### Initialize Database Tables

```bash
mini-llm-chat --init-db --db-backend postgresql --database-url postgresql://user:password@localhost:5432/mini_llm_chat
```

**What this does:**
- Creates all necessary database tables and schema
- Sets up the database structure for first-time use
- Exits after initialization (doesn't start chat)

**When to use:**
- First-time setup with PostgreSQL
- After database schema updates
- When setting up the application in a new environment

#### Setup Admin User

```bash
mini-llm-chat --setup-admin --db-backend postgresql --database-url postgresql://user:password@localhost:5432/mini_llm_chat
```

**What this does:**
- Creates an initial admin user account
- Prompts for username and password
- Sets up authentication system
- Exits after setup (doesn't start chat)

**When to use:**
- First-time setup when you need user authentication
- Setting up admin access for multi-user scenarios

## Environment Variables

Instead of command-line arguments, you can use environment variables:

```bash
# Create a .env file or export these variables
export OPENAI_API_KEY=sk-your-openai-api-key-here
export DB_BACKEND=postgresql
export DATABASE_URL=postgresql://user:password@localhost:5432/mini_llm_chat
export RATE_LIMIT_MAX_CALLS=5
export RATE_LIMIT_TIME_WINDOW=120
export LOG_LEVEL=INFO

# Then run with minimal arguments
mini-llm-chat
```

**When to use:**
- Production deployments
- When you don't want to expose sensitive data in command history
- For consistent configuration across multiple runs

## Complete Setup Example

Here's a complete setup workflow for a new installation:

```bash
# 1. Install the package
pip install mini_llm_chat-0.1.0.tar.gz

# 2. Set up environment variables (optional but recommended)
export OPENAI_API_KEY=sk-your-openai-api-key-here
export DATABASE_URL=postgresql://user:password@localhost:5432/mini_llm_chat

# 3. Initialize database (if using PostgreSQL)
mini-llm-chat --init-db --db-backend postgresql

# 4. Set up admin user (if needed)
mini-llm-chat --setup-admin --db-backend postgresql

# 5. Start chatting!
mini-llm-chat --db-backend postgresql
```

## Troubleshooting

### Common Issues

1. **"Error: OpenAI API key is required"**
   - Solution: Provide API key via `--api-key` argument or `OPENAI_API_KEY` environment variable

2. **"Database initialization failed"**
   - Solution: Check PostgreSQL connection, ensure database exists, or use `--fallback-to-memory`

3. **"Invalid API key format"**
   - Solution: Ensure your API key starts with 'sk-' and is the correct length

4. **Rate limit exceeded**
   - Solution: Wait for the time window to reset, or adjust `--max-calls` and `--time-window`

### Getting Help

```bash
# Show all available options
mini-llm-chat --help

# Show version information
mini-llm-chat --version
```

## Security Notes

- Never commit API keys to version control
- Use environment variables for sensitive configuration
- The application includes secure logging that filters out sensitive data
- Rate limiting helps prevent accidental high API usage and costs

## Performance Tips

- Use PostgreSQL backend for better performance with large conversation histories
- Adjust rate limiting based on your usage patterns and budget
- Use appropriate log levels (WARNING or ERROR) in production for better performance
