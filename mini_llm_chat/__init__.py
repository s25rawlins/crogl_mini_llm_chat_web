"""
Mini LLM Chat Package

A command-line REPL (Read-Eval-Print Loop) interface for interacting with Large Language Models.
This package provides a secure, rate-limited chat interface with streaming responses.

The package structure:
- cli.py: Command-line interface and argument parsing
- chat.py: Core chat functionality and REPL loop
- rate_limiter.py: Rate limiting implementation to manage API usage
- __main__.py: Entry point for running as a module (python -m mini_llm_chat)

Key Features:
- Streaming AI responses for better user experience
- Rate limiting to prevent API abuse and manage costs
- Input validation and security measures
- Configurable logging for debugging
- Conversation history management
"""

# Package metadata
__version__ = "0.1.0"
__author__ = "Sean Rawlins"
__description__ = "A secure interactive REPL with GPT-4 and rate limiting"

# Export main components for easier importing
from .chat import run_chat_repl
from .cli import main
from .rate_limiter import SimpleRateLimiter

__all__ = ["run_chat_repl", "SimpleRateLimiter", "main"]
