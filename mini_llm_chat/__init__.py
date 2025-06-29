"""Interactive chat interface with rate limiting."""

__version__ = "0.1.0"
__author__ = "Sean Rawlins"
__description__ = "A secure interactive REPL with GPT-4 and rate limiting"

from .chat import run_chat_repl
from .cli import main
from .rate_limiter import SimpleRateLimiter

__all__ = ["run_chat_repl", "SimpleRateLimiter", "main"]
