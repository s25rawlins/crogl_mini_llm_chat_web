"""
Routes Package

This package contains all the FastAPI route handlers for the web interface,
organized by functionality (auth, chat, users, etc.).
"""

from . import auth, chat, users

__all__ = ["auth", "chat", "users"]
