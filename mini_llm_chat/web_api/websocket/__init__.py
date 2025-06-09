"""
WebSocket Package

This package contains WebSocket handlers for real-time functionality
in the Mini LLM Chat web interface.
"""

from .chat_handler import setup_websocket_routes

__all__ = ["setup_websocket_routes"]
