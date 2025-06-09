"""
Web Interface Module

This module provides a FastAPI-based web interface for the Mini LLM Chat application.
It serves as an alternative to the CLI interface, offering the same functionality
through a modern web API with real-time chat capabilities.
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Local imports
from mini_llm_chat.database_manager import DatabaseConnectionError, initialize_database
from mini_llm_chat.logging_hygiene import setup_secure_logging
from mini_llm_chat.web_api.exceptions import setup_exception_handlers
from mini_llm_chat.web_api.routes import auth, chat, users
from mini_llm_chat.web_api.websocket.chat_handler import setup_websocket_routes

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager for startup and shutdown events.
    
    This handles database initialization and cleanup during app lifecycle.
    """
    # Startup
    logger.info("Starting Mini LLM Chat Web Interface...")
    
    try:
        # Initialize database backend
        backend_type = os.getenv("DB_BACKEND", "auto")
        database_url = os.getenv("DATABASE_URL")
        
        backend = initialize_database(
            backend_type=backend_type,
            fallback_to_memory=True,  # Always fallback for web interface
            database_url=database_url,
            interactive_fallback=False,  # No interactive prompts for web
        )
        
        backend_info = backend.get_backend_info()
        logger.info(f"Database backend initialized: {backend_info['name']}")
        
        # Initialize database tables/structures
        backend.init_db()
        logger.info("Database tables/structures initialized")
        
        # Store backend info in app state
        app.state.db_backend_info = backend_info
        
    except DatabaseConnectionError as e:
        logger.error(f"Database initialization failed: {e}")
        # For web interface, we'll continue with in-memory backend
        logger.info("Continuing with in-memory backend for web interface")
        
        backend = initialize_database(
            backend_type="memory",
            fallback_to_memory=False,
            database_url=None,
            interactive_fallback=False,
        )
        
        # Initialize database tables/structures for fallback backend too
        backend.init_db()
        logger.info("Fallback database tables/structures initialized")
        
        app.state.db_backend_info = backend.get_backend_info()
    
    yield
    
    # Shutdown
    logger.info("Shutting down Mini LLM Chat Web Interface...")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        FastAPI: Configured FastAPI application instance
    """
    # Set up secure logging
    setup_secure_logging()
    
    app = FastAPI(
        title="Mini LLM Chat Web API",
        description="A secure web interface for chatting with Large Language Models",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    
    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
    
    # Set up exception handlers
    setup_exception_handlers(app)
    
    # Include API routes
    app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
    app.include_router(chat.router, prefix="/api/chat", tags=["Chat"])
    app.include_router(users.router, prefix="/api/users", tags=["Users"])
    
    # Set up WebSocket routes
    setup_websocket_routes(app)
    
    # Serve static files (React frontend)
    frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend", "build")
    if os.path.exists(frontend_dir):
        app.mount("/static", StaticFiles(directory=os.path.join(frontend_dir, "static")), name="static")
        app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    
    # Health check endpoint
    @app.get("/api/health")
    async def health_check():
        """Health check endpoint for monitoring."""
        backend_info = getattr(app.state, 'db_backend_info', {'name': 'Unknown'})
        return {
            "status": "healthy",
            "service": "Mini LLM Chat Web API",
            "version": "0.1.0",
            "database": backend_info.get('name', 'Unknown')
        }
    
    return app


def main():
    """
    Main entry point for the web application.
    
    This function starts the FastAPI server with appropriate configuration
    for development or production environments.
    """
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Get configuration from environment
    # Cloud Run uses PORT environment variable
    host = os.getenv("WEB_HOST", "0.0.0.0")
    port = int(os.getenv("PORT", os.getenv("WEB_PORT", "8000")))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    
    # Validate required environment variables
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable is required")
        print("Set your OpenAI API key in the .env file or environment variables")
        return
    
    logger.info(f"Starting web server on {host}:{port}")
    logger.info(f"Debug mode: {debug}")
    
    # Create the FastAPI app
    app = create_app()
    
    # Run the server
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=debug,
        log_level="debug" if debug else "info",
        access_log=True,
    )


if __name__ == "__main__":
    main()
