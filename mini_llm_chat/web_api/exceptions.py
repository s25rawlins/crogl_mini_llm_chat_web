"""
Exception Handlers Module

This module defines custom exception handlers for the FastAPI application,
providing consistent error responses and proper HTTP status codes.
"""

import logging
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from mini_llm_chat.auth import AuthenticationError, AuthorizationError
from mini_llm_chat.database_manager import DatabaseConnectionError
from mini_llm_chat.rate_limiter import RateLimitExceeded

logger = logging.getLogger(__name__)


class WebAPIException(Exception):
    """Base exception for Web API errors."""
    
    def __init__(self, message: str, status_code: int = 500, details: Dict[str, Any] = None):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class ValidationError(WebAPIException):
    """Raised when request validation fails."""
    
    def __init__(self, message: str, details: Dict[str, Any] = None):
        super().__init__(message, status.HTTP_422_UNPROCESSABLE_ENTITY, details)


class NotFoundError(WebAPIException):
    """Raised when a requested resource is not found."""
    
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, status.HTTP_404_NOT_FOUND)


class ConflictError(WebAPIException):
    """Raised when a request conflicts with current state."""
    
    def __init__(self, message: str, details: Dict[str, Any] = None):
        super().__init__(message, status.HTTP_409_CONFLICT, details)


async def web_api_exception_handler(request: Request, exc: WebAPIException) -> JSONResponse:
    """Handle custom Web API exceptions."""
    logger.warning(f"Web API exception: {exc.message} (Status: {exc.status_code})")
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.message,
            "details": exc.details,
            "status_code": exc.status_code
        }
    )


async def authentication_exception_handler(request: Request, exc: AuthenticationError) -> JSONResponse:
    """Handle authentication errors."""
    logger.warning(f"Authentication error: {str(exc)}")
    
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": True,
            "message": "Authentication failed",
            "details": {"reason": str(exc)},
            "status_code": status.HTTP_401_UNAUTHORIZED
        }
    )


async def authorization_exception_handler(request: Request, exc: AuthorizationError) -> JSONResponse:
    """Handle authorization errors."""
    logger.warning(f"Authorization error: {str(exc)}")
    
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "error": True,
            "message": "Access forbidden",
            "details": {"reason": str(exc)},
            "status_code": status.HTTP_403_FORBIDDEN
        }
    )


async def rate_limit_exception_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Handle rate limiting errors."""
    logger.warning(f"Rate limit exceeded: {str(exc)}")
    
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "error": True,
            "message": "Rate limit exceeded",
            "details": {
                "reason": str(exc),
                "retry_after": getattr(exc, 'retry_after', None)
            },
            "status_code": status.HTTP_429_TOO_MANY_REQUESTS
        }
    )


async def database_exception_handler(request: Request, exc: DatabaseConnectionError) -> JSONResponse:
    """Handle database connection errors."""
    logger.error(f"Database error: {str(exc)}")
    
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "error": True,
            "message": "Database service unavailable",
            "details": {"reason": "Database connection failed"},
            "status_code": status.HTTP_503_SERVICE_UNAVAILABLE
        }
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle FastAPI HTTP exceptions."""
    logger.warning(f"HTTP exception: {exc.detail} (Status: {exc.status_code})")
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "status_code": exc.status_code
        }
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions."""
    logger.exception(f"Unexpected error: {str(exc)}")
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": True,
            "message": "Internal server error",
            "details": {"type": type(exc).__name__},
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    )


def setup_exception_handlers(app: FastAPI) -> None:
    """
    Set up all exception handlers for the FastAPI application.
    
    Args:
        app (FastAPI): The FastAPI application instance
    """
    # Custom exception handlers
    app.add_exception_handler(WebAPIException, web_api_exception_handler)
    app.add_exception_handler(AuthenticationError, authentication_exception_handler)
    app.add_exception_handler(AuthorizationError, authorization_exception_handler)
    app.add_exception_handler(RateLimitExceeded, rate_limit_exception_handler)
    app.add_exception_handler(DatabaseConnectionError, database_exception_handler)
    
    # FastAPI built-in exception handlers
    app.add_exception_handler(HTTPException, http_exception_handler)
    
    # Catch-all exception handler
    app.add_exception_handler(Exception, general_exception_handler)
    
    logger.info("Exception handlers configured")
