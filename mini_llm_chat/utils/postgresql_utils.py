"""
PostgreSQL System Utilities

This module provides utilities for checking PostgreSQL installation,
service status, and performing system-level database operations.
"""

import logging
import os
import platform
import shutil
import subprocess
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class PostgreSQLSystemError(Exception):
    """Raised when PostgreSQL system operations fail."""
    pass


def is_postgresql_installed() -> bool:
    """
    Check if PostgreSQL is installed on the system.
    
    Returns:
        bool: True if PostgreSQL is installed, False otherwise
    """
    try:
        # Check for psql command
        psql_path = shutil.which("psql")
        if psql_path:
            logger.debug(f"Found psql at: {psql_path}")
            return True
            
        # Check for pg_config command
        pg_config_path = shutil.which("pg_config")
        if pg_config_path:
            logger.debug(f"Found pg_config at: {pg_config_path}")
            return True
            
        logger.debug("PostgreSQL commands not found in PATH")
        return False
        
    except Exception as e:
        logger.warning(f"Error checking PostgreSQL installation: {e}")
        return False


def get_postgresql_version() -> Optional[str]:
    """
    Get PostgreSQL version if installed.
    
    Returns:
        Optional[str]: PostgreSQL version string or None if not available
    """
    try:
        # Try psql first
        if shutil.which("psql"):
            result = subprocess.run(
                ["psql", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version_line = result.stdout.strip()
                logger.debug(f"PostgreSQL version: {version_line}")
                return version_line
                
        # Try pg_config as fallback
        if shutil.which("pg_config"):
            result = subprocess.run(
                ["pg_config", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version_line = result.stdout.strip()
                logger.debug(f"PostgreSQL version from pg_config: {version_line}")
                return version_line
                
    except Exception as e:
        logger.warning(f"Error getting PostgreSQL version: {e}")
        
    return None


def is_postgresql_service_running() -> bool:
    """
    Check if PostgreSQL service is running.
    
    Returns:
        bool: True if PostgreSQL service is running, False otherwise
    """
    try:
        # Try pg_isready first (most reliable)
        if shutil.which("pg_isready"):
            result = subprocess.run(
                ["pg_isready"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.debug("PostgreSQL is ready (pg_isready)")
                return True
            else:
                logger.debug(f"pg_isready returned: {result.returncode}")
        
        # Platform-specific service checks
        system = platform.system().lower()
        
        if system == "linux":
            return _check_postgresql_service_linux()
        elif system == "darwin":  # macOS
            return _check_postgresql_service_macos()
        elif system == "windows":
            return _check_postgresql_service_windows()
        else:
            logger.warning(f"Unsupported platform for service check: {system}")
            return False
            
    except Exception as e:
        logger.warning(f"Error checking PostgreSQL service status: {e}")
        return False


def _check_postgresql_service_linux() -> bool:
    """Check PostgreSQL service on Linux systems."""
    try:
        # Try systemctl first
        if shutil.which("systemctl"):
            result = subprocess.run(
                ["systemctl", "is-active", "postgresql"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip() == "active":
                logger.debug("PostgreSQL service is active (systemctl)")
                return True
                
        # Try service command
        if shutil.which("service"):
            result = subprocess.run(
                ["service", "postgresql", "status"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.debug("PostgreSQL service is running (service)")
                return True
                
    except Exception as e:
        logger.debug(f"Linux service check failed: {e}")
        
    return False


def _check_postgresql_service_macos() -> bool:
    """Check PostgreSQL service on macOS systems."""
    try:
        # Check for Homebrew PostgreSQL
        if shutil.which("brew"):
            result = subprocess.run(
                ["brew", "services", "list"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                if "postgresql" in output and "started" in output:
                    logger.debug("PostgreSQL service is running (Homebrew)")
                    return True
                    
        # Check for launchctl
        if shutil.which("launchctl"):
            result = subprocess.run(
                ["launchctl", "list"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                if "postgresql" in output or "postgres" in output:
                    logger.debug("PostgreSQL service found in launchctl")
                    return True
                    
    except Exception as e:
        logger.debug(f"macOS service check failed: {e}")
        
    return False


def _check_postgresql_service_windows() -> bool:
    """Check PostgreSQL service on Windows systems."""
    try:
        # Use sc command to check service status
        result = subprocess.run(
            ["sc", "query", "postgresql"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            output = result.stdout.upper()
            if "RUNNING" in output:
                logger.debug("PostgreSQL service is running (Windows)")
                return True
                
    except Exception as e:
        logger.debug(f"Windows service check failed: {e}")
        
    return False


def start_postgresql_service() -> bool:
    """
    Attempt to start PostgreSQL service.
    
    Returns:
        bool: True if service was started successfully, False otherwise
    """
    if is_postgresql_service_running():
        logger.debug("PostgreSQL service is already running")
        return True
        
    try:
        system = platform.system().lower()
        
        if system == "linux":
            return _start_postgresql_service_linux()
        elif system == "darwin":  # macOS
            return _start_postgresql_service_macos()
        elif system == "windows":
            return _start_postgresql_service_windows()
        else:
            logger.warning(f"Unsupported platform for service start: {system}")
            return False
            
    except Exception as e:
        logger.error(f"Error starting PostgreSQL service: {e}")
        return False


def _start_postgresql_service_linux() -> bool:
    """Start PostgreSQL service on Linux systems."""
    try:
        # Try systemctl first
        if shutil.which("systemctl"):
            result = subprocess.run(
                ["sudo", "systemctl", "start", "postgresql"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                # Wait a moment and check if it's running
                time.sleep(2)
                if is_postgresql_service_running():
                    logger.info("PostgreSQL service started successfully (systemctl)")
                    return True
                    
        # Try service command
        if shutil.which("service"):
            result = subprocess.run(
                ["sudo", "service", "postgresql", "start"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                time.sleep(2)
                if is_postgresql_service_running():
                    logger.info("PostgreSQL service started successfully (service)")
                    return True
                    
    except Exception as e:
        logger.debug(f"Linux service start failed: {e}")
        
    return False


def _start_postgresql_service_macos() -> bool:
    """Start PostgreSQL service on macOS systems."""
    try:
        # Try Homebrew first
        if shutil.which("brew"):
            result = subprocess.run(
                ["brew", "services", "start", "postgresql"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                time.sleep(2)
                if is_postgresql_service_running():
                    logger.info("PostgreSQL service started successfully (Homebrew)")
                    return True
                    
    except Exception as e:
        logger.debug(f"macOS service start failed: {e}")
        
    return False


def _start_postgresql_service_windows() -> bool:
    """Start PostgreSQL service on Windows systems."""
    try:
        # Use net start command
        result = subprocess.run(
            ["net", "start", "postgresql"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            time.sleep(2)
            if is_postgresql_service_running():
                logger.info("PostgreSQL service started successfully (Windows)")
                return True
                
    except Exception as e:
        logger.debug(f"Windows service start failed: {e}")
        
    return False


def parse_database_url(database_url: str) -> Dict[str, Optional[str]]:
    """
    Parse a PostgreSQL database URL into components.
    
    Args:
        database_url: PostgreSQL connection URL
        
    Returns:
        Dict with keys: scheme, username, password, host, port, database
    """
    try:
        parsed = urlparse(database_url)
        return {
            "scheme": parsed.scheme,
            "username": parsed.username,
            "password": parsed.password,
            "host": parsed.hostname or "localhost",
            "port": str(parsed.port) if parsed.port else "5432",
            "database": parsed.path.lstrip("/") if parsed.path else None,
        }
    except Exception as e:
        logger.error(f"Error parsing database URL: {e}")
        raise ValueError(f"Invalid database URL: {database_url}")


def database_exists(database_url: str) -> bool:
    """
    Check if a PostgreSQL database exists.
    
    Args:
        database_url: PostgreSQL connection URL
        
    Returns:
        bool: True if database exists, False otherwise
    """
    try:
        import psycopg2
        from psycopg2 import sql
        
        # Parse the URL
        url_parts = parse_database_url(database_url)
        target_db = url_parts["database"]
        
        if not target_db:
            logger.error("No database name specified in URL")
            return False
            
        # Connect to postgres database to check if target database exists
        postgres_url = database_url.replace(f"/{target_db}", "/postgres")
        
        conn = psycopg2.connect(postgres_url)
        conn.autocommit = True
        
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s",
                (target_db,)
            )
            exists = cursor.fetchone() is not None
            
        conn.close()
        logger.debug(f"Database '{target_db}' exists: {exists}")
        return exists
        
    except Exception as e:
        logger.warning(f"Error checking database existence: {e}")
        return False


def create_database(database_url: str) -> bool:
    """
    Create a PostgreSQL database if it doesn't exist.
    
    Args:
        database_url: PostgreSQL connection URL
        
    Returns:
        bool: True if database was created or already exists, False otherwise
    """
    try:
        import psycopg2
        from psycopg2 import sql
        
        # Parse the URL
        url_parts = parse_database_url(database_url)
        target_db = url_parts["database"]
        
        if not target_db:
            logger.error("No database name specified in URL")
            return False
            
        # Check if database already exists
        if database_exists(database_url):
            logger.debug(f"Database '{target_db}' already exists")
            return True
            
        # Connect to postgres database to create target database
        postgres_url = database_url.replace(f"/{target_db}", "/postgres")
        
        conn = psycopg2.connect(postgres_url)
        conn.autocommit = True
        
        with conn.cursor() as cursor:
            # Create database (using sql.Identifier for safety)
            cursor.execute(
                sql.SQL("CREATE DATABASE {}").format(
                    sql.Identifier(target_db)
                )
            )
            
        conn.close()
        logger.info(f"Database '{target_db}' created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        return False


def get_postgresql_status() -> Dict[str, any]:
    """
    Get comprehensive PostgreSQL system status.
    
    Returns:
        Dict with status information
    """
    status = {
        "installed": False,
        "version": None,
        "service_running": False,
        "can_connect": False,
        "database_exists": False,
        "error": None
    }
    
    try:
        # Check installation
        status["installed"] = is_postgresql_installed()
        if status["installed"]:
            status["version"] = get_postgresql_version()
            
        # Check service
        status["service_running"] = is_postgresql_service_running()
        
        return status
        
    except Exception as e:
        status["error"] = str(e)
        logger.error(f"Error getting PostgreSQL status: {e}")
        return status


def ensure_postgresql_ready(database_url: str) -> Tuple[bool, str]:
    """
    Ensure PostgreSQL is ready for use.
    
    This function performs comprehensive checks and attempts to resolve issues:
    1. Check if PostgreSQL is installed
    2. Check if service is running, start if needed
    3. Check if database exists, create if needed
    4. Verify connection works
    
    Args:
        database_url: PostgreSQL connection URL
        
    Returns:
        Tuple[bool, str]: (success, error_message)
    """
    try:
        # Step 1: Check installation
        if not is_postgresql_installed():
            return False, (
                "PostgreSQL is not installed on this system. "
                "Please install PostgreSQL and try again."
            )
            
        logger.info("PostgreSQL installation found")
        
        # Step 2: Check and start service
        if not is_postgresql_service_running():
            logger.info("PostgreSQL service is not running, attempting to start...")
            if not start_postgresql_service():
                return False, (
                    "PostgreSQL service is not running and could not be started. "
                    "Please start PostgreSQL manually and try again."
                )
            logger.info("PostgreSQL service started successfully")
        else:
            logger.debug("PostgreSQL service is already running")
            
        # Step 3: Check and create database
        if not database_exists(database_url):
            logger.info("Target database does not exist, attempting to create...")
            if not create_database(database_url):
                return False, (
                    "Target database does not exist and could not be created. "
                    "Please create the database manually or check permissions."
                )
            logger.info("Database created successfully")
        else:
            logger.debug("Target database already exists")
            
        # Step 4: Test connection
        try:
            import psycopg2
            conn = psycopg2.connect(database_url)
            conn.close()
            logger.info("PostgreSQL connection test successful")
            return True, "PostgreSQL is ready"
            
        except Exception as e:
            return False, f"Cannot connect to PostgreSQL database: {e}"
            
    except Exception as e:
        logger.error(f"Error ensuring PostgreSQL readiness: {e}")
        return False, f"Unexpected error during PostgreSQL setup: {e}"
