#!/usr/bin/env python3
"""
Database Setup Script

This script helps set up the Mini LLM Chat database and initial configuration.
It can be run independently or as part of the installation process.
"""

import os
import sys
import subprocess
from pathlib import Path

def check_postgresql():
    """Check if PostgreSQL is available."""
    try:
        result = subprocess.run(['psql', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[OK] PostgreSQL found: {result.stdout.strip()}")
            return True
        else:
            print("[ERROR] PostgreSQL not found")
            return False
    except FileNotFoundError:
        print("[ERROR] PostgreSQL not found in PATH")
        return False

def check_redis():
    """Check if Redis is available."""
    try:
        result = subprocess.run(['redis-cli', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[OK] Redis found: {result.stdout.strip()}")
            return True
        else:
            print("[WARNING] Redis not found (optional for caching)")
            return False
    except FileNotFoundError:
        print("[WARNING] Redis not found in PATH (optional for caching)")
        return False

def create_database():
    """Create the PostgreSQL database."""
    db_name = "mini_llm_chat"
    
    print(f"[SETUP] Creating database '{db_name}'...")
    
    try:
        # Try to create database
        result = subprocess.run([
            'createdb', db_name
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[OK] Database '{db_name}' created successfully")
            return True
        elif "already exists" in result.stderr:
            print(f"[INFO] Database '{db_name}' already exists")
            return True
        else:
            print(f"[ERROR] Failed to create database: {result.stderr}")
            return False
            
    except FileNotFoundError:
        print("[ERROR] createdb command not found. Please install PostgreSQL.")
        return False

def setup_environment():
    """Set up environment variables."""
    env_file = Path(".env")
    
    if env_file.exists():
        print("[INFO] .env file already exists")
        return True
    
    print("[SETUP] Creating .env file...")
    
    env_content = """# Mini LLM Chat Environment Variables

# Database Configuration
DATABASE_URL=postgresql://localhost:5432/mini_llm_chat

# JWT Secret (change this in production!)
JWT_SECRET_KEY=your-secret-key-change-in-production

# OpenAI API Key (get from https://platform.openai.com/api-keys)
# OPENAI_API_KEY=sk-your-api-key-here

# Rate Limiting
RATE_LIMIT_MAX_CALLS=3
RATE_LIMIT_TIME_WINDOW=60

# Logging
LOG_LEVEL=INFO

# Redis Configuration (optional)
# REDIS_HOST=localhost
# REDIS_PORT=6379
# REDIS_PASSWORD=
"""
    
    try:
        with open(env_file, 'w') as f:
            f.write(env_content)
        print("[OK] .env file created")
        print("[WARNING] Please edit .env file to add your OpenAI API key and change the JWT secret")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to create .env file: {e}")
        return False

def install_dependencies():
    """Install Python dependencies."""
    print("[SETUP] Installing Python dependencies...")
    
    try:
        result = subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-e', '.'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[OK] Dependencies installed successfully")
            return True
        else:
            print(f"[ERROR] Failed to install dependencies: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Error installing dependencies: {e}")
        return False

def initialize_database():
    """Initialize database tables."""
    print("[SETUP] Initializing database tables...")
    
    try:
        result = subprocess.run([
            sys.executable, '-m', 'mini_llm_chat.cli', '--init-db'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[OK] Database tables initialized")
            return True
        else:
            print(f"[ERROR] Failed to initialize database: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Error initializing database: {e}")
        return False

def setup_admin_user():
    """Set up admin user."""
    print("[SETUP] Setting up admin user...")
    
    try:
        result = subprocess.run([
            sys.executable, '-m', 'mini_llm_chat.cli', '--setup-admin'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[OK] Admin user setup completed")
            return True
        else:
            print(f"[ERROR] Failed to setup admin user: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Error setting up admin user: {e}")
        return False

def main():
    """Main setup function."""
    print("Mini LLM Chat Database Setup")
    print("=" * 40)
    
    # Check prerequisites
    print("\nChecking prerequisites...")
    pg_available = check_postgresql()
    redis_available = check_redis()
    
    if not pg_available:
        print("\n[ERROR] PostgreSQL is required but not found.")
        print("Please install PostgreSQL and try again.")
        print("Installation instructions:")
        print("  Ubuntu/Debian: sudo apt-get install postgresql postgresql-contrib")
        print("  macOS: brew install postgresql")
        print("  Windows: Download from https://www.postgresql.org/download/")
        sys.exit(1)
    
    # Setup steps
    steps = [
        ("Creating database", create_database),
        ("Setting up environment", setup_environment),
        ("Installing dependencies", install_dependencies),
        ("Initializing database", initialize_database),
        ("Setting up admin user", setup_admin_user),
    ]
    
    print(f"\n[SETUP] Running setup steps...")
    
    for step_name, step_func in steps:
        print(f"\n{step_name}...")
        if not step_func():
            print(f"\n[ERROR] Setup failed at step: {step_name}")
            sys.exit(1)
    
    print("\n[SUCCESS] Setup completed successfully!")
    print("\nNext steps:")
    print("1. Edit .env file to add your OpenAI API key")
    print("2. Change the JWT_SECRET_KEY in .env file")
    print("3. Run: mini-llm-chat --api-key YOUR_API_KEY")
    print("\nFor help: mini-llm-chat --help")

if __name__ == "__main__":
    main()
