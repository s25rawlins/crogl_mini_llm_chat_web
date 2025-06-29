"""Command-line interface for Mini LLM Chat."""

import argparse
import logging
import os
import sys

from dotenv import load_dotenv

from mini_llm_chat.auth import setup_initial_admin
from mini_llm_chat.chat import run_chat_repl, validate_api_key
from mini_llm_chat.database_manager import DatabaseConnectionError, initialize_database
from mini_llm_chat.logging_hygiene import setup_secure_logging


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="mini-llm-chat",
        description=(
            "Mini LLM Chat - A secure interactive REPL for chatting with Large Language Models. "
            "Features streaming responses, rate limiting, and conversation history."
        ),
        epilog=(
            "Examples:\n"
            "  %(prog)s --api-key sk-your-key-here\n"
            "  %(prog)s --max-calls 10 --time-window 300\n"
            "  %(prog)s --log-level DEBUG\n"
            "\n"
            "Environment Variables:\n"
            "  OPENAI_API_KEY - Your OpenAI API key\n"
            "  RATE_LIMIT_MAX_CALLS - Maximum API calls per time window\n"
            "  RATE_LIMIT_TIME_WINDOW - Time window in seconds for rate limiting"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # API Key argument - most important configuration
    parser.add_argument(
        "--api-key",
        type=str,
        default=os.getenv("OPENAI_API_KEY"),
        help=(
            "Your OpenAI API key (required). "
            "Can also be set via OPENAI_API_KEY environment variable. "
            "Get your key from https://platform.openai.com/api-keys"
        ),
        metavar="KEY",
    )

    # Rate limiting configuration
    parser.add_argument(
        "--max-calls",
        type=int,
        default=int(os.getenv("RATE_LIMIT_MAX_CALLS", "3")),
        help=(
            "Maximum number of API calls allowed per time window. "
            "Default is 3. Can be set via RATE_LIMIT_MAX_CALLS environment variable. "
            "Lower values help manage costs and prevent abuse."
        ),
        metavar="N",
    )

    parser.add_argument(
        "--time-window",
        type=int,
        default=int(os.getenv("RATE_LIMIT_TIME_WINDOW", "60")),
        help=(
            "Time window in seconds for rate limiting. "
            "Default is 60 seconds. Can be set via RATE_LIMIT_TIME_WINDOW environment variable. "
            "This defines the sliding window for counting API calls."
        ),
        metavar="SECONDS",
    )

    # Logging configuration
    parser.add_argument(
        "--log-level",
        type=str,
        default=os.getenv("LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help=(
            "Set the logging level. Default is INFO. "
            "DEBUG provides detailed information for troubleshooting. "
            "Can be set via LOG_LEVEL environment variable."
        ),
    )

    # Optional configuration file support (for future enhancement)
    parser.add_argument(
        "--config",
        type=str,
        help=(
            "Path to configuration file (not implemented yet). "
            "Reserved for future use to support configuration files."
        ),
        metavar="FILE",
    )

    # Database backend configuration
    parser.add_argument(
        "--db-backend",
        type=str,
        default=os.getenv("DB_BACKEND", "auto"),
        choices=["postgresql", "memory", "auto"],
        help=(
            "Database backend to use. Default is 'auto' which tries PostgreSQL first, "
            "then falls back to in-memory. 'postgresql' requires a PostgreSQL database, "
            "'memory' uses in-memory storage (no persistence). "
            "Can be set via DB_BACKEND environment variable."
        ),
    )

    parser.add_argument(
        "--fallback-to-memory",
        action="store_true",
        help=(
            "Automatically fallback to in-memory database if PostgreSQL fails. "
            "Only applies when --db-backend is 'postgresql' or 'auto'."
        ),
    )

    parser.add_argument(
        "--database-url",
        type=str,
        default=os.getenv("DATABASE_URL"),
        help=(
            "PostgreSQL database URL. Can also be set via DATABASE_URL environment variable. "
            "Format: postgresql://user:password@host:port/database"
        ),
        metavar="URL",
    )

    # Database and setup options
    parser.add_argument(
        "--setup-admin",
        action="store_true",
        help=(
            "Set up initial admin user and exit. "
            "Use this for first-time setup to create an admin account."
        ),
    )

    parser.add_argument(
        "--init-db",
        action="store_true",
        help=(
            "Initialize database tables and exit. "
            "Use this to set up the database schema."
        ),
    )

    # Version information
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    return parser


def setup_logging(log_level: str) -> None:
    """Configure application logging."""
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    log_format = "%(asctime)s [%(levelname)8s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        datefmt=date_format,
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    logger = logging.getLogger(__name__)
    logger.debug(f"Logging configured at {log_level} level")

    # Reduce third-party library noise
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def validate_args(args: argparse.Namespace) -> bool:
    """Validate CLI arguments."""
    logger = logging.getLogger(__name__)
    valid = True

    if not args.api_key:
        print("Error: OpenAI API key is required.")
        print("   Use --api-key argument or set OPENAI_API_KEY environment variable.")
        print("   Get your API key from: https://platform.openai.com/api-keys")
        valid = False
    elif not validate_api_key(args.api_key):
        print("Error: Invalid API key format.")
        print("   OpenAI API keys should start with 'sk-' and be at least 20 characters long.")
        valid = False
    else:
        logger.debug("API key format validation passed")

    if args.max_calls <= 0:
        print(f"Error: max-calls must be positive (got {args.max_calls})")
        valid = False
    elif args.max_calls > 100:
        print(f"Warning: max-calls is very high ({args.max_calls}). This could result in high API costs.")
        logger.warning(f"High max_calls value: {args.max_calls}")

    if args.time_window <= 0:
        print(f"Error: time-window must be positive (got {args.time_window})")
        valid = False
    elif args.time_window < 10:
        print(f"Warning: time-window is very short ({args.time_window}s). This might be too restrictive.")
        logger.warning(f"Short time_window value: {args.time_window}")

    if valid and args.max_calls > 0 and args.time_window > 0:
        rate_per_minute = (args.max_calls / args.time_window) * 60
        if rate_per_minute > 30:
            print(f"Warning: High API call rate ({rate_per_minute:.1f} calls/minute). This could result in significant costs.")
            logger.warning(f"High API call rate: {rate_per_minute:.1f} calls/minute")

    if args.config:
        if not os.path.exists(args.config):
            print(f"Error: Configuration file not found: {args.config}")
            valid = False
        else:
            print("Warning: Configuration file support is not implemented yet.")

    return valid


def show_startup_info(args: argparse.Namespace) -> None:
    """Display startup configuration without revealing sensitive data."""
    print("Starting Mini LLM Chat...")
    print(f"   Rate Limit: {args.max_calls} calls per {args.time_window} seconds")
    print(f"   Log Level: {args.log_level}")

    if args.api_key:
        key_preview = (
            args.api_key[:7] + "..." + args.api_key[-4:]
            if len(args.api_key) > 11
            else "***"
        )
        print(f"   API Key: {key_preview}")

    print()


def main() -> None:
    """CLI entry point."""
    try:
        load_dotenv()
        parser = create_parser()
        args = parser.parse_args()

        setup_secure_logging()
        setup_logging(args.log_level)
        logger = logging.getLogger(__name__)

        logger.info("Mini LLM Chat CLI starting...")
        logger.debug(f"Arguments: max_calls={args.max_calls}, time_window={args.time_window}, log_level={args.log_level}")

        if args.init_db:
            print("Initializing database...")
            try:
                backend = initialize_database(
                    backend_type=args.db_backend,
                    fallback_to_memory=args.fallback_to_memory,
                    database_url=args.database_url,
                    interactive_fallback=True,
                )
                backend.init_db()
                print("Database initialized successfully!")
                logger.info("Database initialized via CLI command")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Database initialization failed: {e}")
                print(f"Database initialization failed: {e}")
                sys.exit(1)

        if args.setup_admin:
            print("Setting up admin user...")
            try:
                backend = initialize_database(
                    backend_type=args.db_backend,
                    fallback_to_memory=args.fallback_to_memory,
                    database_url=args.database_url,
                    interactive_fallback=True,
                )
                backend.init_db()
                success = setup_initial_admin()
                if success:
                    print("Admin user setup completed!")
                    logger.info("Admin user setup completed via CLI command")
                else:
                    print("Admin user setup skipped (user already exists)")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Admin setup failed: {e}")
                print(f"Admin setup failed: {e}")
                sys.exit(1)

        if not args.api_key:
            print("Error: API key is required.")
            print("   Use --api-key argument or set OPENAI_API_KEY environment variable.")
            print("   Get your API key from: https://platform.openai.com/api-keys")
            print("\n   For setup operations, use:")
            print("   --init-db        Initialize database")
            print("   --setup-admin    Create admin user")
            sys.exit(1)

        if not validate_args(args):
            logger.error("Argument validation failed")
            sys.exit(1)

        try:
            print("Initializing database...")
            backend = initialize_database(
                backend_type=args.db_backend,
                fallback_to_memory=args.fallback_to_memory,
                database_url=args.database_url,
                interactive_fallback=True,
            )
            backend_info = backend.get_backend_info()
            logger.info(f"Database backend: {backend_info['name']} ({backend_info['type']})")

            # Auto-setup admin for PostgreSQL if needed
            if backend_info["type"] == "postgresql" and hasattr(backend, "has_admin_users"):
                if not backend.has_admin_users():
                    print("No admin users found. Setting up initial admin user...")
                    try:
                        success = setup_initial_admin()
                        if success:
                            print("Admin user created successfully!")
                            logger.info("Admin user created during startup")
                        else:
                            print("Admin user setup skipped (user already exists)")
                    except Exception as e:
                        logger.error(f"Admin user setup failed: {e}")
                        print(f"Admin user setup failed: {e}")
                        print("You can create an admin user later with: --setup-admin")

            if backend_info["type"] == "memory":
                print(f"Database: {backend_info['name']} (In-Memory)")
                if not backend.supports_persistence():
                    print("Note: Using in-memory storage - data will not persist between sessions")
            else:
                print(f"Database: {backend_info['name']}")

        except DatabaseConnectionError as e:
            logger.error(f"Database initialization failed: {e}")
            error_msg = str(e).lower()
            
            if "not installed" in error_msg:
                print("\n" + "="*60)
                print("PostgreSQL Installation Required")
                print("="*60)
                print(str(e))
                print("\nTo resolve this issue:")
                print("1. Install PostgreSQL on your system")
                print("2. Run the application again")
                print("3. Or use in-memory mode: --db-backend memory")
                print("="*60)
            elif "not running" in error_msg or "could not be started" in error_msg:
                print("\n" + "="*60)
                print("PostgreSQL Service Issue")
                print("="*60)
                print(str(e))
                print("\nTo resolve this issue:")
                print("1. Start PostgreSQL service manually:")
                print("   - Linux: sudo systemctl start postgresql")
                print("   - macOS: brew services start postgresql")
                print("   - Windows: net start postgresql")
                print("2. Run the application again")
                print("3. Or use in-memory mode: --db-backend memory")
                print("="*60)
            elif "does not exist" in error_msg and "could not be created" in error_msg:
                print("\n" + "="*60)
                print("PostgreSQL Database Issue")
                print("="*60)
                print(str(e))
                print("\nTo resolve this issue:")
                print("1. Create the database manually:")
                print("   createdb mini_llm_chat")
                print("2. Check database permissions")
                print("3. Verify your DATABASE_URL is correct")
                print("4. Or use in-memory mode: --db-backend memory")
                print("="*60)
            elif "cannot connect" in error_msg:
                print("\n" + "="*60)
                print("PostgreSQL Connection Issue")
                print("="*60)
                print(str(e))
                print("\nTo resolve this issue:")
                print("1. Check your DATABASE_URL is correct")
                print("2. Verify PostgreSQL is accepting connections")
                print("3. Check authentication credentials")
                print("4. Or use in-memory mode: --db-backend memory")
                print("="*60)
            else:
                print(f"\nDatabase initialization failed: {e}")
                print("\nYou can try using in-memory mode instead:")
                print("  mini-llm-chat --db-backend memory")
            
            sys.exit(1)

        show_startup_info(args)
        logger.info("Launching chat REPL...")
        run_chat_repl(args.api_key, args.max_calls, args.time_window)
        logger.info("Chat REPL ended normally")

    except KeyboardInterrupt:
        print("\nGoodbye! (Interrupted during startup)")
        sys.exit(0)
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.exception("Unexpected error during startup")
        print(f"An unexpected error occurred: {e}")
        print("Please check your configuration and try again.")
        sys.exit(2)


# Entry point when run as a script
if __name__ == "__main__":
    main()
