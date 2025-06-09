"""
Nox configuration for mini_llm_chat project.

This file defines test sessions for running tests, linting, and other
quality assurance tasks across multiple Python versions.
"""

import nox


# Define supported Python versions
PYTHON_VERSIONS = ["3.8", "3.9", "3.10", "3.11", "3.12"]


@nox.session(python=PYTHON_VERSIONS)
def tests(session):
    """Run the test suite with pytest."""
    # Install the package in development mode
    session.install("-e", ".")
    
    # Install test dependencies
    session.install("pytest", "pytest-cov")
    
    # Run tests with coverage
    session.run(
        "pytest",
        "mini_llm_chat/tests/",
        "--cov=mini_llm_chat",
        "--cov-report=term-missing",
        "--cov-report=html",
        "-v"
    )


@nox.session(python="3.12")
def lint(session):
    """Run linting tools."""
    # Install linting tools
    session.install("flake8", "black", "isort", "mypy")
    
    # Install the package for type checking
    session.install("-e", ".")
    
    # Run black (code formatting)
    session.run("black", "--check", "--diff", "mini_llm_chat/")
    
    # Run isort (import sorting)
    session.run("isort", "--check-only", "--diff", "mini_llm_chat/")
    
    # Run flake8 (style and error checking)
    session.run("flake8", "mini_llm_chat/")
    
    # Run mypy (type checking)
    session.run("mypy", "mini_llm_chat/")


@nox.session(python="3.12")
def format(session):
    """Format code with black and isort."""
    # Install formatting tools
    session.install("black", "isort")
    
    # Run black (code formatting)
    session.run("black", "mini_llm_chat/")
    
    # Run isort (import sorting)
    session.run("isort", "mini_llm_chat/")


@nox.session(python="3.12")
def type_check(session):
    """Run type checking with mypy."""
    # Install mypy and the package
    session.install("mypy")
    session.install("-e", ".")
    
    # Run mypy
    session.run("mypy", "mini_llm_chat/")


@nox.session(python="3.12")
def safety(session):
    """Check for security vulnerabilities in dependencies."""
    # Install safety
    session.install("safety")
    
    # Install the package to get its dependencies
    session.install("-e", ".")
    
    # Run safety check
    session.run("safety", "check")


@nox.session(python="3.12")
def docs(session):
    """Build documentation."""
    # Install documentation dependencies
    session.install("sphinx", "sphinx-rtd-theme")
    session.install("-e", ".")
    
    # Build docs (if docs directory exists)
    session.run("sphinx-build", "-b", "html", "docs/", "docs/_build/html/")


# Default session when running `nox` without arguments
nox.options.sessions = ["tests"]
