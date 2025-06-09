from setuptools import setup, find_packages

setup(
    name="mini-llm-chat",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["openai"],
    entry_points={
        "console_scripts": [
            "mini-llm-chat=mini_llm_chat.cli:main"
        ],
    },
    description="A secure interactive REPL with GPT-4 and rate limiting.",
    author="Your Name",
    python_requires=">=3.8",
)
