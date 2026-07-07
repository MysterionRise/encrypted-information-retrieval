from setuptools import setup, find_packages

setup(
    name="encrypted-information-retrieval",
    version="1.0.0",
    description="Production-oriented prototype for regulated AI/RAG retrieval",
    author="Encrypted IR Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.11",
    install_requires=[
        "cryptography>=41.0.0",
        "pycryptodome>=3.19.0",
        "prometheus-client>=0.17.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "pydantic>=2.0.0",
        "httpx>=0.24.0",
        "PyJWT[crypto]>=2.8.0",
        "SQLAlchemy>=2.0.0",
        "psycopg[binary]>=3.1.0",
        "alembic>=1.13.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
        ],
        "research": [
            "numpy>=1.24.0",
            "tenseal>=0.3.14",
            "pqcrypto>=0.4.0",
        ],
        "aws": [
            "boto3>=1.28.0",
        ],
    },
)
