from setuptools import setup, find_packages

setup(
    name="encrypted-information-retrieval",
    version="1.0.0",
    description="Encrypted Information Retrieval for Financial Services",
    author="Encrypted IR Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "pycryptodome>=3.19.0",
        "tenseal>=0.3.14",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
        ],
    },
)
