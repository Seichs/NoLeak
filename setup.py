#!/usr/bin/env python3
"""Setup configuration for NoLeak secret scanner."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="noleak",
    version="1.0.0",
    author="NoLeak Team",
    author_email="security@noleak.dev",
    description="A DevSecOps tool for scanning hardcoded secrets in source code",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Seichs/NoLeak",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "noleak=noleak.cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "noleak": ["rules/*.yaml"],
    },
)
