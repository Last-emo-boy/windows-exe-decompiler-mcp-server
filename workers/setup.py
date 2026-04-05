#!/usr/bin/env python3
"""
Setup script for Rikune - Static Worker
"""

from setuptools import setup, find_packages

setup(
    name="mcp-decompiler-worker",
    version="0.1.0",
    description="Static analysis worker for Rikune",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=[
        "pefile==2024.8.26",
        "lief==0.17.5",
        "yara-python>=4.5.0,<5.0.0",
        "flare-floss>=2.3.0,<3.0.0",
        "dnfile>=0.15.0,<1.0.0",
    ],
)
