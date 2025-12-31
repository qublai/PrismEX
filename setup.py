#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @QK

"""Packaging shim for PrismEX.

This project primarily uses `pyproject.toml`, but a minimal `setup.py` is
kept for compatibility with older tooling.

@QK
"""

from setuptools import setup, find_packages
from pathlib import Path

ROOT = Path(__file__).parent
requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()

long_description = ""
readme_md = ROOT / "README.md"
if readme_md.exists():
    long_description = readme_md.read_text(encoding="utf-8")

setup(
    name="prismex",
    version="0.3.1",
    description="PrismEX - static analysis for Portable Executable (PE) files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="PrismEX contributors ",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "prismex": [
            "config/*.json",
            "templates/*.j2",
            "data/signatures/*.json",
            "data/signatures/userdb.txt",
            "data/signatures/yara_plugins/pe/*.yar",
            "data/signatures/yara_plugins/pe/*.yara",
            "data/signatures/yara_plugins/doc/*.yar",
            "data/signatures/yara_plugins/doc/*.yara",
        ]
    },
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7",
            "ruff>=0.4",
            "build>=1.2",
            "twine>=5",
        ],
        "vt": ["virustotal-api"],
        "docs": ["oletools"],
        "sig": ["M2Crypto"],
    },
    entry_points={
        "console_scripts": [
            "prismex=prismex.cli:main",
        ]
        ,
        "prismex.plugins": [
            # Example: "myplugin = mypkg.plugin:prismex_plugin"
        ]
    },
    python_requires=">=3.9",
)
