"""
CafeChameleon Python Package Installer
"""

import os
import re
from setuptools import setup, find_packages

SETUP_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.abspath(os.path.join(SETUP_DIR, ".."))

init_file = os.path.join(REPO_DIR, "cafe_chameleon", "__init__.py")
with open(init_file, encoding="utf-8") as f:
    version = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', f.read()).group(1)

req_file = os.path.join(SETUP_DIR, "requirements.txt")
if os.path.exists(req_file):
    with open(req_file, encoding="utf-8") as f:
        install_requires = [line.strip() for line in f if line.strip() and not line.startswith("#")]
else:
    install_requires = ["scapy>=2.5.0"]

dev_req_file = os.path.join(SETUP_DIR, "requirements-dev.txt")
if os.path.exists(dev_req_file):
    with open(dev_req_file, encoding="utf-8") as f:
        dev_requires = [
            line.strip() for line in f
            if line.strip() and not line.startswith("#") and not line.startswith("-r")
        ]
else:
    dev_requires = ["pytest>=7.0.0"]

setup(
    name="cafe_chameleon",
    version=version,
    description="Layer 2 Captive Portal Security Auditing Framework",
    author="Bimo754",
    url="https://github.com/Bimo754/CafeChameleon",
    package_dir={"": REPO_DIR},
    packages=find_packages(where=REPO_DIR),
    py_modules=["main"],
    install_requires=install_requires,
    extras_require={
        "dev": dev_requires,
    },
    entry_points={
        "console_scripts": [
            "cafechameleon=main:main",
            "cafe-chameleon=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.10",
)
