"""
CafeChameleon Python Package Installer
"""

from setuptools import setup, find_packages

setup(
    name="cafe_chameleon",
    version="2.0.0",
    description="Layer 2 Captive Portal Security Auditing Framework",
    author="Bimo754",
    url="https://github.com/Bimo754/CafeChameleon",
    packages=find_packages(),
    py_modules=["main"],
    install_requires=[
        "scapy>=2.5.0",
    ],
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
