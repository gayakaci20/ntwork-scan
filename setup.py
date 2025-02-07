from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ntwork-scan",
    version="1.0.0",
    author="Network Scanner",
    description="A comprehensive network scanning tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        'scapy>=2.5.0',
        'python-nmap>=0.7.1',
        'ipaddress>=1.0.23',
    ],
    entry_points={
        'console_scripts': [
            'ntwork-scan=ntwork-scan:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)