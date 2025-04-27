from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cwv-scanner",
    version="1.0.0",
    author="SirCryptic",
    description="Common Web Application Vulnerability Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sircryptic/cwv-scanner",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests",
        "fake-useragent",
        "tabulate",
        "beautifulsoup4",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            "cwv-scanner=cwv_scanner.cwv_scanner:main",
        ],
    },
)
