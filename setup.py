from setuptools import setup, find_packages

setup(
    name="cwv-scanner",
    version="1.0.0",
    author="SirCryptic",
    author_email="sircryptic@protonmail.com",
    description="Common Web Application Vulnerability Scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/sircryptic/cwv-scanner",
    packages=find_packages(),  # Automatically find cwv_scanner package
    include_package_data=True,
    package_data={
        "cwv_scanner": ["waf_indicators.json", "vulnerabilities.json", "user_agents.txt", "banners/*.txt"],
    },
    install_requires=[
        "requests>=2.28.0",
        "fake-useragent>=0.1.11",
        "tabulate>=0.8.9",
    ],
    entry_points={
        "console_scripts": [
            "cwv-scanner=cwv_scanner.cwv_scanner:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
)