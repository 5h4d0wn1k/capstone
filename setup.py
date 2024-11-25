from setuptools import setup, find_packages

setup(
    name="windows-siem",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        line.strip()
        for line in open("requirements.txt").readlines()
        if not line.startswith("#") and line.strip()
    ],
    author="Capstone Team",
    description="Windows Security Information and Event Management System",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "windows-siem=siem.main:main",
        ],
    },
)
