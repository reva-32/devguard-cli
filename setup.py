from setuptools import setup, find_packages
from pathlib import Path

# 1. This reads the contents of your README file dynamically
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="devguard",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "devguard": ["core/pre-push"],
    },
    install_requires=[
        "pyyaml",
    ],
    entry_points={
        "console_scripts": [
            "devguard=devguard.__main__:main",
        ],
    },
    long_description=long_description,
    long_description_content_type="text/markdown",
)