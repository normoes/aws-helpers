#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="aws_get_logs",
    version="0.0.1",
    description="Get logs from AWS Cloudwatch.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Norman Moeschter-Schenck",
    author_email="<norman.moeschter@gmail.com>",
    maintainer="Norman Moeschter-Schenck",
    maintainer_email="<norman.moeschter@gmail.com>",
    url="https://github.com/normoes/aws-helpers/tree/master/cloudwatch_logs",
    packages=find_packages(exclude=["tests*"]),
    install_requires=["boto3>=1.10.25"],
    extras_require={"test": ["mock", "pytest"]},
    # scripts=["bin/servicedb"],
    # entry_points={
    #     "console_scripts": [
    #         "dynamodb=dynamodb:main",
    #     ],
    # },
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
)
