from setuptools import setup

from aws_ecs_services._version import __version__


setup(
    name="aws_ecs_services",
    version=__version__,
    description=("Interact with XMR.to, create and track your orders."),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Norman Moeschter-Schenck",
    author_email="norman.moeschter@gmail.com",
    url="https://github.com/monero-ecosystem/xmrto_wrapper",
    download_url=f"https://github.com/monero-ecosystem/xmrto_wrapper/archive/{__version__}.tar.gz",
    install_requires=["requests>=2.23.0"],
    # py_modules=["xmrto_wrapper"],
    packages=["aws_ecs_services"],
    scripts=["bin/aws_ecs_services"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python",
    ],
)
