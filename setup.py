from setuptools import setup, find_packages

setup(
    name="pybose",
    version="0.0.3",  # Initial version
    description="An unofficial Python API for controlling Bose soundbars and speakers.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="cavefire",
    author_email="timo@cavefire.net",
    url="https://github.com/cavefire/pybose",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "zeroconf",
        "websockets",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",  # Minimum Python version
)