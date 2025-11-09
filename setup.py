from setuptools import setup, find_packages

setup(
    name="timing_attack",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'requests',
        'pyyaml',
        'numpy',
        'scipy',
        'python-dotenv'
    ],
)