from setuptools import setup, find_packages
 
setup(
    name = "tinyshell",
    version = "1.0",
    packages = find_packages(),
    install_requires=[
		'docopt==0.6.2',
		'requests==2.7.0',
    ]

    )