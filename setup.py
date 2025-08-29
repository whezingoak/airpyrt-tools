from setuptools import setup

setup(
	name="acp",
	version="2.0",
	description="Ferramentas AirPyrt",
	author="Whezingoak",
	author_email="whezingoak@voxelflux.com.br",
	packages=["acp"],
	entry_points = {
		"console_scripts": ["acp=acp.cli:main"],
		},
	install_requires=[
		"pycryptodome",
		]
	)
