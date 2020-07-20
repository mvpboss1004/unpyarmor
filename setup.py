import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="unpyarmor",
    version="0.1",
    author="Nayil Mukhametshin",
    author_email="me@nayilm.com",
    description="Deobfuscator / unpacker for PyArmor",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "unpyarmor = unpyarmor.main:main",
        ],
    },
    install_requires=[
        "pycryptodome",
        "click"
    ],
    python_requires='>=3.6',
)
