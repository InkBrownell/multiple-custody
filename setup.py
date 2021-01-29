from distutils.core import setup

setup(
    name='multiple_custody',
    author="Ink Brownell",
    author_email="inkbrownell@gmail.com",
    version='0.1.0',
    packages=['multiple_custody'],
    license='GNU Lesser General Public License v3 or later (LGPLv3+)',
    description="A package facilitating multiple custody of digital secrets",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/InkBrownell/multiple-custody",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Environment :: Console",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography"
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': ['multiple_custody=multiple_custody.multiple_custody:main'],
    }
)
