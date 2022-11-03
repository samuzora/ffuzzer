from setuptools import setup, find_packages

setup(
    name='ffuzzer',
    description='ffuzzer is a CLI tool that makes fuzzing format string offsets easy, especially relevant for full RELRO format string challenges, where you want to leak as much info from the binary as you can.',
    version='0.1.4.post0',
    license='MIT',
    author='samuzora',
    author_email='lucastanyj@gmail.com',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=['ffuzzer'],
    keywords='formatstring pwn',
    url='https://github.com/samuzora/ffuzzer',
    install_requires=[
        'Click',
        'pwntools',
        'rich',
        'regex'
    ],
    python_requires='>=3.9',
    entry_points={
        'console_scripts': [
            'ffuzzer=ffuzzer:cli',
        ],
    },
)
