from setuptools import setup, find_packages

setup(
    name='ffuzzer',
    version='0.1.3',
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
        'pwntools'
    ],
    python_requires='>=3',
    entry_points={
        'console_scripts': [
            'ffuzzer=ffuzzer:cli',
        ],
    },
)
