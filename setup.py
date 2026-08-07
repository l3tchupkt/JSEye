"""Setup script for JSEye."""

from setuptools import setup, find_packages
import os

# Read version from version.py
version_file = os.path.join(os.path.dirname(__file__), 'jseye', 'version.py')
with open(version_file) as f:
    exec(f.read())

# Read README for long description
readme_file = os.path.join(os.path.dirname(__file__), 'README.md')
try:
    with open(readme_file, 'r', encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "JSEye - JavaScript Intelligence & Attack Surface Discovery Engine"

# Read requirements
requirements_file = os.path.join(os.path.dirname(__file__), 'requirements.txt')
try:
    with open(requirements_file, 'r') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
except FileNotFoundError:
    requirements = [
        'aiohttp>=3.8.0',
        'beautifulsoup4>=4.11.0',
        'lxml>=4.9.0',
        'jsbeautifier>=1.14.0',
        'jinja2>=3.1.0',
        'waybackpy>=3.0.6',
        'tldextract>=3.4.0',
        'rich>=12.0.2',
        'psutil>=5.9.0',
        'requests>=2.28.0',
        'packaging>=21.0',
        'pyyaml>=6.0'
    ]

setup(
    name='jseye',
    version=__version__,
    description='JavaScript Intelligence & Attack Surface Discovery Engine',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Lakshmikanthan K',
    author_email='letchupkt.dev@gmail.com',
    url='https://github.com/letchupkt/jseye',
    packages=find_packages(include=['jseye', 'jseye.*']),
    include_package_data=True,
    package_data={
        'jseye': [
            'data/*.json',
            'data/*.yaml',
            'report/templates/*.html'
        ]
    },
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-asyncio>=0.21.0',
            'black>=22.0.2',
            'flake8>=5.0.0',
            'mypy>=0.991',
            'build>=0.10.0',
            'twine>=4.0.0'
        ],
        'headless': [
            'selenium>=4.0.0',
            'webdriver-manager>=3.8.0'
        ],
        'all': [
            'selenium>=4.0.0',
            'webdriver-manager>=3.8.0',
            'pytest>=7.0.0',
            'pytest-asyncio>=0.21.0'
        ]
    },
    entry_points={
        'console_scripts': [
            'jseye=jseye.cli:cli_main',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Testing',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Software Development :: Quality Assurance',
        'Environment :: Console',
    ],
    python_requires='>=3.8',
    keywords='security javascript reconnaissance osint bug-bounty penetration-testing vulnerability-scanner',
    project_urls={
        'Bug Reports': 'https://github.com/letchupkt/jseye/issues',
        'Source': 'https://github.com/letchupkt/jseye',
        'Documentation': 'https://github.com/letchupkt/jseye/wiki',
        'Homepage': 'https://github.com/letchupkt/jseye',
    },
    zip_safe=False,
)