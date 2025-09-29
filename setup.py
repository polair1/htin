from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="html-injection-scanner",
    version="1.0.0",
    author="Tu Nombre",
    author_email="tu-email@ejemplo.com",
    description="Herramienta para detectar vulnerabilidades de inyección HTML",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tu-usuario/html-injection-scanner",
    py_modules=["html_scanner"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
    ],
    entry_points={
        "console_scripts": [
            "html-scanner=html_scanner:main",
        ],
    },
)
