#!/bin/bash
# Builds the JSEye project into a pip-compatible wheel and installs it locally.

set -e

echo "[*] Cleaning old build directories..."
rm -rf build/ dist/ *.egg-info/

echo "[*] Upgrading build tools..."
python -m pip install --upgrade build pip setuptools wheel

echo "[*] Building the package (sdist and wheel)..."
python -m build

echo "[*] Installing the built wheel locally..."
WHEEL_FILE=$(ls dist/*.whl | head -n 1)

if [ -n "$WHEEL_FILE" ]; then
    python -m pip install "$WHEEL_FILE" --force-reinstall
    echo "[+] Installation complete. Try running 'jseye --help'"
else
    echo "[-] Build failed. No wheel file found."
    exit 1
fi
