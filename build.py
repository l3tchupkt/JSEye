#!/usr/bin/env python3
"""
JSEye Build Script - Proper Python Package Distribution
Creates standard Python packages with correct metadata
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def print_header(text):
    """Print a header."""
    print(f"\n{'='*60}")
    print(f"{text.center(60)}")
    print(f"{'='*60}")

def print_step(text):
    """Print a step."""
    print(f"\n[*] {text}")

def print_success(text):
    """Print success."""
    print(f"[+] {text}")

def print_error(text):
    """Print error."""
    print(f"[-] {text}")

def clean_build():
    """Clean build artifacts."""
    print_step("Cleaning build artifacts")
    
    # Directories to remove
    dirs_to_remove = ['build', 'dist', 'jseye.egg-info']
    
    for dir_name in dirs_to_remove:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"  Removed: {dir_name}")
    
    print_success("Build artifacts cleaned")

def validate_structure():
    """Validate package structure."""
    print_step("Validating package structure")
    
    required_files = [
        'setup.py',
        'pyproject.toml', 
        'requirements.txt',
        'README.md',
        'LICENSE',
        'jseye/__init__.py',
        'jseye/version.py',
        'jseye/cli.py'
    ]
    
    missing = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing.append(file_path)
    
    if missing:
        print_error(f"Missing files: {', '.join(missing)}")
        return False
    
    print_success("Package structure valid")
    return True

def get_version():
    """Get version from version.py."""
    try:
        version_file = Path('jseye/version.py')
        content = version_file.read_text()
        
        # Extract version using simple string parsing
        for line in content.split('\n'):
            if line.strip().startswith('__version__'):
                # Extract version between quotes
                start = line.find('"')
                if start == -1:
                    start = line.find("'")
                if start != -1:
                    end = line.find(line[start], start + 1)
                    if end != -1:
                        version = line[start + 1:end]
                        print(f"  Found version: {version}")
                        return version
        
        print_error("Could not extract version")
        return None
        
    except Exception as e:
        print_error(f"Failed to read version: {e}")
        return None

def install_build_tools():
    """Install required build tools."""
    print_step("Installing build tools")
    
    try:
        # Install setuptools, wheel, and build
        cmd = [sys.executable, '-m', 'pip', 'install', '--upgrade', 'setuptools', 'wheel', 'build', 'twine']
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            print_success("Build tools installed")
            return True
        else:
            print_error("Failed to install build tools")
            if result.stderr:
                print(f"  STDERR: {result.stderr}")
            return False
            
    except Exception as e:
        print_error(f"Failed to install build tools: {e}")
        return False

def build_with_setuptools():
    """Build using setuptools directly."""
    print_step("Building with setuptools")
    
    try:
        # Create source distribution
        print("  Creating source distribution...")
        cmd_sdist = [sys.executable, 'setup.py', 'sdist']
        
        result_sdist = subprocess.run(
            cmd_sdist,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result_sdist.returncode != 0:
            print_error("Source distribution failed")
            if result_sdist.stderr:
                print(f"  STDERR: {result_sdist.stderr}")
            return False
        
        # Create wheel distribution
        print("  Creating wheel distribution...")
        cmd_wheel = [sys.executable, 'setup.py', 'bdist_wheel']
        
        result_wheel = subprocess.run(
            cmd_wheel,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result_wheel.returncode != 0:
            print_error("Wheel distribution failed")
            if result_wheel.stderr:
                print(f"  STDERR: {result_wheel.stderr}")
            return False
        
        print_success("Package built with setuptools")
        return True
        
    except Exception as e:
        print_error(f"Build failed: {e}")
        return False

def build_with_build_module():
    """Build using the build module."""
    print_step("Building with build module")
    
    try:
        # Use python -m build
        cmd = [sys.executable, '-m', 'build', '--sdist', '--wheel']
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            print_success("Package built with build module")
            return True
        else:
            print_error("Build module failed")
            if result.stdout:
                print(f"  STDOUT: {result.stdout}")
            if result.stderr:
                print(f"  STDERR: {result.stderr}")
            return False
            
    except Exception as e:
        print_error(f"Build module failed: {e}")
        return False

def list_built_files():
    """List files in dist directory."""
    if os.path.exists('dist'):
        print("\n[*] Built packages:")
        for file_name in sorted(os.listdir('dist')):
            file_path = os.path.join('dist', file_name)
            size = os.path.getsize(file_path)
            print(f"  - {file_name} ({size:,} bytes)")
    else:
        print("  No dist directory found")

def check_package():
    """Check package with twine."""
    print_step("Checking package with twine")
    
    try:
        cmd = [sys.executable, '-m', 'twine', 'check', 'dist/*']
        
        result = subprocess.run(
            cmd,
            shell=True,  # For glob expansion
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            print_success("Package check passed")
            if result.stdout:
                print(f"  Output: {result.stdout}")
            return True
        else:
            print_error("Package check failed")
            if result.stdout:
                print(f"  STDOUT: {result.stdout}")
            if result.stderr:
                print(f"  STDERR: {result.stderr}")
            return False
            
    except Exception as e:
        print_error(f"Package check failed: {e}")
        return False

def main():
    """Main build function."""
    print_header("JSEye Build Script v2.0")
    
    # Clean first
    clean_build()
    
    # Validate structure
    if not validate_structure():
        return 1
    
    # Get version
    version = get_version()
    if not version:
        return 1
    
    # Install build tools
    if not install_build_tools():
        return 1
    
    # Try building with build module first
    build_success = build_with_build_module()
    
    # If that fails, try setuptools
    if not build_success:
        print("\nTrying alternative build method...")
        build_success = build_with_setuptools()
    
    if not build_success:
        print_header("BUILD FAILED")
        return 1
    
    # List built files
    list_built_files()
    
    # Check package
    if not check_package():
        print_header("PACKAGE CHECK FAILED")
        return 1
    
    print_header("BUILD COMPLETED SUCCESSFULLY")
    print("[+] JSEye v{} is ready for PyPI distribution!".format(version))
    print("[*] Built packages are in the 'dist/' directory")
    print("[*] To upload to PyPI: python -m twine upload dist/*")
    print("[*] To upload to Test PyPI: python -m twine upload --repository testpypi dist/*")
    
    return 0

if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n[-] Build interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        sys.exit(1)