#!/usr/bin/env python3
"""
Release and Version Validation Script for JSEye.
Validates tag consistency, packaging metadata, and distribution contents.
"""

import os
import sys
import zipfile
import tarfile
from pathlib import Path


def get_package_version() -> str:
    """Extract package version from jseye/version.py."""
    version_file = Path(__file__).resolve().parent.parent / "jseye" / "version.py"
    if not version_file.exists():
        raise FileNotFoundError(f"version.py not found at {version_file}")
    
    version_dict = {}
    with open(version_file, "r", encoding="utf-8") as f:
        exec(f.read(), version_dict)
    
    version = version_dict.get("__version__")
    if not version:
        raise ValueError("Could not find __version__ in jseye/version.py")
    return version


def validate_tag_consistency(expected_version: str) -> None:
    """Ensure git tag (if present or in CI environment) matches package version."""
    # Check explicit RELEASE_TAG env var first, then GITHUB_REF_NAME
    tag = os.environ.get("RELEASE_TAG", "").strip() or os.environ.get("GITHUB_REF_NAME", "").strip()
    is_ci = os.environ.get("GITHUB_ACTIONS", "") == "true"

    if tag and (tag.startswith("v") or is_ci):
        if not tag.startswith("v"):
            print(f"[!] ERROR: Release tag '{tag}' must start with 'v' (e.g. v{expected_version})!", file=sys.stderr)
            sys.exit(1)
        tag_version = tag.lstrip("v")
        print(f"[*] Validating release tag: '{tag}' against package version: '{expected_version}'")
        if tag_version != expected_version:
            print(f"[!] ERROR: Release tag '{tag}' does not match package version '{expected_version}'!", file=sys.stderr)
            sys.exit(1)
        print(f"[+] Release tag matches package version: {expected_version}")
    elif is_ci:
        print("[!] ERROR: No release tag provided in CI environment!", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"[*] Local environment detected. Validating package version: {expected_version}")


def validate_distribution_artifacts(expected_version: str) -> None:
    """Validate that wheel and sdist files exist and contain required data files."""
    dist_dir = Path(__file__).resolve().parent.parent / "dist"
    if not dist_dir.exists():
        print("[!] No 'dist/' directory found. Build distributions first.", file=sys.stderr)
        sys.exit(1)

    wheel_files = list(dist_dir.glob(f"jseye-{expected_version}*.whl"))
    sdist_files = list(dist_dir.glob(f"jseye-{expected_version}*.tar.gz"))

    if not wheel_files:
        print(f"[!] Missing wheel file for version {expected_version} in dist/", file=sys.stderr)
        sys.exit(1)
    if not sdist_files:
        print(f"[!] Missing sdist file for version {expected_version} in dist/", file=sys.stderr)
        sys.exit(1)

    wheel_path = wheel_files[0]
    print(f"[*] Validating wheel archive: {wheel_path.name}")
    required_wheel_entries = [
        "jseye/__init__.py",
        "jseye/cli.py",
        "jseye/version.py",
        "jseye/data/regex_patterns.json",
        "jseye/data/swagger.yaml",
        "jseye/report/templates/report.html",
    ]

    with zipfile.ZipFile(wheel_path, "r") as z:
        names = set(z.namelist())
        for entry in required_wheel_entries:
            if entry not in names:
                print(f"[!] Wheel is missing required entry: {entry}", file=sys.stderr)
                sys.exit(1)
        print(f"[+] Wheel archive contains all {len(required_wheel_entries)} required package data entries.")

    sdist_path = sdist_files[0]
    print(f"[*] Validating source distribution: {sdist_path.name}")
    required_sdist_entries = [
        f"jseye-{expected_version}/README.md",
        f"jseye-{expected_version}/LICENSE",
        f"jseye-{expected_version}/pyproject.toml",
        f"jseye-{expected_version}/setup.py",
        f"jseye-{expected_version}/jseye/version.py",
    ]

    with tarfile.open(sdist_path, "r:gz") as t:
        sdist_names = set(t.getnames())
        for entry in required_sdist_entries:
            if entry not in sdist_names:
                print(f"[!] Sdist is missing required entry: {entry}", file=sys.stderr)
                sys.exit(1)
        print(f"[+] Sdist contains all {len(required_sdist_entries)} required root entries.")


def main() -> None:
    version = get_package_version()
    print(f"[+] Current JSEye version: {version}")
    validate_tag_consistency(version)
    validate_distribution_artifacts(version)
    print("\n[+] All release validation checks passed successfully!")


if __name__ == "__main__":
    main()

