<#
.SYNOPSIS
    Builds the JSEye project into a pip-compatible wheel and installs it locally.
.DESCRIPTION
    This script cleanly wipes existing build directories, upgrades the Python build tools,
    builds a fresh sdist and wheel package, and then installs it directly utilizing pip.
#>

Write-Host "[*] Cleaning old build directories..." -ForegroundColor Cyan
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "jseye.egg-info") { Remove-Item -Recurse -Force "jseye.egg-info" }

Write-Host "[*] Upgrading build tools..." -ForegroundColor Cyan
python -m pip install --upgrade build pip setuptools wheel

Write-Host "[*] Building the package (sdist and wheel)..." -ForegroundColor Cyan
python -m build

Write-Host "[*] Installing the built wheel locally..." -ForegroundColor Cyan
$wheelFile = Get-ChildItem "dist\*.whl" | Select-Object -First 1
if ($wheelFile) {
    python -m pip install $wheelFile.FullName --force-reinstall
    Write-Host "[+] Installation complete. Try running 'jseye --help'" -ForegroundColor Green
} else {
    Write-Host "[-] Build failed. No wheel file found." -ForegroundColor Red
    exit 1
}
