"""Operating system detection and tool management."""

import platform
import subprocess
import shutil
import os
from typing import Dict, List, Optional
from rich.console import Console

console = Console()


class OSDetector:
    """Detect operating system and manage tool installations."""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.arch = platform.machine().lower()
        
    def get_os_info(self) -> Dict[str, str]:
        """Get detailed OS information."""
        return {
            'system': self.os_type,
            'architecture': self.arch,
            'platform': platform.platform(),
            'version': platform.version()
        }
    
    def is_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed and available in PATH or Go bin directory."""
        # Check system PATH first
        if shutil.which(tool_name) is not None:
            return True
        
        # Check user's local bin directory
        home_dir = os.path.expanduser('~')
        local_bin = os.path.join(home_dir, '.local', 'bin', tool_name)
        if os.path.exists(local_bin) and os.access(local_bin, os.X_OK):
            return True
        
        # Check Go bin directory (common locations)
        go_bin_paths = [
            os.path.join(home_dir, 'go', 'bin', tool_name),
            os.path.join('/root', 'go', 'bin', tool_name),
            os.path.join('/usr', 'local', 'go', 'bin', tool_name),
            os.path.join(home_dir, '.go', 'bin', tool_name),
            os.path.join('/usr', 'local', 'go', 'bin', tool_name),
            os.path.join('/opt', 'go', 'bin', tool_name)
        ]
        
        for go_bin_path in go_bin_paths:
            if os.path.exists(go_bin_path) and os.access(go_bin_path, os.X_OK):
                # Add to PATH for this session
                go_bin_dir = os.path.dirname(go_bin_path)
                current_path = os.environ.get('PATH', '')
                if go_bin_dir not in current_path:
                    os.environ['PATH'] = f"{go_bin_dir}:{current_path}"
                return True
        
        return False
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get the full path to a tool if it exists."""
        # Check system PATH first
        tool_path = shutil.which(tool_name)
        if tool_path is not None:
            return tool_path
        
        # Check user's local bin directory
        home_dir = os.path.expanduser('~')
        local_bin = os.path.join(home_dir, '.local', 'bin', tool_name)
        if os.path.exists(local_bin) and os.access(local_bin, os.X_OK):
            return local_bin
        
        # Check Go bin directory (common locations)
        go_bin_paths = [
            os.path.join(home_dir, 'go', 'bin', tool_name),
            os.path.join('/root', 'go', 'bin', tool_name),
            os.path.join('/usr', 'local', 'go', 'bin', tool_name),
            os.path.join(home_dir, '.go', 'bin', tool_name),
            os.path.join('/usr', 'local', 'go', 'bin', tool_name),
            os.path.join('/opt', 'go', 'bin', tool_name)
        ]
        
        for go_bin_path in go_bin_paths:
            if os.path.exists(go_bin_path) and os.access(go_bin_path, os.X_OK):
                return go_bin_path
        
        return None
    
    def install_gau(self) -> bool:
        """Install gau tool based on OS."""
        if self.is_tool_installed('gau'):
            return True
            
        console.print(f"[yellow]Installing gau for {self.os_type}...")
        
        try:
            # Method 1: Try go install first
            result = subprocess.run(['go', 'install', 'github.com/lc/gau/v2/cmd/gau@latest'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and self.is_tool_installed('gau'):
                return True
            
            # Method 2: Try older version
            result = subprocess.run(['go', 'install', 'github.com/lc/gau@latest'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and self.is_tool_installed('gau'):
                return True
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Method 3: OS-specific installation
        try:
            if self.os_type == 'linux':
                return self._install_gau_linux()
            elif self.os_type == 'darwin':  # macOS
                return self._install_gau_macos()
            elif self.os_type == 'windows':
                return self._install_gau_windows()
            else:
                console.print(f"[red]Unsupported OS: {self.os_type}")
                return False
        except Exception as e:
            console.print(f"[red]Failed to install gau: {e}")
            return False
    
    def _install_gau_linux(self) -> bool:
        """Install gau on Linux."""
        try:
            # Try go install first
            result = subprocess.run(['go', 'install', 'github.com/lc/gau/v2/cmd/gau@latest'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and self.is_tool_installed('gau'):
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Fallback to binary download in user directory
        try:
            import tempfile
            import os
            
            arch_map = {'x86_64': 'amd64', 'aarch64': 'arm64'}
            arch = arch_map.get(self.arch, 'amd64')
            
            # Use user's home directory for installation
            home_dir = os.path.expanduser('~')
            bin_dir = os.path.join(home_dir, '.local', 'bin')
            os.makedirs(bin_dir, exist_ok=True)
            
            with tempfile.TemporaryDirectory() as temp_dir:
                tar_file = os.path.join(temp_dir, 'gau.tar.gz')
                
                # Try multiple download URLs
                download_urls = [
                    f'https://github.com/lc/gau/releases/download/v2.2.3/gau_2.2.3_linux_{arch}.tar.gz',
                    f'https://github.com/lc/gau/releases/download/v2.2.1/gau_2.2.1_linux_{arch}.tar.gz',
                    f'https://github.com/lc/gau/releases/download/v2.1.0/gau_2.1.0_linux_{arch}.tar.gz'
                ]
                
                download_success = False
                for url in download_urls:
                    try:
                        download_cmd = ['curl', '-L', '-o', tar_file, url]
                        result = subprocess.run(download_cmd, capture_output=True, text=True, timeout=30)
                        
                        if result.returncode == 0 and os.path.exists(tar_file) and os.path.getsize(tar_file) > 1000:
                            # Verify it's a valid gzip file
                            with open(tar_file, 'rb') as f:
                                magic = f.read(2)
                                if magic == b'\x1f\x8b':  # gzip magic number
                                    download_success = True
                                    break
                    except Exception:
                        continue
                
                if not download_success:
                    console.print("[red]Failed to download valid gau archive from any source")
                    return False
                
                # Extract and install
                try:
                    subprocess.run(['tar', '-xzf', tar_file, '-C', temp_dir], check=True)
                except subprocess.CalledProcessError:
                    console.print("[red]Failed to extract gau archive")
                    return False
                
                gau_binary = os.path.join(temp_dir, 'gau')
                if os.path.exists(gau_binary):
                    dest_path = os.path.join(bin_dir, 'gau')
                    subprocess.run(['cp', gau_binary, dest_path], check=True)
                    subprocess.run(['chmod', '+x', dest_path], check=True)
                    
                    # Add to PATH if not already there
                    current_path = os.environ.get('PATH', '')
                    if bin_dir not in current_path:
                        console.print(f"[yellow]Note: Add {bin_dir} to your PATH for gau to work globally")
                    
                    return os.path.exists(dest_path)
                else:
                    console.print("[red]gau binary not found in downloaded archive")
                    return False
                    
        except Exception as e:
            console.print(f"[red]Binary installation failed: {e}")
            # Try a simple wget fallback
            try:
                console.print("[yellow]Trying alternative download method...")
                home_dir = os.path.expanduser('~')
                bin_dir = os.path.join(home_dir, '.local', 'bin')
                os.makedirs(bin_dir, exist_ok=True)
                
                # Direct binary download without compression
                binary_url = f'https://github.com/lc/gau/releases/download/v2.1.0/gau_linux_{arch}'
                dest_path = os.path.join(bin_dir, 'gau')
                
                result = subprocess.run(['curl', '-L', '-o', dest_path, binary_url], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0 and os.path.exists(dest_path):
                    subprocess.run(['chmod', '+x', dest_path], check=True)
                    return os.path.exists(dest_path)
                    
            except Exception:
                pass
            
            return False
    
    def _install_gau_macos(self) -> bool:
        """Install gau on macOS."""
        try:
            # Try brew first
            result = subprocess.run(['brew', 'install', 'gau'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Try go install
        try:
            result = subprocess.run(['go', 'install', 'github.com/lc/gau/v2/cmd/gau@latest'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Fallback to binary download
        try:
            arch_map = {'x86_64': 'amd64', 'arm64': 'arm64'}
            arch = arch_map.get(self.arch, 'amd64')
            
            download_cmd = [
                'curl', '-L', '-o', '/tmp/gau.tar.gz',
                f'https://github.com/lc/gau/releases/latest/download/gau_{arch}_darwin.tar.gz'
            ]
            subprocess.run(download_cmd, check=True, timeout=30)
            
            subprocess.run(['tar', '-xzf', '/tmp/gau.tar.gz', '-C', '/tmp/'], check=True)
            subprocess.run(['mv', '/tmp/gau', '/usr/local/bin/'], check=True)
            subprocess.run(['chmod', '+x', '/usr/local/bin/gau'], check=True)
            
            return self.is_tool_installed('gau')
        except Exception:
            return False
    
    def _install_gau_windows(self) -> bool:
        """Install gau on Windows."""
        try:
            # Try go install first
            result = subprocess.run(['go', 'install', 'github.com/lc/gau/v2/cmd/gau@latest'], 
                                  capture_output=True, text=True, timeout=60, shell=True)
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Manual binary download
        try:
            import urllib.request
            import zipfile
            
            arch = 'amd64' if '64' in self.arch else '386'
            url = f'https://github.com/lc/gau/releases/latest/download/gau_{arch}_windows.zip'
            
            zip_path = os.path.join(os.environ.get('TEMP', '.'), 'gau.zip')
            urllib.request.urlretrieve(url, zip_path)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(os.environ.get('TEMP', '.'))
            
            # Move to a directory in PATH
            gau_exe = os.path.join(os.environ.get('TEMP', '.'), 'gau.exe')
            dest_dir = os.path.join(os.environ.get('USERPROFILE', '.'), 'bin')
            os.makedirs(dest_dir, exist_ok=True)
            
            import shutil
            shutil.move(gau_exe, os.path.join(dest_dir, 'gau.exe'))
            
            # Add to PATH if not already there
            current_path = os.environ.get('PATH', '')
            if dest_dir not in current_path:
                console.print(f"[yellow]Please add {dest_dir} to your PATH environment variable")
            
            return True
        except Exception:
            return False
    
    def install_waybackurls(self) -> bool:
        """Install waybackurls tool."""
        if self.is_tool_installed('waybackurls'):
            return True
            
        console.print(f"[yellow]Installing waybackurls for {self.os_type}...")
        
        try:
            # Method 1: Try go install first
            result = subprocess.run(['go', 'install', 'github.com/tomnomnom/waybackurls@latest'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and self.is_tool_installed('waybackurls'):
                return True
            
            # Method 2: Try go get (older method)
            result = subprocess.run(['go', 'get', 'github.com/tomnomnom/waybackurls'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and self.is_tool_installed('waybackurls'):
                return True
                
            # Method 3: OS-specific installation
            if self.os_type == 'linux':
                return self._install_waybackurls_linux()
            elif self.os_type == 'darwin':
                return self._install_waybackurls_macos()
            elif self.os_type == 'windows':
                return self._install_waybackurls_windows()
                
        except Exception as e:
            console.print(f"[red]Failed to install waybackurls: {e}")
            return False
        
        return False
    
    def _install_waybackurls_linux(self) -> bool:
        """Install waybackurls on Linux using binary download."""
        try:
            import tempfile
            
            # Use user's home directory for installation
            home_dir = os.path.expanduser('~')
            bin_dir = os.path.join(home_dir, '.local', 'bin')
            os.makedirs(bin_dir, exist_ok=True)
            
            # Try direct binary download first (no compression)
            arch_map = {'x86_64': 'amd64', 'aarch64': 'arm64'}
            arch = arch_map.get(self.arch, 'amd64')
            
            # Try direct binary download
            try:
                binary_url = f'https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-{arch}-0.1.0'
                dest_path = os.path.join(bin_dir, 'waybackurls')
                
                result = subprocess.run(['curl', '-L', '-o', dest_path, binary_url], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0 and os.path.exists(dest_path) and os.path.getsize(dest_path) > 1000:
                    subprocess.run(['chmod', '+x', dest_path], check=True)
                    if self.is_tool_installed('waybackurls'):
                        return True
            except Exception:
                pass
            
            # Fallback to compressed archive
            with tempfile.TemporaryDirectory() as temp_dir:
                tar_file = os.path.join(temp_dir, 'waybackurls.tgz')
                
                # Try multiple download URLs
                download_urls = [
                    f'https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-{arch}-0.1.0.tgz',
                    f'https://github.com/tomnomnom/waybackurls/releases/latest/download/waybackurls-linux-{arch}.tgz'
                ]
                
                download_success = False
                for url in download_urls:
                    try:
                        download_cmd = ['curl', '-L', '-o', tar_file, url]
                        result = subprocess.run(download_cmd, capture_output=True, text=True, timeout=30)
                        
                        if result.returncode == 0 and os.path.exists(tar_file) and os.path.getsize(tar_file) > 1000:
                            # Verify it's a valid gzip file
                            with open(tar_file, 'rb') as f:
                                magic = f.read(2)
                                if magic == b'\x1f\x8b':  # gzip magic number
                                    download_success = True
                                    break
                    except Exception:
                        continue
                
                if not download_success:
                    # Try alternative installation via go get (older method)
                    try:
                        result = subprocess.run(['go', 'get', 'github.com/tomnomnom/waybackurls'], 
                                              capture_output=True, text=True, timeout=60)
                        if result.returncode == 0 and self.is_tool_installed('waybackurls'):
                            return True
                    except Exception:
                        pass
                    
                    console.print("[red]Failed to download waybackurls from any source")
                    return False
                
                # Extract and install
                try:
                    subprocess.run(['tar', '-xzf', tar_file, '-C', temp_dir], check=True)
                except subprocess.CalledProcessError:
                    console.print("[red]Failed to extract waybackurls archive")
                    return False
                
                # Find the binary (might be in different locations)
                possible_paths = [
                    os.path.join(temp_dir, 'waybackurls'),
                    os.path.join(temp_dir, f'waybackurls-linux-{arch}-0.1.0'),
                    os.path.join(temp_dir, f'waybackurls-linux-{arch}')
                ]
                
                waybackurls_binary = None
                for path in possible_paths:
                    if os.path.exists(path) and os.access(path, os.X_OK):
                        waybackurls_binary = path
                        break
                
                if waybackurls_binary:
                    dest_path = os.path.join(bin_dir, 'waybackurls')
                    subprocess.run(['cp', waybackurls_binary, dest_path], check=True)
                    subprocess.run(['chmod', '+x', dest_path], check=True)
                    
                    return os.path.exists(dest_path) and self.is_tool_installed('waybackurls')
                else:
                    console.print("[red]waybackurls binary not found in downloaded archive")
                    return False
                    
        except Exception as e:
            console.print(f"[red]waybackurls installation failed: {e}")
            return False
    
    def _install_waybackurls_macos(self) -> bool:
        """Install waybackurls on macOS."""
        try:
            # Try brew first
            result = subprocess.run(['brew', 'install', 'waybackurls'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Fallback to binary download similar to Linux
        return self._install_waybackurls_linux()
    
    def _install_waybackurls_windows(self) -> bool:
        """Install waybackurls on Windows."""
        try:
            import urllib.request
            import zipfile
            
            arch = 'amd64' if '64' in self.arch else '386'
            url = f'https://github.com/tomnomnom/waybackurls/releases/latest/download/waybackurls-windows-{arch}.zip'
            
            zip_path = os.path.join(os.environ.get('TEMP', '.'), 'waybackurls.zip')
            urllib.request.urlretrieve(url, zip_path)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(os.environ.get('TEMP', '.'))
            
            # Move to a directory in PATH
            waybackurls_exe = os.path.join(os.environ.get('TEMP', '.'), 'waybackurls.exe')
            dest_dir = os.path.join(os.environ.get('USERPROFILE', '.'), 'bin')
            os.makedirs(dest_dir, exist_ok=True)
            
            import shutil
            shutil.move(waybackurls_exe, os.path.join(dest_dir, 'waybackurls.exe'))
            
            return True
        except Exception:
            return False
    
    def install_hakrawl(self) -> bool:
        """Install hakrawler tool."""
        if self.is_tool_installed('hakrawler'):
            return True
            
        console.print(f"[yellow]Installing hakrawler for {self.os_type}...")
        
        try:
            # Method 1: Try go install with latest version
            result = subprocess.run(['go', 'install', 'github.com/hakluke/hakrawler@latest'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and self.is_tool_installed('hakrawler'):
                return True
            
            # Method 2: Try go get (older method)
            result = subprocess.run(['go', 'get', 'github.com/hakluke/hakrawler'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and self.is_tool_installed('hakrawler'):
                return True
            
            # Method 3: Try alternative repository
            result = subprocess.run(['go', 'install', 'github.com/hakluke/hakrawler/cmd/hakrawler@latest'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and self.is_tool_installed('hakrawler'):
                return True
                
        except Exception as e:
            console.print(f"[red]Failed to install hakrawler: {e}")
            return False
        
        return False
    
    def install_mantra(self) -> bool:
        """Install mantra tool."""
        if self.is_tool_installed('mantra'):
            return True
            
        console.print(f"[yellow]Installing mantra for {self.os_type}...")
        
        try:
            # Method 1: Try go install with latest version
            result = subprocess.run(['go', 'install', 'github.com/Brosck/mantra@latest'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and self.is_tool_installed('mantra'):
                return True
            
            # Method 2: Try go get
            result = subprocess.run(['go', 'get', 'github.com/Brosck/mantra'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and self.is_tool_installed('mantra'):
                return True
                
        except Exception as e:
            console.print(f"[red]Failed to install mantra: {e}")
            return False
        
        return False
    
    def is_go_installed(self) -> bool:
        """Check if Go is installed and available."""
        try:
            result = subprocess.run(['go', 'version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def install_go(self) -> bool:
        """Install Go programming language."""
        if self.is_go_installed():
            return True
            
        console.print(f"[yellow]Installing Go for {self.os_type}...")
        
        try:
            if self.os_type == 'linux':
                return self._install_go_linux()
            elif self.os_type == 'darwin':
                return self._install_go_macos()
            elif self.os_type == 'windows':
                return self._install_go_windows()
            else:
                console.print(f"[red]Unsupported OS for Go installation: {self.os_type}")
                return False
        except Exception as e:
            console.print(f"[red]Go installation failed: {e}")
            return False
    
    def _install_go_linux(self) -> bool:
        """Install Go on Linux."""
        try:
            # Try package manager first
            package_managers = [
                ['apt', 'update', '&&', 'apt', 'install', '-y', 'golang-go'],
                ['yum', 'install', '-y', 'golang'],
                ['dnf', 'install', '-y', 'golang'],
                ['pacman', '-S', '--noconfirm', 'go'],
                ['zypper', 'install', '-y', 'go']
            ]
            
            for pm_cmd in package_managers:
                try:
                    result = subprocess.run(pm_cmd, capture_output=True, text=True, timeout=300)
                    if result.returncode == 0 and self.is_go_installed():
                        return True
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
            
            # Manual installation as fallback
            console.print("[yellow]Package manager installation failed, trying manual installation...")
            return self._install_go_manual_linux()
            
        except Exception as e:
            console.print(f"[red]Go Linux installation failed: {e}")
            return False
    
    def _install_go_manual_linux(self) -> bool:
        """Manually install Go on Linux."""
        try:
            import tempfile
            
            arch_map = {'x86_64': 'amd64', 'aarch64': 'arm64'}
            arch = arch_map.get(self.arch, 'amd64')
            
            go_version = "1.21.5"
            go_url = f"https://golang.org/dl/go{go_version}.linux-{arch}.tar.gz"
            
            with tempfile.TemporaryDirectory() as temp_dir:
                go_tar = os.path.join(temp_dir, 'go.tar.gz')
                
                # Download Go
                result = subprocess.run(['curl', '-L', '-o', go_tar, go_url], 
                                      capture_output=True, text=True, timeout=120)
                
                if result.returncode != 0:
                    return False
                
                # Install to /usr/local
                result = subprocess.run(['sudo', 'tar', '-C', '/usr/local', '-xzf', go_tar], 
                                      capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    # Add to PATH
                    console.print("[yellow]Go installed to /usr/local/go")
                    console.print("[yellow]Add /usr/local/go/bin to your PATH")
                    return True
                
                return False
                
        except Exception:
            return False
    
    def _install_go_macos(self) -> bool:
        """Install Go on macOS."""
        try:
            # Try Homebrew first
            result = subprocess.run(['brew', 'install', 'go'], 
                                  capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Fallback to manual installation
        return self._install_go_manual_linux()
    
    def _install_go_windows(self) -> bool:
        """Install Go on Windows."""
        try:
            # Try Chocolatey first
            result = subprocess.run(['choco', 'install', 'golang', '-y'], 
                                  capture_output=True, text=True, timeout=300, shell=True)
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Try Scoop
        try:
            result = subprocess.run(['scoop', 'install', 'go'], 
                                  capture_output=True, text=True, timeout=300, shell=True)
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        console.print("[yellow]Please install Go manually from: https://golang.org/dl/")
        return False
    
    def check_and_install_tools(self) -> Dict[str, bool]:
        """Check and install all required tools."""
        tools_status = {}
        
        # Check Go first (required for all other tools)
        if not self.is_go_installed():
            tools_status['go'] = self.install_go()
        else:
            tools_status['go'] = True
        
        # Only proceed with other tools if Go is available
        if not tools_status['go']:
            console.print("[red]Go installation failed - cannot install other tools")
            tools_status.update({'gau': False, 'waybackurls': False, 'hakrawler': False})
            return tools_status
        
        # Check gau (required)
        if not self.is_tool_installed('gau'):
            tools_status['gau'] = self.install_gau()
        else:
            tools_status['gau'] = True
        
        # Check waybackurls (required)
        if not self.is_tool_installed('waybackurls'):
            tools_status['waybackurls'] = self.install_waybackurls()
        else:
            tools_status['waybackurls'] = True
        
        # Check hakrawler (required)
        if not self.is_tool_installed('hakrawler'):
            tools_status['hakrawler'] = self.install_hakrawl()
        else:
            tools_status['hakrawler'] = True
        
        # Check mantra (required)
        if not self.is_tool_installed('mantra'):
            tools_status['mantra'] = self.install_mantra()
        else:
            tools_status['mantra'] = True
        
        return tools_status
    
    def get_install_instructions(self) -> Dict[str, str]:
        """Get manual installation instructions for missing tools."""
        instructions = {}
        
        if not self.is_tool_installed('gau'):
            if self.os_type == 'linux':
                instructions['gau'] = """
Manual installation for gau on Linux:
1. Install Go: https://golang.org/dl/
2. Run: go install github.com/lc/gau/v2/cmd/gau@latest
3. Or download binary from: https://github.com/lc/gau/releases
"""
            elif self.os_type == 'darwin':
                instructions['gau'] = """
Manual installation for gau on macOS:
1. Install Homebrew: https://brew.sh/
2. Run: brew install gau
3. Or install Go and run: go install github.com/lc/gau/v2/cmd/gau@latest
"""
            elif self.os_type == 'windows':
                instructions['gau'] = """
Manual installation for gau on Windows:
1. Download from: https://github.com/lc/gau/releases
2. Extract gau.exe to a directory in your PATH
3. Or install Go and run: go install github.com/lc/gau/v2/cmd/gau@latest
"""
        
        if not self.is_tool_installed('waybackurls'):
            instructions['waybackurls'] = """
Manual installation for waybackurls:
1. Install Go: https://golang.org/dl/
2. Run: go install github.com/tomnomnom/waybackurls@latest
3. Or download from: https://github.com/tomnomnom/waybackurls/releases
"""
        
        if not self.is_tool_installed('hakrawler'):
            instructions['hakrawler'] = """
Manual installation for hakrawler:
1. Install Go: https://golang.org/dl/
2. Run: go install github.com/hakluke/hakrawler@latest
3. Or download from: https://github.com/hakluke/hakrawler/releases
"""
        
        if not self.is_tool_installed('mantra'):
            instructions['mantra'] = """
Manual installation for mantra:
1. Install Go: https://golang.org/dl/
2. Run: go install github.com/Brosck/mantra@latest
3. Or download from: https://github.com/Brosck/mantra/releases
"""
        
        return instructions