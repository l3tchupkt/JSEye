"""Tool installer and dependency manager."""

import asyncio
import subprocess
import sys
import os
from typing import Dict, List, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from .os_detect import OSDetector

console = Console()


class ToolInstaller:
    """Manage installation of external tools and dependencies."""
    
    def __init__(self):
        self.os_detector = OSDetector()
        self.required_tools = ['gau', 'waybackurls', 'hakrawler', 'mantra', 'subfinder', 'katana']
        self.optional_tools = []  # No optional tools
        self.go_required = True  # Go is required for all tools
        self.required_packages = [
            'aiohttp', 'beautifulsoup4', 'lxml', 'jsbeautifier',
            'jinja2', 'waybackpy', 'tldextract', 'rich', 'psutil', 'requests', 'packaging',
            'pyyaml',
        ]
    
    async def install_python_packages(self, packages: List[str]) -> bool:
        """Install missing Python packages automatically."""
        if not packages:
            return True
            
        console.print(f"[yellow]Installing missing Python packages: {', '.join(packages)}")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Installing packages...", total=None)
                
                # Install packages
                cmd = [sys.executable, '-m', 'pip', 'install', '--break-system-packages'] + packages
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await result.communicate()
                progress.remove_task(task)
                
                if result.returncode == 0:
                    console.print(f"[green][+] Successfully installed: {', '.join(packages)}")
                    return True
                else:
                    console.print(f"[red][-] Failed to install packages")
                    if stderr:
                        console.print(f"[red]Error: {stderr.decode()}")
                    return False
                    
        except Exception as e:
            console.print(f"[red][-] Installation failed: {e}")
            return False
    
    async def check_and_install_python_dependencies(self) -> bool:
        """Check and automatically install Python dependencies."""
        missing_packages = []
        
        for package in self.required_packages:
            try:
                # Handle special package name mappings
                import_name = package
                if package == 'beautifulsoup4':
                    import_name = 'bs4'
                elif package == 'pillow':
                    import_name = 'PIL'
                elif package == 'pyyaml':
                    import_name = 'yaml'
                
                __import__(import_name)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            console.print(f"[yellow]Installing missing packages: {', '.join(missing_packages)}")
            success = await self.install_python_packages(missing_packages)
            if success:
                # Verify installation by re-checking imports
                still_missing = []
                for package in missing_packages:
                    try:
                        import_name = package
                        if package == 'beautifulsoup4':
                            import_name = 'bs4'
                        elif package == 'pillow':
                            import_name = 'PIL'
                        elif package == 'pyyaml':
                            import_name = 'yaml'
                        __import__(import_name)
                    except ImportError:
                        still_missing.append(package)
                
                if still_missing:
                    console.print(f"[red][-] Some packages still missing: {', '.join(still_missing)}")
                    return False
            return success
        
        # All dependencies available - no message needed
        return True
    
    async def install_external_tools(self) -> Dict[str, bool]:
        """Install external tools automatically (all are now required)."""
        results = {}
        
        # First, ensure Go is installed (silently)
        if not await self._ensure_go_installed():
            console.print("[red]! Go installation required for tools")
            return {'go': False, 'gau': False, 'waybackurls': False, 'hakrawler': False}
        
        results['go'] = True
        
        # Check and install gau (required)
        if self.os_detector.is_tool_installed('gau'):
            results['gau'] = True
        else:
            console.print("[yellow]Installing gau...")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Installing gau...", total=None)
                results['gau'] = await self._install_gau_async()
                progress.remove_task(task)
            
            if results['gau']:
                console.print("[green][+] gau installed successfully")
            else:
                console.print("[red][-] gau installation failed (required)")
        
        # Check and install waybackurls (required)
        if self.os_detector.is_tool_installed('waybackurls'):
            results['waybackurls'] = True
        else:
            console.print("[yellow]Installing waybackurls...")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Installing waybackurls...", total=None)
                results['waybackurls'] = await self._install_waybackurls_async()
                progress.remove_task(task)
            
            if results['waybackurls']:
                console.print("[green][+] waybackurls installed successfully")
            else:
                console.print("[red][-] waybackurls installation failed (required)")
        
        # Check and install hakrawler (required)
        if self.os_detector.is_tool_installed('hakrawler'):
            results['hakrawler'] = True
        else:
            console.print("[yellow]Installing hakrawler...")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Installing hakrawler...", total=None)
                results['hakrawler'] = await self._install_hakrawl_async()
                progress.remove_task(task)
            
            if results['hakrawler']:
                console.print("[green][+] hakrawler installed successfully")
            else:
                console.print("[red][-] hakrawler installation failed (required)")
        
        # Check and install mantra (required)
        if self.os_detector.is_tool_installed('mantra'):
            results['mantra'] = True
        else:
            console.print("[yellow]Installing mantra...")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Installing mantra...", total=None)
                results['mantra'] = await self._install_mantra_async()
                progress.remove_task(task)
            
            if results['mantra']:
                console.print("[green][+] mantra installed successfully")
            else:
                console.print("[red][-] mantra installation failed (required)")
        
        # Check and install subfinder (required)
        if self.os_detector.is_tool_installed('subfinder'):
            results['subfinder'] = True
        else:
            console.print("[yellow]Installing subfinder...")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Installing subfinder...", total=None)
                results['subfinder'] = await self._install_subfinder_async()
                progress.remove_task(task)
            
            if results['subfinder']:
                console.print("[green][+] subfinder installed successfully")
            else:
                console.print("[red][-] subfinder installation failed (required)")
        
        # Check and install katana (required)
        if self.os_detector.is_tool_installed('katana'):
            results['katana'] = True
        else:
            console.print("[yellow]Installing katana...")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Installing katana...", total=None)
                results['katana'] = await self._install_katana_async()
                progress.remove_task(task)
            
            if results['katana']:
                console.print("[green][+] katana installed successfully")
            else:
                console.print("[red][-] katana installation failed (required)")
        
        return results
    
    async def _install_gau_async(self) -> bool:
        """Install gau asynchronously."""
        try:
            # Method 1: Try go install first
            result = await asyncio.create_subprocess_exec(
                'go', 'install', 'github.com/lc/gau/v2/cmd/gau@latest',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode == 0 and self.os_detector.is_tool_installed('gau'):
                return True
            
            # Method 2: Try older version
            result = await asyncio.create_subprocess_exec(
                'go', 'install', 'github.com/lc/gau@latest',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode == 0 and self.os_detector.is_tool_installed('gau'):
                return True
                
        except FileNotFoundError:
            pass  # Go not installed, try other methods
        
        # Fallback to OS-specific installation
        return self.os_detector.install_gau()
    
    async def _install_waybackurls_async(self) -> bool:
        """Install waybackurls asynchronously."""
        try:
            # Method 1: Try go install
            result = await asyncio.create_subprocess_exec(
                'go', 'install', 'github.com/tomnomnom/waybackurls@latest',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode == 0 and self.os_detector.is_tool_installed('waybackurls'):
                return True
            
            # Method 2: Try go get
            result = await asyncio.create_subprocess_exec(
                'go', 'get', 'github.com/tomnomnom/waybackurls',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode == 0 and self.os_detector.is_tool_installed('waybackurls'):
                return True
            
        except FileNotFoundError:
            pass
        
        # Fallback to OS-specific installation
        return self.os_detector.install_waybackurls()
            
    async def _install_hakrawl_async(self) -> bool:
        """Install hakrawler asynchronously."""
        try:
            # Method 1: Try go install with latest version
            result = await asyncio.create_subprocess_exec(
                'go', 'install', 'github.com/hakluke/hakrawler@latest',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode == 0 and self.os_detector.is_tool_installed('hakrawler'):
                return True
            
            # Method 2: Try go get
            result = await asyncio.create_subprocess_exec(
                'go', 'get', 'github.com/hakluke/hakrawler',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode == 0 and self.os_detector.is_tool_installed('hakrawler'):
                return True
            
            # Method 3: Try alternative repository
            result = await asyncio.create_subprocess_exec(
                'go', 'install', 'github.com/hakluke/hakrawler/cmd/hakrawler@latest',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            return result.returncode == 0 and self.os_detector.is_tool_installed('hakrawler')
            
        except FileNotFoundError:
            return False
    
    async def _install_mantra_async(self) -> bool:
        """Install mantra asynchronously."""
        try:
            # Method 1: Try go install with latest version
            result = await asyncio.create_subprocess_exec(
                'go', 'install', 'github.com/Brosck/mantra@latest',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode == 0 and self.os_detector.is_tool_installed('mantra'):
                return True
            
            # Method 2: Try go get
            result = await asyncio.create_subprocess_exec(
                'go', 'get', 'github.com/Brosck/mantra',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            return result.returncode == 0 and self.os_detector.is_tool_installed('mantra')
            
        except FileNotFoundError:
            return False
    
    async def _install_subfinder_async(self) -> bool:
        """Install subfinder (ProjectDiscovery subdomain discovery tool)."""
        try:
            result = await asyncio.create_subprocess_exec(
                'go', 'install',
                'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            if result.returncode == 0 and self.os_detector.is_tool_installed('subfinder'):
                return True
            # Fallback: older path
            result = await asyncio.create_subprocess_exec(
                'go', 'install',
                'github.com/projectdiscovery/subfinder/cmd/subfinder@latest',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            return result.returncode == 0 and self.os_detector.is_tool_installed('subfinder')
        except FileNotFoundError:
            return False

    async def _install_katana_async(self) -> bool:
        """Install katana (ProjectDiscovery fast crawler with JS support)."""
        try:
            result = await asyncio.create_subprocess_exec(
                'go', 'install',
                'github.com/projectdiscovery/katana/cmd/katana@latest',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            return result.returncode == 0 and self.os_detector.is_tool_installed('katana')
        except FileNotFoundError:
            return False
    
    async def _ensure_go_installed(self) -> bool:
        """Ensure Go is installed and available."""
        # Always add Go bin to PATH first
        self._add_go_bin_to_path()
        
        # Check if Go is already installed
        try:
            result = await asyncio.create_subprocess_exec(
                'go', 'version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode == 0:
                return True
        except FileNotFoundError:
            pass
        
        # Go is not installed, try to install it
        console.print("[yellow]Go not found. Installing Go...")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Installing Go programming language...", total=None)
            
            success = await self._install_go()
            
            progress.remove_task(task)
            
            if success:
                console.print("[green][+] Go installed successfully")
                self._add_go_bin_to_path()
                return True
            else:
                console.print("[red][-] Go installation failed")
                console.print("[yellow]Please install Go manually from: https://golang.org/dl/")
                return False
    
    def _add_go_bin_to_path(self):
        """Add Go bin directory to PATH."""
        import os
        
        home_dir = os.path.expanduser('~')
        go_bin_paths = [
            os.path.join(home_dir, 'go', 'bin'),
            os.path.join('/root', 'go', 'bin'),
            os.path.join('/usr', 'local', 'go', 'bin'),
            os.path.join(home_dir, '.go', 'bin'),
            '/usr/local/go/bin',
            '/opt/go/bin'
        ]
        
        current_path = os.environ.get('PATH', '')
        paths_added = []
        
        for go_bin_path in go_bin_paths:
            if os.path.exists(go_bin_path) and go_bin_path not in current_path:
                os.environ['PATH'] = f"{go_bin_path}:{current_path}"
                current_path = os.environ['PATH']  # Update for next iteration
                paths_added.append(go_bin_path)
        
        if paths_added:
            console.print(f"[cyan]Added Go bin directories to PATH: {', '.join(paths_added)}")
    
    async def _install_go(self) -> bool:
        """Install Go programming language."""
        try:
            os_detector = self.os_detector
            
            if os_detector.os_type == 'linux':
                return await self._install_go_linux()
            elif os_detector.os_type == 'darwin':
                return await self._install_go_macos()
            elif os_detector.os_type == 'windows':
                return await self._install_go_windows()
            else:
                console.print(f"[red]Unsupported OS for Go installation: {os_detector.os_type}")
                return False
                
        except Exception as e:
            console.print(f"[red]Go installation failed: {e}")
            return False
    
    async def _install_go_linux(self) -> bool:
        """Install Go on Linux."""
        try:
            import tempfile
            import os
            
            # Determine architecture
            arch_map = {'x86_64': 'amd64', 'aarch64': 'arm64'}
            arch = arch_map.get(self.os_detector.arch, 'amd64')
            
            # Download Go
            go_version = "1.21.5"  # Use a stable version
            go_url = f"https://golang.org/dl/go{go_version}.linux-{arch}.tar.gz"
            
            with tempfile.TemporaryDirectory() as temp_dir:
                go_tar = os.path.join(temp_dir, 'go.tar.gz')
                
                # Download Go
                result = await asyncio.create_subprocess_exec(
                    'curl', '-L', '-o', go_tar, go_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()
                
                if result.returncode != 0 or not os.path.exists(go_tar):
                    return False
                
                # Install to user directory
                home_dir = os.path.expanduser('~')
                go_root = os.path.join(home_dir, 'go')
                
                # Remove existing Go installation
                if os.path.exists(go_root):
                    import shutil
                    shutil.rmtree(go_root)
                
                # Extract Go
                result = await asyncio.create_subprocess_exec(
                    'tar', '-C', home_dir, '-xzf', go_tar,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()
                
                if result.returncode != 0:
                    return False
                
                # Add Go to PATH
                go_bin = os.path.join(go_root, 'bin')
                current_path = os.environ.get('PATH', '')
                
                if go_bin not in current_path:
                    os.environ['PATH'] = f"{go_bin}:{current_path}"
                    
                    # Also add GOPATH
                    gopath = os.path.join(home_dir, 'go-workspace')
                    os.makedirs(gopath, exist_ok=True)
                    os.environ['GOPATH'] = gopath
                    os.environ['GOROOT'] = go_root
                
                # Verify installation
                try:
                    result = await asyncio.create_subprocess_exec(
                        os.path.join(go_bin, 'go'), 'version',
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await result.communicate()
                    
                    if result.returncode == 0:
                        console.print(f"[green]Go installed to {go_root}")
                        console.print(f"[yellow]Add {go_bin} to your PATH permanently")
                        return True
                except Exception:
                    pass
                
                return False
                
        except Exception as e:
            console.print(f"[red]Go Linux installation failed: {e}")
            return False
    
    async def _install_go_macos(self) -> bool:
        """Install Go on macOS."""
        try:
            # Try Homebrew first
            result = await asyncio.create_subprocess_exec(
                'brew', 'install', 'go',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode == 0:
                return True
                
        except FileNotFoundError:
            pass
        
        # Fallback to manual installation similar to Linux
        return await self._install_go_linux()
    
    async def _install_go_windows(self) -> bool:
        """Install Go on Windows."""
        try:
            import tempfile
            import urllib.request
            import subprocess
            
            # Determine architecture
            arch = 'amd64' if '64' in self.os_detector.arch else '386'
            
            # Download Go installer
            go_version = "1.21.5"
            go_url = f"https://golang.org/dl/go{go_version}.windows-{arch}.msi"
            
            with tempfile.TemporaryDirectory() as temp_dir:
                go_msi = os.path.join(temp_dir, 'go.msi')
                
                # Download Go installer
                urllib.request.urlretrieve(go_url, go_msi)
                
                # Install Go silently
                result = await asyncio.create_subprocess_exec(
                    'msiexec', '/i', go_msi, '/quiet',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()
                
                return result.returncode == 0
                
        except Exception as e:
            console.print(f"[red]Go Windows installation failed: {e}")
            return False
    
    async def install_playwright(self) -> bool:
        """Install Playwright browsers if needed."""
        try:
            import playwright
            
            console.print("[yellow]Installing Playwright browsers...")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Installing Chromium browser...", total=None)
                
                result = await asyncio.create_subprocess_exec(
                    sys.executable, '-m', 'playwright', 'install', 'chromium',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()
                progress.remove_task(task)
                
                if result.returncode == 0:
                    console.print("[green][+] Playwright browsers installed")
                    return True
                else:
                    console.print("[red][-] Playwright browser installation failed")
                    return False
            
        except ImportError:
            console.print("[yellow]Playwright not installed. Install with: pip install playwright")
            return False
        except Exception as e:
            console.print(f"[red]Failed to install Playwright browsers: {e}")
            return False
    
    async def verify_tools(self) -> Dict[str, bool]:
        """Verify all tools are working correctly."""
        results = {}
        
        console.print("[cyan]Verifying tool installations...")
        
        # Test gau
        try:
            result = await asyncio.create_subprocess_exec(
                'gau', '--help',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            results['gau'] = result.returncode == 0
        except Exception:
            results['gau'] = False
        
        # Test waybackurls
        try:
            result = await asyncio.create_subprocess_exec(
                'waybackurls', '--help',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            results['waybackurls'] = result.returncode == 0
        except Exception:
            results['waybackurls'] = False
        
        return results
    
    async def setup_environment(self, auto_install: bool = True) -> bool:
        """Set up the complete environment for JSEye."""
        success = True
        
        if auto_install:
            # Check Python dependencies silently
            if not await self.check_and_install_python_dependencies():
                success = False
            
            # Check and install external tools (all are now required)
            tools_status = await self.install_external_tools()
            
            # Check if any required tools failed
            failed_tools = [tool for tool, status in tools_status.items() if not status]
            if failed_tools:
                console.print(f"[red][-] Required tools installation failed: {', '.join(failed_tools)}")
                console.print("[red][-] Cannot continue without required tools")
                success = False
        else:
            # Just check without installing
            missing_packages = []
            for package in self.required_packages:
                try:
                    # Handle special package name mappings
                    import_name = package
                    if package == 'beautifulsoup4':
                        import_name = 'bs4'
                    elif package == 'pillow':
                        import_name = 'PIL'
                    
                    __import__(import_name)
                except ImportError:
                    missing_packages.append(package)
            
            if missing_packages:
                console.print(f"[red]Missing Python packages: {', '.join(missing_packages)}")
                console.print(f"[yellow]Install with: pip install {' '.join(missing_packages)}")
                success = False
            
            missing_tools = self.get_missing_tools()
            if missing_tools:
                console.print(f"[red]Missing required tools: {', '.join(missing_tools)}")
                success = False
        
        return success
    
    def get_missing_tools(self) -> List[str]:
        """Get list of missing required tools."""
        missing = []
        for tool in self.required_tools:
            if not self.os_detector.is_tool_installed(tool):
                missing.append(tool)
        return missing
    
    def can_run_headless(self) -> bool:
        """Check if headless mode is available."""
        try:
            import playwright
            return True
        except ImportError:
            return False