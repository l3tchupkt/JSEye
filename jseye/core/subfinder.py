"""
Subfinder Integration for JSEye
Discovers subdomains using subfinder tool
"""

import asyncio
import subprocess
from typing import List, Dict, Any, Optional


class SubfinderIntegration:
    """Integration with subfinder for subdomain discovery."""
    
    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self.subfinder_available = self._check_subfinder_availability()
    
    def _check_subfinder_availability(self) -> bool:
        """Check if subfinder is installed."""
        try:
            result = subprocess.run(
                ['subfinder', '-version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    async def discover_subdomains(self, domain: str, silent: bool = True) -> List[str]:
        """Discover subdomains using subfinder."""
        if not self.subfinder_available:
            return []
        
        try:
            # Prepare subfinder command
            cmd = ['subfinder', '-d', domain]
            
            if silent:
                cmd.append('-silent')
            
            # Add other useful flags
            cmd.extend([
                '-all',  # Use all sources
                '-recursive',  # Recursive enumeration
                '-timeout', '5'  # Timeout per source
            ])
            
            # Run subfinder
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=self.timeout
                )
                
                if process.returncode == 0:
                    subdomains = stdout.decode('utf-8', errors='ignore').strip().split('\n')
                    # Filter out empty lines and add https://
                    subdomains = [f"https://{sub.strip()}" for sub in subdomains if sub.strip()]
                    return subdomains
                else:
                    return []
                    
            except asyncio.TimeoutError:
                # Kill the process if it times out
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                return []
                
        except Exception:
            return []
    
    async def discover_with_sources(self, domain: str, sources: List[str] = None) -> Dict[str, Any]:
        """Discover subdomains with specific sources."""
        if not self.subfinder_available:
            return {
                'success': False,
                'error': 'Subfinder not available',
                'subdomains': []
            }
        
        try:
            cmd = ['subfinder', '-d', domain, '-silent']
            
            if sources:
                cmd.extend(['-sources', ','.join(sources)])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
                
                subdomains = []
                if process.returncode == 0:
                    subdomains = stdout.decode('utf-8', errors='ignore').strip().split('\n')
                    subdomains = [f"https://{sub.strip()}" for sub in subdomains if sub.strip()]
                
                return {
                    'success': process.returncode == 0,
                    'subdomains': subdomains,
                    'count': len(subdomains)
                }
                
            except asyncio.TimeoutError:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                return {
                    'success': False,
                    'error': 'Timeout',
                    'subdomains': []
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'subdomains': []
            }
    
    def is_available(self) -> bool:
        """Check if subfinder is available."""
        return self.subfinder_available
