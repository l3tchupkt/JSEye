"""GAU (Get All URLs) integration for URL discovery."""

import asyncio
import subprocess
import tempfile
import os
from typing import List, Dict, Any, Set
from .utils import is_js_file, normalize_url


class GAUIntegration:
    """Integration with GAU tool for URL discovery."""
    
    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self.gau_available = self._check_gau_availability()
    
    def _check_gau_availability(self) -> bool:
        """Check if GAU tool is available."""
        try:
            result = subprocess.run(['gau', '--help'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False
    
    async def discover_urls(self, domain: str, include_subs: bool = True) -> List[str]:
        """Discover URLs using GAU."""
        if not self.gau_available:
            return []
        
        try:
            # Prepare GAU command
            cmd = ['gau']
            
            if include_subs:
                cmd.append('--subs')
            
            # Add other useful flags
            cmd.extend([
                '--threads', '10',
                '--timeout', '10',
                '--retries', '2'
            ])
            
            cmd.append(domain)
            
            # Run GAU
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
                    urls = stdout.decode('utf-8', errors='ignore').strip().split('\n')
                    # Filter out empty lines
                    urls = [url.strip() for url in urls if url.strip()]
                    return urls
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
    
    async def discover_js_urls(self, domain: str, include_subs: bool = True) -> List[Dict[str, Any]]:
        """Discover JavaScript URLs using GAU."""
        all_urls = await self.discover_urls(domain, include_subs)
        
        js_urls = []
        seen_urls = set()
        
        for url in all_urls:
            if url and is_js_file(url):
                normalized_url = normalize_url(url)
                if normalized_url not in seen_urls:
                    seen_urls.add(normalized_url)
                    js_urls.append({
                        'url': normalized_url,
                        'source': 'gau',
                        'domain': domain
                    })
        
        return js_urls
    
    async def discover_from_file(self, domains_file: str) -> List[Dict[str, Any]]:
        """Discover URLs from a file of domains using GAU."""
        if not self.gau_available:
            return []
        
        try:
            # Check if file exists
            if not os.path.exists(domains_file):
                return []
            
            # Run GAU with file input
            cmd = [
                'gau',
                '--subs',
                '--threads', '10',
                '--timeout', '10',
                '--retries', '2'
            ]
            
            with open(domains_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            all_js_urls = []
            
            # Process domains in batches to avoid overwhelming GAU
            batch_size = 10
            for i in range(0, len(domains), batch_size):
                batch = domains[i:i + batch_size]
                
                for domain in batch:
                    js_urls = await self.discover_js_urls(domain)
                    all_js_urls.extend(js_urls)
                
                # Small delay between batches
                await asyncio.sleep(1)
            
            return all_js_urls
            
        except Exception:
            return []
    
    async def discover_with_filters(self, domain: str, extensions: List[str] = None, 
                                  exclude_patterns: List[str] = None) -> List[Dict[str, Any]]:
        """Discover URLs with custom filters."""
        if not self.gau_available:
            return []
        
        if extensions is None:
            extensions = ['.js', '.jsx', '.ts', '.tsx']
        
        if exclude_patterns is None:
            exclude_patterns = ['node_modules', '.min.js.map', 'test/', 'spec/']
        
        all_urls = await self.discover_urls(domain)
        
        filtered_urls = []
        seen_urls = set()
        
        for url in all_urls:
            if not url:
                continue
            
            # Check extensions
            has_valid_extension = any(url.lower().endswith(ext) for ext in extensions)
            if not has_valid_extension:
                continue
            
            # Check exclude patterns
            should_exclude = any(pattern in url.lower() for pattern in exclude_patterns)
            if should_exclude:
                continue
            
            normalized_url = normalize_url(url)
            if normalized_url not in seen_urls:
                seen_urls.add(normalized_url)
                filtered_urls.append({
                    'url': normalized_url,
                    'source': 'gau_filtered',
                    'domain': domain
                })
        
        return filtered_urls
    
    async def get_gau_stats(self, domain: str) -> Dict[str, Any]:
        """Get statistics about GAU discovery for a domain."""
        if not self.gau_available:
            return {
                'gau_available': False,
                'total_urls': 0,
                'js_urls': 0,
                'error': 'GAU tool not available'
            }
        
        try:
            all_urls = await self.discover_urls(domain)
            js_urls = [url for url in all_urls if is_js_file(url)]
            
            # Analyze URL patterns
            url_extensions = {}
            url_domains = set()
            
            for url in all_urls:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    url_domains.add(parsed.netloc)
                    
                    # Extract extension
                    path = parsed.path.lower()
                    if '.' in path:
                        ext = path.split('.')[-1]
                        if len(ext) <= 5:  # Reasonable extension length
                            url_extensions[ext] = url_extensions.get(ext, 0) + 1
                except Exception:
                    continue
            
            return {
                'gau_available': True,
                'total_urls': len(all_urls),
                'js_urls': len(js_urls),
                'unique_domains': len(url_domains),
                'domains': list(url_domains),
                'extensions': dict(sorted(url_extensions.items(), 
                                        key=lambda x: x[1], reverse=True)[:10])
            }
            
        except Exception as e:
            return {
                'gau_available': True,
                'total_urls': 0,
                'js_urls': 0,
                'error': str(e)
            }
    
    def is_available(self) -> bool:
        """Check if GAU is available."""
        return self.gau_available
    
    async def run_gau_command(self, args: List[str]) -> Dict[str, Any]:
        """Run a custom GAU command with specified arguments."""
        if not self.gau_available:
            return {
                'success': False,
                'error': 'GAU tool not available',
                'output': '',
                'stderr': ''
            }
        
        try:
            cmd = ['gau'] + args
            
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
                
                return {
                    'success': process.returncode == 0,
                    'returncode': process.returncode,
                    'output': stdout.decode('utf-8', errors='ignore'),
                    'stderr': stderr.decode('utf-8', errors='ignore')
                }
                
            except asyncio.TimeoutError:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                
                return {
                    'success': False,
                    'error': 'Command timed out',
                    'output': '',
                    'stderr': ''
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'output': '',
                'stderr': ''
            }