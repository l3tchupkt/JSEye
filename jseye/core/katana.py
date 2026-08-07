"""
Katana Integration for JSEye
Fast web crawler for discovering URLs and endpoints
"""

import asyncio
import subprocess
from typing import List, Dict, Any


class KatanaIntegration:
    """Integration with Katana for fast web crawling."""
    
    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self.katana_available = self._check_katana_availability()
    
    def _check_katana_availability(self) -> bool:
        """Check if katana is installed."""
        try:
            result = subprocess.run(
                ['katana', '-version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    async def crawl_target(self, target: str, depth: int = 5) -> List[str]:
        """Crawl target and discover URLs."""
        if not self.katana_available:
            return []
        
        try:
            # Prepare katana command with deeper crawling
            cmd = [
                'katana',
                '-u', target,
                '-d', str(depth),
                '-jc',  # JavaScript crawling
                '-kf', 'all',  # Known files
                '-silent',
                '-no-color'
            ]
            
            # Run katana
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
                    urls = [url.strip() for url in urls if url.strip()]
                    return urls
                else:
                    return []
                    
            except asyncio.TimeoutError:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                return []
                
        except Exception:
            return []
    
    async def crawl_with_js_focus(self, target: str) -> Dict[str, Any]:
        """Crawl target with focus on JavaScript files."""
        if not self.katana_available:
            return {
                'success': False,
                'error': 'Katana not available',
                'urls': [],
                'js_urls': []
            }
        
        try:
            # Crawl with depth 5 for deeper discovery
            all_urls = await self.crawl_target(target, depth=5)
            
            # Filter for JS files
            js_urls = []
            other_urls = []
            
            for url in all_urls:
                if url.endswith('.js') or '/js/' in url or 'javascript' in url.lower():
                    js_urls.append({'url': url, 'source': 'katana'})
                else:
                    other_urls.append(url)
            
            return {
                'success': True,
                'urls': all_urls,
                'js_urls': js_urls,
                'other_urls': other_urls,
                'total_count': len(all_urls),
                'js_count': len(js_urls)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'urls': [],
                'js_urls': []
            }
    
    def is_available(self) -> bool:
        """Check if katana is available."""
        return self.katana_available
