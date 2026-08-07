"""
Hakrawler Integration for JSEye
Fast web crawler for discovering URLs and endpoints
"""

import asyncio
import subprocess
from typing import List, Dict, Any


class HakrawlerIntegration:
    """Integration with hakrawler for web crawling."""
    
    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self.hakrawler_available = self._check_hakrawler_availability()
    
    def _check_hakrawler_availability(self) -> bool:
        """Check if hakrawler is installed."""
        try:
            result = subprocess.run(
                ['hakrawler', '-h'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    async def crawl_target(self, target: str, depth: int = 3) -> List[str]:
        """Crawl target and discover URLs."""
        if not self.hakrawler_available:
            return []
        
        try:
            # Prepare hakrawler command with deeper crawling
            cmd = ['hakrawler', '-url', target, '-depth', str(depth), '-plain']
            
            # Run hakrawler
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
        if not self.hakrawler_available:
            return {
                'success': False,
                'error': 'Hakrawler not available',
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
                    js_urls.append({'url': url, 'source': 'hakrawler'})
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
        """Check if hakrawler is available."""
        return self.hakrawler_available
