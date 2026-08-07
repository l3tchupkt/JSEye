"""
Source Map Detection and Fetching
Detects and fetches .map files for JavaScript files
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Any, Optional


class SourceMapDetector:
    """Detect and fetch source map files for JavaScript."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def detect_sourcemap_url(self, js_content: str, js_url: str) -> Optional[str]:
        """Detect source map URL from JS content or URL."""
        # Check for sourceMappingURL comment
        patterns = [
            r'//[@#]\s*sourceMappingURL=(.+?)(?:\s|$)',
            r'/\*[@#]\s*sourceMappingURL=(.+?)\s*\*/',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, js_content)
            if match:
                map_url = match.group(1).strip()
                
                # Handle relative URLs
                if not map_url.startswith(('http://', 'https://')):
                    # Resolve relative to JS file URL
                    if js_url.endswith('.js'):
                        base_url = js_url.rsplit('/', 1)[0]
                        map_url = f"{base_url}/{map_url}"
                    else:
                        map_url = f"{js_url}/{map_url}"
                
                return map_url
        
        # Try common convention: filename.js.map
        if js_url.endswith('.js'):
            return f"{js_url}.map"
        
        return None
    
    async def fetch_sourcemap(self, map_url: str) -> Optional[Dict[str, Any]]:
        """Fetch source map file."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    map_url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={'User-Agent': 'Mozilla/5.0'}
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        return {
                            'url': map_url,
                            'content': content,
                            'size': len(content),
                            'status': 'success'
                        }
        except Exception:
            pass
        
        return None
    
    async def discover_and_fetch_sourcemaps(
        self, 
        js_files: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Discover and fetch source maps for all JS files."""
        sourcemaps = []
        stats = {
            'total_js_files': len(js_files),
            'maps_detected': 0,
            'maps_fetched': 0,
            'maps_failed': 0
        }
        
        tasks = []
        for js_file in js_files:
            js_url = js_file.get('url', '')
            js_content = js_file.get('content', '')
            
            if js_url and js_content:
                map_url = self.detect_sourcemap_url(js_content, js_url)
                if map_url:
                    stats['maps_detected'] += 1
                    tasks.append(self._fetch_with_metadata(map_url, js_url))
        
        # Fetch all source maps concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict) and result.get('status') == 'success':
                    sourcemaps.append(result)
                    stats['maps_fetched'] += 1
                else:
                    stats['maps_failed'] += 1
        
        return {
            'sourcemaps': sourcemaps,
            'statistics': stats
        }
    
    async def _fetch_with_metadata(self, map_url: str, js_url: str) -> Dict[str, Any]:
        """Fetch source map with metadata."""
        result = await self.fetch_sourcemap(map_url)
        if result:
            result['source_js'] = js_url
            return result
        return {'status': 'failed', 'url': map_url}
    
    def extract_original_sources(self, sourcemap_content: str) -> List[str]:
        """Extract original source file paths from source map."""
        import json
        
        try:
            sourcemap = json.loads(sourcemap_content)
            sources = sourcemap.get('sources', [])
            return sources
        except Exception:
            return []
