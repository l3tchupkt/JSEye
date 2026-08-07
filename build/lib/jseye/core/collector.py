"""JavaScript file collection and extraction engine."""

import asyncio
import aiohttp
import re
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from .utils import normalize_url, calculate_sha256, is_js_file, is_map_file, extract_domain


class JSCollector:
    """Collect JavaScript files from web pages and various sources."""
    
    def __init__(self, timeout: int = 10, max_concurrent: int = 20):
        self.timeout = timeout  # Keep as integer
        self.max_concurrent = max_concurrent
        self.session = None
        self.collected_js = {}
        self.collected_hashes = set()
        
    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def collect_from_url(self, url: str) -> Dict[str, Any]:
        """Collect JavaScript files from a single URL."""
        try:
            # Normalize URL
            url = normalize_url(url)
            
            # Fetch the main page
            async with self.session.get(url) as response:
                if response.status != 200:
                    return {
                        'url': url,
                        'status': 'error',
                        'error': f'HTTP {response.status}',
                        'js_files': []
                    }
                
                content = await response.text()
                content_type = response.headers.get('content-type', '').lower()
                
                # If this is already a JS file
                if 'javascript' in content_type or is_js_file(url):
                    js_info = await self._process_js_content(content, url)
                    return {
                        'url': url,
                        'status': 'success',
                        'js_files': [js_info] if js_info else []
                    }
                
                # Parse HTML to find JS files
                js_files = await self._extract_js_from_html(content, url)
                
                return {
                    'url': url,
                    'status': 'success',
                    'js_files': js_files
                }
                
        except asyncio.TimeoutError:
            return {
                'url': url,
                'status': 'error',
                'error': 'Timeout',
                'js_files': []
            }
        except Exception as e:
            return {
                'url': url,
                'status': 'error',
                'error': str(e),
                'js_files': []
            }
    
    async def collect_from_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Collect JavaScript files from multiple URLs."""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def collect_single(url):
            async with semaphore:
                return await self.collect_from_url(url)
        
        tasks = [collect_single(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    'url': urls[i],
                    'status': 'error',
                    'error': str(result),
                    'js_files': []
                })
            else:
                processed_results.append(result)
        
        return processed_results
    
    async def _extract_js_from_html(self, html_content: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract JavaScript files from HTML content."""
        js_files = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract script tags with src
            script_tags = soup.find_all('script', src=True)
            for script in script_tags:
                src = script.get('src')
                if src:
                    js_url = urljoin(base_url, src)
                    js_info = await self._fetch_js_file(js_url)
                    if js_info:
                        js_files.append(js_info)
            
            # Extract inline scripts
            inline_scripts = soup.find_all('script', src=False)
            for i, script in enumerate(inline_scripts):
                if script.string and len(script.string.strip()) > 50:
                    js_info = await self._process_js_content(
                        script.string, 
                        f"{base_url}#inline-{i}"
                    )
                    if js_info:
                        js_files.append(js_info)
            
            # Extract preload/prefetch scripts
            preload_links = soup.find_all('link', rel=['preload', 'prefetch'])
            for link in preload_links:
                if link.get('as') == 'script' or is_js_file(link.get('href', '')):
                    href = link.get('href')
                    if href:
                        js_url = urljoin(base_url, href)
                        js_info = await self._fetch_js_file(js_url)
                        if js_info:
                            js_files.append(js_info)
            
            # Look for dynamically loaded scripts in existing JS
            for js_file in js_files[:]:  # Copy list to avoid modification during iteration
                if js_file.get('content'):
                    dynamic_scripts = self._extract_dynamic_scripts(js_file['content'], base_url)
                    for dynamic_url in dynamic_scripts:
                        dynamic_js = await self._fetch_js_file(dynamic_url)
                        if dynamic_js:
                            js_files.append(dynamic_js)
            
        except Exception as e:
            # If HTML parsing fails, try to extract JS URLs with regex
            js_urls = self._extract_js_urls_regex(html_content, base_url)
            for js_url in js_urls:
                js_info = await self._fetch_js_file(js_url)
                if js_info:
                    js_files.append(js_info)
        
        return js_files
    
    async def _fetch_js_file(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch a single JavaScript file."""
        try:
            url = normalize_url(url)
            
            async with self.session.get(url) as response:
                if response.status != 200:
                    return None
                
                content = await response.text()
                return await self._process_js_content(content, url)
                
        except Exception:
            return None
    
    async def _process_js_content(self, content: str, url: str) -> Optional[Dict[str, Any]]:
        """Process JavaScript content and create file info."""
        if not content or len(content.strip()) < 10:
            return None
        
        # Calculate hash for deduplication
        content_hash = calculate_sha256(content)
        
        # Skip if already processed
        if content_hash in self.collected_hashes:
            return None
        
        self.collected_hashes.add(content_hash)
        
        # Check for source map
        source_map_url = self._extract_source_map_url(content, url)
        
        js_info = {
            'url': url,
            'content': content,
            'size': len(content),
            'hash': content_hash,
            'source_map': source_map_url,
            'type': self._detect_js_type(content, url)
        }
        
        # Store in collected_js for later reference
        self.collected_js[content_hash] = js_info
        
        return js_info
    
    def _extract_dynamic_scripts(self, js_content: str, base_url: str) -> List[str]:
        """Extract dynamically loaded script URLs from JavaScript content."""
        dynamic_urls = []
        
        patterns = [
            # Dynamic imports
            r'import\s*\(\s*["\']([^"\']+\.js[^"\']*)["\']',
            # Script tag creation
            r'createElement\s*\(\s*["\']script["\'][\s\S]*?src\s*=\s*["\']([^"\']+)["\']',
            # jQuery script loading
            r'\$\.getScript\s*\(\s*["\']([^"\']+)["\']',
            # RequireJS
            r'require\s*\(\s*\[\s*["\']([^"\']+\.js[^"\']*)["\']',
            # General script URLs in strings
            r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if match and not match.startswith(('http://', 'https://')):
                    full_url = urljoin(base_url, match)
                    if is_js_file(full_url):
                        dynamic_urls.append(full_url)
                elif is_js_file(match):
                    dynamic_urls.append(match)
        
        return list(set(dynamic_urls))  # Remove duplicates
    
    def _extract_js_urls_regex(self, html_content: str, base_url: str) -> List[str]:
        """Extract JavaScript URLs using regex patterns."""
        js_urls = []
        
        patterns = [
            # Script src attributes
            r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
            # Preload/prefetch for scripts
            r'<link[^>]+rel\s*=\s*["\'](?:preload|prefetch)["\'][^>]+href\s*=\s*["\']([^"\']+\.js[^"\']*)["\']',
            # Direct JS file references
            r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if match:
                    if not match.startswith(('http://', 'https://')):
                        full_url = urljoin(base_url, match)
                    else:
                        full_url = match
                    
                    if is_js_file(full_url):
                        js_urls.append(full_url)
        
        return list(set(js_urls))  # Remove duplicates
    
    def _extract_source_map_url(self, js_content: str, js_url: str) -> Optional[str]:
        """Extract source map URL from JavaScript content."""
        # Look for source map comment
        sourcemap_pattern = r'//[@#]\s*sourceMappingURL=([^\s]+)'
        match = re.search(sourcemap_pattern, js_content)
        
        if match:
            map_url = match.group(1)
            if not map_url.startswith(('http://', 'https://')):
                map_url = urljoin(js_url, map_url)
            return map_url
        
        # Try conventional .map file
        if js_url.endswith('.js'):
            potential_map_url = js_url + '.map'
            return potential_map_url
        
        return None
    
    def _detect_js_type(self, content: str, url: str) -> str:
        """Detect the type of JavaScript file."""
        content_lower = content.lower()
        url_lower = url.lower()
        
        # Check URL patterns first
        if 'jquery' in url_lower:
            return 'jquery'
        elif 'react' in url_lower:
            return 'react'
        elif 'angular' in url_lower:
            return 'angular'
        elif 'vue' in url_lower:
            return 'vue'
        elif 'bootstrap' in url_lower:
            return 'bootstrap'
        elif 'lodash' in url_lower or 'underscore' in url_lower:
            return 'utility'
        elif '.min.js' in url_lower:
            return 'minified'
        elif 'bundle' in url_lower or 'chunk' in url_lower:
            return 'bundled'
        
        # Check content patterns
        if 'jquery' in content_lower and 'function($' in content_lower:
            return 'jquery'
        elif 'react' in content_lower and ('jsx' in content_lower or 'createelement' in content_lower):
            return 'react'
        elif 'angular' in content_lower and 'module' in content_lower:
            return 'angular'
        elif 'vue' in content_lower and ('template' in content_lower or 'component' in content_lower):
            return 'vue'
        elif len(content) > 10000 and '\n' not in content[:1000]:
            return 'minified'
        elif 'webpack' in content_lower or '__webpack_require__' in content_lower:
            return 'webpack_bundle'
        elif 'define(' in content and 'require(' in content:
            return 'amd'
        elif 'module.exports' in content or 'exports.' in content:
            return 'commonjs'
        elif 'import ' in content and 'export ' in content:
            return 'es6_module'
        
        return 'unknown'
    
    async def fetch_source_maps(self, js_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fetch source map files for JavaScript files."""
        source_maps = []
        
        for js_file in js_files:
            source_map_url = js_file.get('source_map')
            if source_map_url:
                try:
                    async with self.session.get(source_map_url) as response:
                        if response.status == 200:
                            map_content = await response.text()
                            source_maps.append({
                                'url': source_map_url,
                                'js_file': js_file['url'],
                                'content': map_content,
                                'size': len(map_content)
                            })
                except Exception:
                    continue
        
        return source_maps
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the collection process."""
        total_files = len(self.collected_js)
        total_size = sum(js_info['size'] for js_info in self.collected_js.values())
        
        type_counts = {}
        for js_info in self.collected_js.values():
            js_type = js_info.get('type', 'unknown')
            type_counts[js_type] = type_counts.get(js_type, 0) + 1
        
        return {
            'total_files': total_files,
            'total_size': total_size,
            'average_size': total_size // total_files if total_files > 0 else 0,
            'type_distribution': type_counts,
            'unique_hashes': len(self.collected_hashes)
        }