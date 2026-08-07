"""Wayback Machine integration for historical JavaScript discovery."""

import asyncio
import aiohttp
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, urljoin
import json
from waybackpy import WaybackMachineCDXServerAPI
from .utils import normalize_url, is_js_file, extract_domain


class WaybackIntegration:
    """Integration with Wayback Machine for historical JS discovery."""
    
    def __init__(self, timeout: int = 30, max_concurrent: int = 10):
        self.timeout = timeout  # Keep as integer
        self.max_concurrent = max_concurrent
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': 'JSEye/1.0.0 Security Research Tool'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def discover_historical_js(self, domain: str, limit: int = 1000) -> List[Dict[str, Any]]:
        """Discover historical JavaScript files for a domain."""
        try:
            # Get historical URLs from Wayback Machine
            historical_urls = await self._get_wayback_urls(domain, limit)
            
            # Filter for JavaScript files
            js_urls = self._filter_js_urls(historical_urls)
            
            # Get unique JS files
            unique_js_files = await self._get_unique_js_files(js_urls)
            
            return unique_js_files
            
        except Exception as e:
            return []
    
    async def _get_wayback_urls(self, domain: str, limit: int) -> List[Dict[str, Any]]:
        """Get URLs from Wayback Machine CDX API."""
        wayback_urls = []
        
        try:
            # Use waybackpy for initial discovery
            cdx_api = WaybackMachineCDXServerAPI(
                url=f"*.{domain}/*",
                user_agent="JSEye/1.0.0",
                start_timestamp="20100101",
                end_timestamp="20241231"
            )
            
            # Get snapshots
            snapshots = []
            try:
                for snapshot in cdx_api.snapshots():
                    snapshots.append({
                        'url': snapshot.original,
                        'timestamp': snapshot.timestamp,
                        'status_code': snapshot.statuscode,
                        'mimetype': snapshot.mimetype
                    })
                    
                    if len(snapshots) >= limit:
                        break
                        
            except Exception:
                # If waybackpy fails, try direct CDX API
                snapshots = await self._query_cdx_api_direct(domain, limit)
            
            wayback_urls.extend(snapshots)
            
        except Exception as e:
            # Fallback to direct CDX API query
            try:
                wayback_urls = await self._query_cdx_api_direct(domain, limit)
            except Exception:
                pass
        
        return wayback_urls
    
    async def _query_cdx_api_direct(self, domain: str, limit: int) -> List[Dict[str, Any]]:
        """Query Wayback CDX API directly."""
        urls = []
        
        try:
            # CDX API endpoint
            cdx_url = "http://web.archive.org/cdx/search/cdx"
            
            params = {
                'url': f"*.{domain}/*",
                'output': 'json',
                'fl': 'original,timestamp,statuscode,mimetype',
                'filter': 'statuscode:200',
                'collapse': 'original',
                'limit': limit
            }
            
            async with self.session.get(cdx_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Skip header row
                    if data and len(data) > 1:
                        for row in data[1:]:
                            if len(row) >= 4:
                                urls.append({
                                    'url': row[0],
                                    'timestamp': row[1],
                                    'status_code': row[2],
                                    'mimetype': row[3] if len(row) > 3 else ''
                                })
        
        except Exception:
            pass
        
        return urls
    
    def _filter_js_urls(self, urls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter URLs to only include JavaScript files."""
        js_urls = []
        
        for url_info in urls:
            url = url_info.get('url', '')
            mimetype = url_info.get('mimetype', '').lower()
            
            # Check if it's a JavaScript file
            if (is_js_file(url) or 
                'javascript' in mimetype or 
                'application/javascript' in mimetype or
                'text/javascript' in mimetype):
                
                js_urls.append(url_info)
        
        return js_urls
    
    async def _get_unique_js_files(self, js_urls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get unique JavaScript files from Wayback Machine."""
        unique_files = []
        seen_urls = set()
        
        # Limit concurrent requests
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def fetch_js_file(url_info):
            async with semaphore:
                return await self._fetch_wayback_js(url_info)
        
        # Process in batches to avoid overwhelming the API
        batch_size = 20
        for i in range(0, len(js_urls), batch_size):
            batch = js_urls[i:i + batch_size]
            
            tasks = []
            for url_info in batch:
                url = url_info.get('url', '')
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    tasks.append(fetch_js_file(url_info))
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, dict) and result.get('content'):
                        unique_files.append(result)
            
            # Small delay between batches
            await asyncio.sleep(0.5)
        
        return unique_files
    
    async def _fetch_wayback_js(self, url_info: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch JavaScript file from Wayback Machine."""
        try:
            original_url = url_info.get('url', '')
            timestamp = url_info.get('timestamp', '')
            
            if not original_url or not timestamp:
                return {}
            
            # Construct Wayback Machine URL
            wayback_url = f"http://web.archive.org/web/{timestamp}id_/{original_url}"
            
            async with self.session.get(wayback_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Basic validation
                    if content and len(content.strip()) > 50:
                        return {
                            'url': original_url,
                            'wayback_url': wayback_url,
                            'timestamp': timestamp,
                            'content': content,
                            'size': len(content),
                            'source': 'wayback'
                        }
        
        except Exception:
            pass
        
        return {}
    
    async def get_wayback_snapshots(self, url: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get available snapshots for a specific URL."""
        snapshots = []
        
        try:
            cdx_api = WaybackMachineCDXServerAPI(
                url=url,
                user_agent="JSEye/1.0.0"
            )
            
            for snapshot in cdx_api.snapshots():
                snapshots.append({
                    'url': snapshot.original,
                    'wayback_url': snapshot.archive_url,
                    'timestamp': snapshot.timestamp,
                    'status_code': snapshot.statuscode,
                    'mimetype': snapshot.mimetype
                })
                
                if len(snapshots) >= limit:
                    break
                    
        except Exception:
            pass
        
        return snapshots
    
    async def search_wayback_js_by_pattern(self, domain: str, pattern: str, limit: int = 500) -> List[Dict[str, Any]]:
        """Search for JavaScript files matching a pattern in Wayback Machine."""
        try:
            # Get all historical URLs
            historical_urls = await self._get_wayback_urls(domain, limit * 2)
            
            # Filter by pattern
            matching_urls = []
            for url_info in historical_urls:
                url = url_info.get('url', '')
                if pattern.lower() in url.lower() and is_js_file(url):
                    matching_urls.append(url_info)
            
            # Get unique files
            unique_files = await self._get_unique_js_files(matching_urls[:limit])
            
            return unique_files
            
        except Exception:
            return []
    
    def get_wayback_stats(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get statistics about Wayback Machine results."""
        if not results:
            return {
                'total_files': 0,
                'total_size': 0,
                'date_range': {},
                'unique_domains': 0
            }
        
        total_size = sum(item.get('size', 0) for item in results)
        
        # Extract timestamps and convert to dates
        timestamps = [item.get('timestamp', '') for item in results if item.get('timestamp')]
        dates = []
        for ts in timestamps:
            if len(ts) >= 8:
                try:
                    date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                    dates.append(date)
                except Exception:
                    pass
        
        # Get unique domains
        domains = set()
        for item in results:
            url = item.get('url', '')
            if url:
                try:
                    parsed = urlparse(url)
                    domains.add(parsed.netloc)
                except Exception:
                    pass
        
        return {
            'total_files': len(results),
            'total_size': total_size,
            'average_size': total_size // len(results) if results else 0,
            'date_range': {
                'earliest': min(dates) if dates else '',
                'latest': max(dates) if dates else '',
                'span_days': len(set(dates))
            },
            'unique_domains': len(domains),
            'domains': list(domains)
        }