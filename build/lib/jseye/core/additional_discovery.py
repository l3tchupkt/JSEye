"""
Additional Discovery Features
CSS analysis, HTML parsing, robots.txt, sitemap.xml, and more
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Any, Set
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET


class AdditionalDiscovery:
    """Additional discovery methods for comprehensive coverage."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    async def discover_from_robots_txt(self, base_url: str) -> Dict[str, Any]:
        """Discover URLs from robots.txt."""
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    robots_url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={'User-Agent': 'Mozilla/5.0'}
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Extract disallowed paths (often interesting)
                        disallowed = re.findall(r'Disallow:\s*(.+)', content, re.IGNORECASE)
                        
                        # Extract sitemaps
                        sitemaps = re.findall(r'Sitemap:\s*(.+)', content, re.IGNORECASE)
                        
                        # Convert to full URLs
                        urls = []
                        for path in disallowed:
                            path = path.strip()
                            if path and path != '/':
                                full_url = urljoin(base_url, path)
                                urls.append(full_url)
                        
                        return {
                            'success': True,
                            'urls': urls,
                            'sitemaps': [s.strip() for s in sitemaps],
                            'disallowed_count': len(disallowed)
                        }
        except Exception:
            pass
        
        return {'success': False, 'urls': [], 'sitemaps': []}
    
    async def discover_from_sitemap(self, sitemap_url: str) -> List[str]:
        """Discover URLs from sitemap.xml."""
        urls = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    sitemap_url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={'User-Agent': 'Mozilla/5.0'}
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Parse XML
                        try:
                            root = ET.fromstring(content)
                            
                            # Handle different sitemap formats
                            namespaces = {
                                'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'
                            }
                            
                            # Find all <loc> tags
                            for loc in root.findall('.//sm:loc', namespaces):
                                if loc.text:
                                    urls.append(loc.text.strip())
                            
                            # Also try without namespace
                            if not urls:
                                for loc in root.findall('.//loc'):
                                    if loc.text:
                                        urls.append(loc.text.strip())
                        except Exception:
                            # Try regex fallback
                            url_matches = re.findall(r'<loc>([^<]+)</loc>', content)
                            urls.extend(url_matches)
        except Exception:
            pass
        
        return urls
    
    async def analyze_css_files(self, css_urls: List[str]) -> Dict[str, Any]:
        """Analyze CSS files for URLs and endpoints."""
        findings = {
            'urls': set(),
            'images': set(),
            'fonts': set(),
            'imports': set()
        }
        
        for css_url in css_urls[:50]:  # Limit to 50 CSS files
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        css_url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        headers={'User-Agent': 'Mozilla/5.0'}
                    ) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Extract URLs from url()
                            url_matches = re.findall(r'url\(["\']?([^"\'()]+)["\']?\)', content)
                            for url in url_matches:
                                url = url.strip()
                                if url.startswith('data:'):
                                    continue
                                
                                full_url = urljoin(css_url, url)
                                findings['urls'].add(full_url)
                                
                                # Categorize
                                if any(ext in url.lower() for ext in ['.jpg', '.png', '.gif', '.svg', '.webp']):
                                    findings['images'].add(full_url)
                                elif any(ext in url.lower() for ext in ['.woff', '.woff2', '.ttf', '.eot']):
                                    findings['fonts'].add(full_url)
                            
                            # Extract @import
                            import_matches = re.findall(r'@import\s+["\']([^"\']+)["\']', content)
                            for imp in import_matches:
                                full_url = urljoin(css_url, imp.strip())
                                findings['imports'].add(full_url)
            except Exception:
                continue
        
        return {
            'urls': list(findings['urls']),
            'images': list(findings['images']),
            'fonts': list(findings['fonts']),
            'imports': list(findings['imports']),
            'total': len(findings['urls'])
        }
    
    async def parse_html_for_resources(self, html_url: str) -> Dict[str, Any]:
        """Parse HTML for all resources."""
        resources = {
            'scripts': set(),
            'stylesheets': set(),
            'images': set(),
            'links': set(),
            'forms': [],
            'meta_tags': []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    html_url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={'User-Agent': 'Mozilla/5.0'}
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Extract scripts
                        script_matches = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE)
                        for script in script_matches:
                            resources['scripts'].add(urljoin(html_url, script))
                        
                        # Extract stylesheets
                        css_matches = re.findall(r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']', content, re.IGNORECASE)
                        for css in css_matches:
                            resources['stylesheets'].add(urljoin(html_url, css))
                        
                        # Extract images
                        img_matches = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE)
                        for img in img_matches:
                            resources['images'].add(urljoin(html_url, img))
                        
                        # Extract all links
                        link_matches = re.findall(r'<a[^>]+href=["\']([^"\']+)["\']', content, re.IGNORECASE)
                        for link in link_matches:
                            if not link.startswith(('javascript:', 'mailto:', '#')):
                                resources['links'].add(urljoin(html_url, link))
                        
                        # Extract forms
                        form_matches = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', content, re.IGNORECASE)
                        for form in form_matches:
                            resources['forms'].append({
                                'action': urljoin(html_url, form),
                                'source': html_url
                            })
                        
                        # Extract meta tags
                        meta_matches = re.findall(r'<meta[^>]+content=["\']([^"\']+)["\']', content, re.IGNORECASE)
                        resources['meta_tags'] = meta_matches[:20]  # Limit
        except Exception:
            pass
        
        return {
            'scripts': list(resources['scripts']),
            'stylesheets': list(resources['stylesheets']),
            'images': list(resources['images']),
            'links': list(resources['links']),
            'forms': resources['forms'],
            'meta_tags': resources['meta_tags']
        }
    
    async def discover_common_files(self, base_url: str) -> List[str]:
        """Check for common files that might exist."""
        common_files = [
            '/robots.txt',
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/.well-known/security.txt',
            '/security.txt',
            '/humans.txt',
            '/ads.txt',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            '/.git/config',
            '/.env',
            '/package.json',
            '/composer.json',
            '/webpack.config.js',
            '/tsconfig.json',
            '/.htaccess',
            '/web.config',
            '/manifest.json',
            '/sw.js',
            '/service-worker.js',
        ]
        
        found = []
        
        async with aiohttp.ClientSession() as session:
            for file_path in common_files:
                try:
                    url = urljoin(base_url, file_path)
                    async with session.head(
                        url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        headers={'User-Agent': 'Mozilla/5.0'},
                        allow_redirects=False
                    ) as response:
                        if response.status == 200:
                            found.append(url)
                except Exception:
                    continue
        
        return found
    
    async def discover_api_documentation(self, base_url: str) -> List[str]:
        """Discover API documentation endpoints."""
        doc_paths = [
            '/api/docs',
            '/api/documentation',
            '/docs',
            '/documentation',
            '/swagger',
            '/swagger-ui',
            '/swagger.json',
            '/swagger.yaml',
            '/openapi.json',
            '/openapi.yaml',
            '/api-docs',
            '/redoc',
            '/graphql',
            '/graphiql',
            '/api/v1/docs',
            '/api/v2/docs',
            '/api/v3/docs',
        ]
        
        found = []
        
        async with aiohttp.ClientSession() as session:
            for doc_path in doc_paths:
                try:
                    url = urljoin(base_url, doc_path)
                    async with session.head(
                        url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        headers={'User-Agent': 'Mozilla/5.0'},
                        allow_redirects=True
                    ) as response:
                        if response.status == 200:
                            found.append(url)
                except Exception:
                    continue
        
        return found
