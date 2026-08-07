"""
Recursive JavaScript Discovery
Finds JS files referenced within other JS files
"""

import re
from typing import List, Set, Dict, Any
from urllib.parse import urljoin, urlparse


class RecursiveJSFinder:
    """Find JavaScript files referenced in other JS files."""
    
    def __init__(self):
        # Patterns to find JS file references
        self.patterns = [
            # import/require statements
            r'import\s+.*?from\s+["\']([^"\']+\.js)["\']',
            r'require\s*\(\s*["\']([^"\']+\.js)["\']\s*\)',
            
            # Dynamic imports
            r'import\s*\(\s*["\']([^"\']+\.js)["\']\s*\)',
            
            # Script src
            r'<script[^>]+src=["\']([^"\']+\.js)["\']',
            
            # Webpack/module loaders
            r'__webpack_require__\s*\(\s*["\']([^"\']+\.js)["\']\s*\)',
            
            # Direct URL references
            r'["\']([^"\']*?/[^"\']*?\.js)["\']',
            
            # Chunk files
            r'["\']([^"\']*?chunk[^"\']*?\.js)["\']',
            r'["\']([^"\']*?bundle[^"\']*?\.js)["\']',
            r'["\']([^"\']*?vendor[^"\']*?\.js)["\']',
            
            # Source maps
            r'["\']([^"\']+\.js\.map)["\']',
        ]
    
    def find_js_references(self, js_content: str, base_url: str) -> Set[str]:
        """Find all JS file references in content."""
        found_urls = set()
        
        for pattern in self.patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                js_path = match.group(1)
                
                # Skip if it's a data URL or too short
                if js_path.startswith('data:') or len(js_path) < 3:
                    continue
                
                # Resolve relative URLs
                try:
                    if js_path.startswith(('http://', 'https://')):
                        full_url = js_path
                    else:
                        # Get base URL from the JS file URL
                        parsed = urlparse(base_url)
                        base = f"{parsed.scheme}://{parsed.netloc}"
                        
                        if js_path.startswith('/'):
                            full_url = f"{base}{js_path}"
                        else:
                            # Relative to current directory
                            current_dir = base_url.rsplit('/', 1)[0]
                            full_url = f"{current_dir}/{js_path}"
                    
                    # Clean up URL
                    full_url = full_url.split('?')[0].split('#')[0]
                    
                    # Only add if it looks like a valid JS URL
                    if full_url.endswith(('.js', '.map')) or '/js/' in full_url:
                        found_urls.add(full_url)
                        
                except Exception:
                    continue
        
        return found_urls
    
    def discover_recursive_js(
        self, 
        js_files: List[Dict[str, Any]], 
        max_depth: int = 2
    ) -> Set[str]:
        """Recursively discover JS files referenced in other JS files."""
        all_discovered = set()
        current_level = set()
        
        # Start with initial JS files
        for js_file in js_files:
            url = js_file.get('url', '')
            content = js_file.get('content', '')
            
            if url and content:
                refs = self.find_js_references(content, url)
                current_level.update(refs)
        
        # Track what we've already processed
        processed = {js_file.get('url', '') for js_file in js_files}
        
        # Recursively discover up to max_depth
        for depth in range(max_depth):
            if not current_level:
                break
            
            all_discovered.update(current_level)
            next_level = set()
            
            # For each URL in current level, we would need to fetch and analyze
            # But we'll just return the URLs for now and let the main collector fetch them
            
            current_level = next_level
        
        # Return only new URLs not already in processed
        return all_discovered - processed
