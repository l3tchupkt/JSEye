"""
LinkFinder Integration for JSEye
Extracts endpoints and paths from JavaScript files
"""

import re
import jsbeautifier
from typing import List, Dict, Any


class LinkFinder:
    """Extract endpoints and paths from JavaScript content."""
    
    def __init__(self):
        # Regex pattern from LinkFinder
        self.regex_str = r"""
            (?:"|')                               # Start newline delimiter
            (
              ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
                [^"'/]{1,}\.                        # Match a domainname (any character + dot)
                [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
              |
              ((?:/|\.\./|\./)                    # Start with /,../,./
                [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
                [^"'><,;|()]{1,})                   # Rest of the characters can't be
              |
              ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
                [a-zA-Z0-9_\-/.]{1,}                # Resource name
                \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
                (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
              |
              ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
                [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
                (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
              |
              ([a-zA-Z0-9_\-]{1,}                 # filename
                \.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)        # . + extension
                (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
            )
            (?:"|')                               # End newline delimiter
        """
        self.regex = re.compile(self.regex_str, re.VERBOSE)
    
    def extract_endpoints(self, js_content: str, beautify: bool = True) -> List[Dict[str, Any]]:
        """Extract endpoints from JavaScript content."""
        try:
            # Beautify JS for better extraction
            if beautify and len(js_content) < 1000000:
                try:
                    js_content = jsbeautifier.beautify(js_content)
                except Exception:
                    # If beautification fails, use original
                    pass
            
            # Find all matches
            endpoints = []
            seen = set()
            
            for match in self.regex.finditer(js_content):
                endpoint = match.group(1)
                if endpoint and endpoint not in seen:
                    seen.add(endpoint)
                    
                    # Get context (surrounding code)
                    start = max(0, match.start() - 50)
                    end = min(len(js_content), match.end() + 50)
                    context = js_content[start:end]
                    
                    endpoints.append({
                        'endpoint': endpoint,
                        'context': context,
                        'type': self._classify_endpoint(endpoint)
                    })
            
            return endpoints
            
        except Exception:
            return []
    
    def _classify_endpoint(self, endpoint: str) -> str:
        """Classify the type of endpoint."""
        if endpoint.startswith(('http://', 'https://', '//')):
            return 'absolute_url'
        elif endpoint.startswith('/'):
            return 'absolute_path'
        elif endpoint.startswith(('./', '../')):
            return 'relative_path'
        elif '/' in endpoint:
            return 'api_endpoint'
        else:
            return 'file'
    
    def extract_from_multiple(self, js_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract endpoints from multiple JS files."""
        all_endpoints = []
        stats = {
            'total_files': len(js_files),
            'files_processed': 0,
            'total_endpoints': 0,
            'by_type': {}
        }
        
        for js_file in js_files:
            try:
                content = js_file.get('content', '')
                if content:
                    endpoints = self.extract_endpoints(content)
                    
                    # Add source URL to each endpoint
                    for ep in endpoints:
                        ep['source_file'] = js_file.get('url', 'unknown')
                        all_endpoints.append(ep)
                        
                        # Update stats
                        ep_type = ep['type']
                        stats['by_type'][ep_type] = stats['by_type'].get(ep_type, 0) + 1
                    
                    stats['files_processed'] += 1
            except Exception:
                continue
        
        stats['total_endpoints'] = len(all_endpoints)
        
        return {
            'endpoints': all_endpoints,
            'statistics': stats
        }
