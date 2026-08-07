"""JavaScript parsing and analysis engine."""

import re
import json
import jsbeautifier
from typing import List, Dict, Any, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
from .utils import (
    extract_js_strings, extract_endpoints_from_js, 
    extract_urls_from_string, clean_js_content,
    extract_subdomains_from_js, decode_base64, decode_hex, decode_uri_component
)


class JSParser:
    """Parse and analyze JavaScript content for security-relevant information."""
    
    def __init__(self):
        self.beautifier_options = {
            'indent_size': 2,
            'indent_char': ' ',
            'max_preserve_newlines': 2,
            'preserve_newlines': True,
            'keep_array_indentation': False,
            'break_chained_methods': False,
            'indent_scripts': 'normal',
            'brace_style': 'collapse',
            'space_before_conditional': True,
            'unescape_strings': False,
            'jslint_happy': False,
            'end_with_newline': False,
            'wrap_line_length': 0,
            'indent_inner_html': False,
            'comma_first': False,
            'e4x': False,
            'indent_empty_lines': False
        }
    
    def parse_javascript(self, content: str, source_url: str = "") -> Dict[str, Any]:
        """Parse JavaScript content and extract security-relevant information."""
        try:
            # Beautify the JavaScript for better analysis
            beautified_content = jsbeautifier.beautify(content, self.beautifier_options)
        except Exception:
            # If beautification fails, use original content
            beautified_content = content
        
        # Clean content for analysis
        cleaned_content = clean_js_content(beautified_content)
        
        analysis_result = {
            'source_url': source_url,
            'content_length': len(content),
            'beautified_length': len(beautified_content),
            'endpoints': self._extract_endpoints(beautified_content, source_url),
            'urls': self._extract_urls(beautified_content, source_url),
            'subdomains': self._extract_subdomains(beautified_content, source_url),
            'api_calls': self._extract_api_calls(beautified_content),
            'websockets': self._extract_websockets(beautified_content),
            'graphql': self._extract_graphql(beautified_content),
            'variables': self._extract_variables(beautified_content),
            'functions': self._extract_functions(beautified_content),
            'imports': self._extract_imports(beautified_content),
            'comments': self._extract_comments(content),  # Use original for comments
            'strings': self._extract_strings(beautified_content),
            'encoded_data': self._extract_encoded_data(beautified_content),
            'source_maps': self._find_source_maps(beautified_content, source_url),
            'service_workers': self._extract_service_workers(beautified_content),
            'web_workers': self._extract_web_workers(beautified_content),
            'wasm_references': self._extract_wasm_references(beautified_content),
            'security_headers': self._extract_security_headers(beautified_content),
            'cookies': self._extract_cookie_operations(beautified_content),
            'storage_operations': self._extract_storage_operations(beautified_content),
            'event_listeners': self._extract_event_listeners(beautified_content)
        }
        
        return analysis_result
    
    def _extract_endpoints(self, content: str, source_url: str) -> List[Dict[str, Any]]:
        """Extract API endpoints from JavaScript content."""
        endpoints = []
        
        # Use utility function to get basic endpoints
        basic_endpoints = extract_endpoints_from_js(content)
        
        # Enhanced endpoint patterns
        patterns = [
            # Fetch API calls
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            # XMLHttpRequest
            r'\.open\s*\(\s*["\'][^"\']*["\']\s*,\s*["\']([^"\']+)["\']',
            # Axios calls
            r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            r'axios\s*\(\s*["\']([^"\']+)["\']',
            # jQuery AJAX
            r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
            # URL constructors
            r'new\s+URL\s*\(\s*["\']([^"\']+)["\']',
            # Template literals with URLs
            r'`([^`]*(?:https?://|/api/|/v\d+/)[^`]*)`',
            # Object properties that look like endpoints
            r'(?:url|endpoint|path|route)\s*:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = match.group(1)
                
                # Skip if not a valid endpoint
                if not endpoint or len(endpoint) < 2:
                    continue
                
                # Normalize endpoint
                if source_url and not endpoint.startswith(('http://', 'https://')):
                    if endpoint.startswith('/'):
                        parsed_source = urlparse(source_url)
                        endpoint = f"{parsed_source.scheme}://{parsed_source.netloc}{endpoint}"
                    else:
                        endpoint = urljoin(source_url, endpoint)
                
                endpoint_info = {
                    'url': endpoint,
                    'method': self._guess_http_method(content, match.start()),
                    'context': self._extract_context(content, match.start()),
                    'parameters': self._extract_parameters_near_endpoint(content, match.start())
                }
                
                endpoints.append(endpoint_info)
        
        # Add basic endpoints
        for endpoint in basic_endpoints:
            if source_url and not endpoint.startswith(('http://', 'https://')):
                if endpoint.startswith('/'):
                    parsed_source = urlparse(source_url)
                    endpoint = f"{parsed_source.scheme}://{parsed_source.netloc}{endpoint}"
            
            endpoint_info = {
                'url': endpoint,
                'method': 'GET',  # Default
                'context': '',
                'parameters': []
            }
            endpoints.append(endpoint_info)
        
        # Deduplicate
        seen_urls = set()
        unique_endpoints = []
        for endpoint in endpoints:
            url = endpoint['url']
            if url not in seen_urls:
                seen_urls.add(url)
                unique_endpoints.append(endpoint)
        
        return unique_endpoints
    
    def _extract_urls(self, content: str, source_url: str) -> List[str]:
        """Extract all URLs from JavaScript content."""
        urls = set()
        
        # Extract from strings
        strings = extract_js_strings(content)
        for string in strings:
            string_urls = extract_urls_from_string(string)
            urls.update(string_urls)
        
        # Direct URL patterns
        url_patterns = [
            r'https?://[^\s<>"\'`]+',
            r'//[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\'`]*',
            r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s<>"\'`]*'
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if not match.startswith('http'):
                    match = 'https://' + match.lstrip('//')
                urls.add(match)
        
        return list(urls)
    
    def _extract_subdomains(self, content: str, source_url: str) -> List[str]:
        """Extract subdomains related to the target domain."""
        if not source_url:
            return []
        
        subdomains = extract_subdomains_from_js(content, source_url)
        return list(subdomains)
    
    def _extract_api_calls(self, content: str) -> List[Dict[str, Any]]:
        """Extract API call patterns."""
        api_calls = []
        
        patterns = [
            {
                'type': 'fetch',
                'pattern': r'fetch\s*\(\s*([^)]+)\)',
                'description': 'Fetch API call'
            },
            {
                'type': 'xhr',
                'pattern': r'XMLHttpRequest\s*\(\s*\)|new\s+XMLHttpRequest\s*\(\s*\)',
                'description': 'XMLHttpRequest usage'
            },
            {
                'type': 'axios',
                'pattern': r'axios\s*\.\s*(?:get|post|put|delete|patch|request)',
                'description': 'Axios HTTP call'
            },
            {
                'type': 'jquery',
                'pattern': r'\$\.(?:ajax|get|post|getJSON)',
                'description': 'jQuery AJAX call'
            }
        ]
        
        for pattern_info in patterns:
            matches = re.finditer(pattern_info['pattern'], content, re.IGNORECASE)
            for match in matches:
                api_call = {
                    'type': pattern_info['type'],
                    'description': pattern_info['description'],
                    'match': match.group(0),
                    'position': match.start(),
                    'context': self._extract_context(content, match.start())
                }
                api_calls.append(api_call)
        
        return api_calls
    
    def _extract_websockets(self, content: str) -> List[Dict[str, Any]]:
        """Extract WebSocket usage."""
        websockets = []
        
        patterns = [
            r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            r'WebSocket\s*\(\s*["\']([^"\']+)["\']',
            r'ws://[^\s<>"\'`]+',
            r'wss://[^\s<>"\'`]+'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                websocket_url = match.group(1) if match.groups() else match.group(0)
                
                websocket_info = {
                    'url': websocket_url,
                    'context': self._extract_context(content, match.start()),
                    'position': match.start()
                }
                websockets.append(websocket_info)
        
        return websockets
    
    def _extract_graphql(self, content: str) -> List[Dict[str, Any]]:
        """Extract GraphQL queries and mutations."""
        graphql_items = []
        
        patterns = [
            r'(?:query|mutation|subscription)\s+\w+\s*\{[^}]+\}',
            r'gql`([^`]+)`',
            r'graphql`([^`]+)`',
            r'["\'](?:query|mutation|subscription)\s+[^"\']+["\']'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                graphql_content = match.group(1) if match.groups() else match.group(0)
                
                graphql_info = {
                    'content': graphql_content.strip(),
                    'type': self._detect_graphql_type(graphql_content),
                    'context': self._extract_context(content, match.start()),
                    'position': match.start()
                }
                graphql_items.append(graphql_info)
        
        return graphql_items
    
    def _extract_variables(self, content: str) -> List[Dict[str, Any]]:
        """Extract variable declarations and assignments."""
        variables = []
        
        patterns = [
            r'(?:var|let|const)\s+(\w+)\s*=\s*([^;]+);?',
            r'(\w+)\s*=\s*([^;]+);?',
            r'(\w+)\s*:\s*([^,}]+)'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                var_name = match.group(1)
                var_value = match.group(2).strip()
                
                # Skip very common/generic variables
                if var_name in ['i', 'j', 'k', 'x', 'y', 'z', 'e', 'el', 'item']:
                    continue
                
                variable_info = {
                    'name': var_name,
                    'value': var_value[:100],  # Limit value length
                    'context': self._extract_context(content, match.start(), 30),
                    'position': match.start()
                }
                variables.append(variable_info)
        
        return variables[:50]  # Limit number of variables
    
    def _extract_functions(self, content: str) -> List[Dict[str, Any]]:
        """Extract function declarations."""
        functions = []
        
        patterns = [
            r'function\s+(\w+)\s*\([^)]*\)',
            r'(\w+)\s*:\s*function\s*\([^)]*\)',
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>',
            r'(\w+)\s*\([^)]*\)\s*\{'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                func_name = match.group(1)
                
                function_info = {
                    'name': func_name,
                    'signature': match.group(0),
                    'context': self._extract_context(content, match.start(), 50),
                    'position': match.start()
                }
                functions.append(function_info)
        
        return functions[:30]  # Limit number of functions
    
    def _extract_imports(self, content: str) -> List[Dict[str, Any]]:
        """Extract import statements and require calls."""
        imports = []
        
        patterns = [
            r'import\s+[^;]+from\s+["\']([^"\']+)["\']',
            r'import\s*\(\s*["\']([^"\']+)["\']\s*\)',
            r'require\s*\(\s*["\']([^"\']+)["\']\s*\)',
            r'import\s+["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                import_path = match.group(1)
                
                import_info = {
                    'path': import_path,
                    'statement': match.group(0),
                    'type': self._detect_import_type(match.group(0)),
                    'position': match.start()
                }
                imports.append(import_info)
        
        return imports
    
    def _extract_comments(self, content: str) -> List[Dict[str, Any]]:
        """Extract comments from JavaScript."""
        comments = []
        
        # Single line comments
        single_line_pattern = r'//(.*)$'
        matches = re.finditer(single_line_pattern, content, re.MULTILINE)
        for match in matches:
            comment_text = match.group(1).strip()
            if len(comment_text) > 5:  # Skip very short comments
                comments.append({
                    'type': 'single_line',
                    'content': comment_text,
                    'position': match.start()
                })
        
        # Multi-line comments
        multi_line_pattern = r'/\*(.*?)\*/'
        matches = re.finditer(multi_line_pattern, content, re.DOTALL)
        for match in matches:
            comment_text = match.group(1).strip()
            if len(comment_text) > 5:
                comments.append({
                    'type': 'multi_line',
                    'content': comment_text,
                    'position': match.start()
                })
        
        return comments[:20]  # Limit number of comments
    
    def _extract_strings(self, content: str) -> List[str]:
        """Extract string literals."""
        strings = extract_js_strings(content)
        
        # Filter out very short strings and common patterns
        filtered_strings = []
        for string in strings:
            if len(string) > 5 and not re.match(r'^[a-z]{1,3}$', string):
                filtered_strings.append(string)
        
        return filtered_strings[:100]  # Limit number of strings
    
    def _extract_encoded_data(self, content: str) -> List[Dict[str, Any]]:
        """Extract and decode encoded data."""
        encoded_data = []
        
        # Base64 patterns
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.finditer(base64_pattern, content)
        for match in matches:
            encoded = match.group(0)
            decoded = decode_base64(encoded)
            if decoded and len(decoded) > 5:
                encoded_data.append({
                    'type': 'base64',
                    'encoded': encoded[:50] + '...' if len(encoded) > 50 else encoded,
                    'decoded': decoded[:100] + '...' if len(decoded) > 100 else decoded,
                    'position': match.start()
                })
        
        # Hex patterns
        hex_pattern = r'(?:0x|\\x)?[a-fA-F0-9]{16,}'
        matches = re.finditer(hex_pattern, content)
        for match in matches:
            encoded = match.group(0)
            decoded = decode_hex(encoded)
            if decoded and len(decoded) > 3:
                encoded_data.append({
                    'type': 'hex',
                    'encoded': encoded,
                    'decoded': decoded[:100] + '...' if len(decoded) > 100 else decoded,
                    'position': match.start()
                })
        
        return encoded_data[:20]  # Limit results
    
    def _find_source_maps(self, content: str, source_url: str) -> List[str]:
        """Find source map references."""
        source_maps = []
        
        # Source map comment
        sourcemap_pattern = r'//[@#]\s*sourceMappingURL=([^\s]+)'
        matches = re.findall(sourcemap_pattern, content)
        
        for match in matches:
            if source_url and not match.startswith(('http://', 'https://')):
                match = urljoin(source_url, match)
            source_maps.append(match)
        
        return source_maps
    
    def _extract_service_workers(self, content: str) -> List[Dict[str, Any]]:
        """Extract Service Worker registrations."""
        service_workers = []
        
        pattern = r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']'
        matches = re.finditer(pattern, content, re.IGNORECASE)
        
        for match in matches:
            sw_path = match.group(1)
            service_workers.append({
                'path': sw_path,
                'context': self._extract_context(content, match.start()),
                'position': match.start()
            })
        
        return service_workers
    
    def _extract_web_workers(self, content: str) -> List[Dict[str, Any]]:
        """Extract Web Worker usage."""
        web_workers = []
        
        pattern = r'new\s+Worker\s*\(\s*["\']([^"\']+)["\']'
        matches = re.finditer(pattern, content, re.IGNORECASE)
        
        for match in matches:
            worker_path = match.group(1)
            web_workers.append({
                'path': worker_path,
                'context': self._extract_context(content, match.start()),
                'position': match.start()
            })
        
        return web_workers
    
    def _extract_wasm_references(self, content: str) -> List[Dict[str, Any]]:
        """Extract WebAssembly references."""
        wasm_refs = []
        
        patterns = [
            r'WebAssembly\.instantiate',
            r'WebAssembly\.compile',
            r'\.wasm["\']',
            r'wasm-[a-zA-Z0-9]+'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                wasm_refs.append({
                    'match': match.group(0),
                    'context': self._extract_context(content, match.start()),
                    'position': match.start()
                })
        
        return wasm_refs
    
    def _extract_security_headers(self, content: str) -> List[Dict[str, Any]]:
        """Extract security-related header operations."""
        headers = []
        
        patterns = [
            r'setRequestHeader\s*\(\s*["\']([^"\']+)["\']',
            r'headers\s*:\s*\{[^}]*["\']([^"\']+)["\'][^}]*\}',
            r'Authorization["\']?\s*:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                header_name = match.group(1)
                headers.append({
                    'header': header_name,
                    'context': self._extract_context(content, match.start()),
                    'position': match.start()
                })
        
        return headers
    
    def _extract_cookie_operations(self, content: str) -> List[Dict[str, Any]]:
        """Extract cookie operations."""
        cookies = []
        
        patterns = [
            r'document\.cookie\s*=\s*["\']([^"\']+)["\']',
            r'getCookie\s*\(\s*["\']([^"\']+)["\']',
            r'setCookie\s*\(\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                cookie_info = {
                    'operation': match.group(0),
                    'cookie_name': match.group(1) if match.groups() else '',
                    'context': self._extract_context(content, match.start()),
                    'position': match.start()
                }
                cookies.append(cookie_info)
        
        return cookies
    
    def _extract_storage_operations(self, content: str) -> List[Dict[str, Any]]:
        """Extract localStorage/sessionStorage operations."""
        storage_ops = []
        
        patterns = [
            r'(?:localStorage|sessionStorage)\.(?:setItem|getItem|removeItem)\s*\(\s*["\']([^"\']+)["\']',
            r'(?:localStorage|sessionStorage)\[["\']([^"\']+)["\']\]'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                storage_ops.append({
                    'operation': match.group(0),
                    'key': match.group(1),
                    'context': self._extract_context(content, match.start()),
                    'position': match.start()
                })
        
        return storage_ops
    
    def _extract_event_listeners(self, content: str) -> List[Dict[str, Any]]:
        """Extract event listener registrations."""
        listeners = []
        
        patterns = [
            r'addEventListener\s*\(\s*["\']([^"\']+)["\']',
            r'on(\w+)\s*=',
            r'\.on(\w+)\s*\('
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                event_name = match.group(1)
                listeners.append({
                    'event': event_name,
                    'context': self._extract_context(content, match.start(), 30),
                    'position': match.start()
                })
        
        return listeners[:20]  # Limit results
    
    def _guess_http_method(self, content: str, position: int) -> str:
        """Guess HTTP method based on context around position."""
        context = self._extract_context(content, position, 100)
        context_lower = context.lower()
        
        if 'post' in context_lower:
            return 'POST'
        elif 'put' in context_lower:
            return 'PUT'
        elif 'delete' in context_lower:
            return 'DELETE'
        elif 'patch' in context_lower:
            return 'PATCH'
        else:
            return 'GET'
    
    def _extract_context(self, content: str, position: int, size: int = 50) -> str:
        """Extract context around a position."""
        start = max(0, position - size)
        end = min(len(content), position + size)
        return content[start:end].strip()
    
    def _extract_parameters_near_endpoint(self, content: str, position: int) -> List[str]:
        """Extract parameters near an endpoint."""
        context = self._extract_context(content, position, 200)
        
        # Look for parameter patterns
        param_patterns = [
            r'["\'](\w+)["\']:\s*\w+',
            r'(\w+):\s*["\'][^"\']*["\']',
            r'data\s*:\s*\{[^}]*["\'](\w+)["\'][^}]*\}'
        ]
        
        parameters = []
        for pattern in param_patterns:
            matches = re.findall(pattern, context)
            parameters.extend(matches)
        
        return list(set(parameters))[:10]  # Limit and deduplicate
    
    def _detect_graphql_type(self, content: str) -> str:
        """Detect GraphQL operation type."""
        content_lower = content.lower()
        if 'mutation' in content_lower:
            return 'mutation'
        elif 'subscription' in content_lower:
            return 'subscription'
        else:
            return 'query'
    
    def _detect_import_type(self, statement: str) -> str:
        """Detect import statement type."""
        if 'require(' in statement:
            return 'commonjs'
        elif 'import(' in statement:
            return 'dynamic'
        else:
            return 'es6'