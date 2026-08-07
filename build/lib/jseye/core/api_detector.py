"""
Advanced API Detection and Discovery
Comprehensive API endpoint detection from JavaScript and URLs
"""

import re
import json
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, parse_qs


class APIDetector:
    """Advanced API endpoint detection and analysis."""
    
    def __init__(self):
        # API endpoint patterns
        self.api_patterns = [
            # REST API patterns
            r'["\']([^"\']*?/api/[^"\']*?)["\']',
            r'["\']([^"\']*?/v\d+/[^"\']*?)["\']',
            r'["\']([^"\']*?/rest/[^"\']*?)["\']',
            
            # GraphQL
            r'["\']([^"\']*?/graphql[^"\']*?)["\']',
            r'["\']([^"\']*?/gql[^"\']*?)["\']',
            
            # Common API paths
            r'["\']([^"\']*?/users?/[^"\']*?)["\']',
            r'["\']([^"\']*?/auth/[^"\']*?)["\']',
            r'["\']([^"\']*?/login[^"\']*?)["\']',
            r'["\']([^"\']*?/register[^"\']*?)["\']',
            r'["\']([^"\']*?/admin/[^"\']*?)["\']',
            r'["\']([^"\']*?/dashboard/[^"\']*?)["\']',
            r'["\']([^"\']*?/profile/[^"\']*?)["\']',
            r'["\']([^"\']*?/settings/[^"\']*?)["\']',
            r'["\']([^"\']*?/account/[^"\']*?)["\']',
            r'["\']([^"\']*?/data/[^"\']*?)["\']',
            r'["\']([^"\']*?/service/[^"\']*?)["\']',
            r'["\']([^"\']*?/endpoint/[^"\']*?)["\']',
            
            # CRUD operations
            r'["\']([^"\']*?/create[^"\']*?)["\']',
            r'["\']([^"\']*?/read[^"\']*?)["\']',
            r'["\']([^"\']*?/update[^"\']*?)["\']',
            r'["\']([^"\']*?/delete[^"\']*?)["\']',
            r'["\']([^"\']*?/get[^"\']*?)["\']',
            r'["\']([^"\']*?/post[^"\']*?)["\']',
            r'["\']([^"\']*?/put[^"\']*?)["\']',
            r'["\']([^"\']*?/patch[^"\']*?)["\']',
            
            # Microservices
            r'["\']([^"\']*?/service-[^"\']*?)["\']',
            r'["\']([^"\']*?/ms-[^"\']*?)["\']',
            
            # Mobile API
            r'["\']([^"\']*?/mobile/[^"\']*?)["\']',
            r'["\']([^"\']*?/app/[^"\']*?)["\']',
            
            # Internal APIs
            r'["\']([^"\']*?/internal/[^"\']*?)["\']',
            r'["\']([^"\']*?/private/[^"\']*?)["\']',
            
            # Webhooks
            r'["\']([^"\']*?/webhook[^"\']*?)["\']',
            r'["\']([^"\']*?/callback[^"\']*?)["\']',
            
            # File operations
            r'["\']([^"\']*?/upload[^"\']*?)["\']',
            r'["\']([^"\']*?/download[^"\']*?)["\']',
            r'["\']([^"\']*?/file[^"\']*?)["\']',
            
            # Search and query
            r'["\']([^"\']*?/search[^"\']*?)["\']',
            r'["\']([^"\']*?/query[^"\']*?)["\']',
            r'["\']([^"\']*?/filter[^"\']*?)["\']',
        ]
        
        # HTTP method detection
        self.method_patterns = {
            'GET': r'\.get\s*\(\s*["\']([^"\']+)["\']',
            'POST': r'\.post\s*\(\s*["\']([^"\']+)["\']',
            'PUT': r'\.put\s*\(\s*["\']([^"\']+)["\']',
            'DELETE': r'\.delete\s*\(\s*["\']([^"\']+)["\']',
            'PATCH': r'\.patch\s*\(\s*["\']([^"\']+)["\']',
            'HEAD': r'\.head\s*\(\s*["\']([^"\']+)["\']',
            'OPTIONS': r'\.options\s*\(\s*["\']([^"\']+)["\']',
        }
        
        # API framework detection
        self.framework_patterns = {
            'axios': r'axios\.',
            'fetch': r'fetch\s*\(',
            'XMLHttpRequest': r'XMLHttpRequest',
            'jQuery': r'\$\.ajax',
            'superagent': r'superagent\.',
            'request': r'request\.',
        }
    
    def detect_api_endpoints(self, content: str, source_url: str = '') -> List[Dict[str, Any]]:
        """Detect all API endpoints in content."""
        endpoints = []
        seen = set()
        
        # Detect by pattern
        for pattern in self.api_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = match.group(1)
                
                # Clean up endpoint
                endpoint = endpoint.split('?')[0].split('#')[0]
                
                if endpoint and len(endpoint) > 3 and endpoint not in seen:
                    seen.add(endpoint)
                    
                    # Detect HTTP method
                    method = self._detect_method(content, endpoint)
                    
                    # Detect parameters
                    params = self._detect_parameters(content, endpoint)
                    
                    # Classify endpoint
                    classification = self._classify_endpoint(endpoint)
                    
                    endpoints.append({
                        'endpoint': endpoint,
                        'method': method,
                        'parameters': params,
                        'classification': classification,
                        'source': source_url,
                        'type': 'api',
                        'framework': self._detect_framework(content)
                    })
        
        # Detect by HTTP method
        for method, pattern in self.method_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = match.group(1)
                
                if endpoint and len(endpoint) > 3 and endpoint not in seen:
                    seen.add(endpoint)
                    
                    params = self._detect_parameters(content, endpoint)
                    classification = self._classify_endpoint(endpoint)
                    
                    endpoints.append({
                        'endpoint': endpoint,
                        'method': method,
                        'parameters': params,
                        'classification': classification,
                        'source': source_url,
                        'type': 'api',
                        'framework': self._detect_framework(content)
                    })
        
        return endpoints
    
    def _detect_method(self, content: str, endpoint: str) -> str:
        """Detect HTTP method for endpoint."""
        # Look for method in context around endpoint
        escaped_endpoint = re.escape(endpoint)
        
        for method, pattern in self.method_patterns.items():
            if re.search(pattern.replace('([^"\']+)', escaped_endpoint), content, re.IGNORECASE):
                return method
        
        # Check for method in nearby context
        context_pattern = rf'.{{0,100}}{escaped_endpoint}.{{0,100}}'
        match = re.search(context_pattern, content, re.IGNORECASE | re.DOTALL)
        
        if match:
            context = match.group(0).lower()
            if 'post' in context:
                return 'POST'
            elif 'put' in context:
                return 'PUT'
            elif 'delete' in context:
                return 'DELETE'
            elif 'patch' in context:
                return 'PATCH'
        
        return 'GET'  # Default
    
    def _detect_parameters(self, content: str, endpoint: str) -> List[str]:
        """Detect parameters for endpoint."""
        params = []
        
        # URL parameters in endpoint
        if '/:' in endpoint:
            param_matches = re.findall(r'/:([a-zA-Z0-9_]+)', endpoint)
            params.extend(param_matches)
        
        if '/{' in endpoint:
            param_matches = re.findall(r'/\{([a-zA-Z0-9_]+)\}', endpoint)
            params.extend(param_matches)
        
        # Query parameters
        if '?' in endpoint:
            query_part = endpoint.split('?')[1]
            query_params = re.findall(r'([a-zA-Z0-9_]+)=', query_part)
            params.extend(query_params)
        
        return list(set(params))
    
    def _classify_endpoint(self, endpoint: str) -> str:
        """Classify endpoint type."""
        endpoint_lower = endpoint.lower()
        
        if '/graphql' in endpoint_lower or '/gql' in endpoint_lower:
            return 'GraphQL'
        elif '/api/' in endpoint_lower:
            return 'REST API'
        elif '/auth' in endpoint_lower or '/login' in endpoint_lower:
            return 'Authentication'
        elif '/admin' in endpoint_lower:
            return 'Admin'
        elif '/user' in endpoint_lower or '/profile' in endpoint_lower:
            return 'User Management'
        elif '/upload' in endpoint_lower or '/download' in endpoint_lower:
            return 'File Operations'
        elif '/webhook' in endpoint_lower or '/callback' in endpoint_lower:
            return 'Webhook'
        elif '/internal' in endpoint_lower or '/private' in endpoint_lower:
            return 'Internal API'
        elif '/mobile' in endpoint_lower or '/app' in endpoint_lower:
            return 'Mobile API'
        else:
            return 'General API'
    
    def _detect_framework(self, content: str) -> str:
        """Detect API framework used."""
        for framework, pattern in self.framework_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                return framework
        return 'unknown'
    
    def detect_api_keys_in_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Detect API keys and tokens in URLs."""
        findings = []
        
        api_key_params = [
            'api_key', 'apikey', 'key', 'token', 'access_token',
            'auth', 'authorization', 'secret', 'client_id',
            'client_secret', 'app_id', 'app_key'
        ]
        
        for url in urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                for param_name, param_values in params.items():
                    if param_name.lower() in api_key_params:
                        for value in param_values:
                            if len(value) > 10:  # Likely a real key
                                findings.append({
                                    'type': 'api_key_in_url',
                                    'parameter': param_name,
                                    'value': value,
                                    'url': url,
                                    'severity': 'high'
                                })
            except Exception:
                continue
        
        return findings
    
    def analyze_api_structure(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze API structure and patterns."""
        analysis = {
            'total_endpoints': len(endpoints),
            'by_method': {},
            'by_classification': {},
            'by_framework': {},
            'versioned_apis': [],
            'authenticated_endpoints': [],
            'admin_endpoints': [],
            'file_operations': [],
            'internal_apis': [],
            'unique_base_paths': set(),
            'parameter_count': 0
        }
        
        for endpoint in endpoints:
            # Count by method
            method = endpoint.get('method', 'GET')
            analysis['by_method'][method] = analysis['by_method'].get(method, 0) + 1
            
            # Count by classification
            classification = endpoint.get('classification', 'General API')
            analysis['by_classification'][classification] = analysis['by_classification'].get(classification, 0) + 1
            
            # Count by framework
            framework = endpoint.get('framework', 'unknown')
            analysis['by_framework'][framework] = analysis['by_framework'].get(framework, 0) + 1
            
            # Detect versioned APIs
            if re.search(r'/v\d+/', endpoint.get('endpoint', '')):
                analysis['versioned_apis'].append(endpoint)
            
            # Detect authenticated endpoints
            if 'auth' in endpoint.get('endpoint', '').lower():
                analysis['authenticated_endpoints'].append(endpoint)
            
            # Detect admin endpoints
            if 'admin' in endpoint.get('endpoint', '').lower():
                analysis['admin_endpoints'].append(endpoint)
            
            # Detect file operations
            if any(x in endpoint.get('endpoint', '').lower() for x in ['upload', 'download', 'file']):
                analysis['file_operations'].append(endpoint)
            
            # Detect internal APIs
            if any(x in endpoint.get('endpoint', '').lower() for x in ['internal', 'private']):
                analysis['internal_apis'].append(endpoint)
            
            # Extract base path
            ep = endpoint.get('endpoint', '')
            if '/' in ep:
                parts = ep.split('/')
                if len(parts) >= 2:
                    base = '/'.join(parts[:3])
                    analysis['unique_base_paths'].add(base)
            
            # Count parameters
            analysis['parameter_count'] += len(endpoint.get('parameters', []))
        
        analysis['unique_base_paths'] = list(analysis['unique_base_paths'])
        
        return analysis
