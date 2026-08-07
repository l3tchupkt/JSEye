"""API intelligence and reconnaissance engine."""

import asyncio
import aiohttp
import json
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse
import re


class APIIntelligence:
    """API reconnaissance and intelligence gathering."""
    
    def __init__(self, timeout: int = 10, max_concurrent: int = 15):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def analyze_endpoints(self, endpoints: List[str], base_url: str = "") -> List[Dict[str, Any]]:
        """Analyze discovered API endpoints."""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def analyze_single_endpoint(endpoint):
            async with semaphore:
                return await self._analyze_endpoint(endpoint, base_url)
        
        tasks = [analyze_single_endpoint(endpoint) for endpoint in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and None results
        analyzed_endpoints = []
        for result in results:
            if isinstance(result, dict) and result:
                analyzed_endpoints.append(result)
        
        return analyzed_endpoints
    
    async def _analyze_endpoint(self, endpoint: str, base_url: str = "") -> Dict[str, Any]:
        """Analyze a single API endpoint."""
        try:
            # Normalize endpoint URL
            if base_url and not endpoint.startswith(('http://', 'https://')):
                full_url = urljoin(base_url, endpoint)
            else:
                full_url = endpoint
            
            analysis = {
                'url': full_url,
                'original_endpoint': endpoint,
                'methods': {},
                'cors_config': {},
                'authentication': {},
                'content_types': [],
                'response_headers': {},
                'status_codes': {},
                'vulnerabilities': [],
                'api_type': 'unknown',
                'parameters': [],
                'rate_limiting': {},
                'security_headers': {}
            }
            
            # Test different HTTP methods
            methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
            
            for method in methods_to_test:
                method_result = await self._test_http_method(full_url, method)
                if method_result:
                    analysis['methods'][method] = method_result
            
            # Analyze CORS configuration
            analysis['cors_config'] = await self._analyze_cors(full_url)
            
            # Detect API type
            analysis['api_type'] = self._detect_api_type(full_url, analysis['methods'])
            
            # Check for common vulnerabilities
            analysis['vulnerabilities'] = await self._check_vulnerabilities(full_url, analysis)
            
            # Extract parameters from successful responses
            analysis['parameters'] = self._extract_parameters(analysis['methods'])
            
            # Analyze security headers
            analysis['security_headers'] = self._analyze_security_headers(analysis['methods'])
            
            return analysis
            
        except Exception as e:
            return {
                'url': endpoint,
                'error': str(e),
                'status': 'error'
            }
    
    async def _test_http_method(self, url: str, method: str) -> Optional[Dict[str, Any]]:
        """Test a specific HTTP method on an endpoint."""
        try:
            async with self.session.request(method, url) as response:
                # Read response content (limit size)
                content = ""
                try:
                    content = await response.text()
                    if len(content) > 10000:  # Limit content size
                        content = content[:10000] + "... [truncated]"
                except Exception:
                    content = "[Unable to read content]"
                
                return {
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'content_type': response.headers.get('content-type', ''),
                    'content_length': len(content),
                    'content_preview': content[:500] if content else '',
                    'response_time': 0  # Could add timing if needed
                }
                
        except asyncio.TimeoutError:
            return {
                'status_code': 0,
                'error': 'timeout',
                'headers': {},
                'content_type': '',
                'content_length': 0,
                'content_preview': ''
            }
        except Exception as e:
            return {
                'status_code': 0,
                'error': str(e),
                'headers': {},
                'content_type': '',
                'content_length': 0,
                'content_preview': ''
            }
    
    async def _analyze_cors(self, url: str) -> Dict[str, Any]:
        """Analyze CORS configuration."""
        cors_info = {
            'enabled': False,
            'allow_origin': '',
            'allow_methods': [],
            'allow_headers': [],
            'allow_credentials': False,
            'max_age': 0,
            'vulnerabilities': []
        }
        
        try:
            # Send OPTIONS request to check CORS
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Content-Type'
            }
            
            async with self.session.options(url, headers=headers) as response:
                response_headers = response.headers
                
                # Check CORS headers
                allow_origin = response_headers.get('Access-Control-Allow-Origin', '')
                if allow_origin:
                    cors_info['enabled'] = True
                    cors_info['allow_origin'] = allow_origin
                    
                    # Check for wildcard origin vulnerability
                    if allow_origin == '*':
                        cors_info['vulnerabilities'].append('Wildcard origin allowed')
                    
                    # Check if credentials are allowed with wildcard
                    allow_credentials = response_headers.get('Access-Control-Allow-Credentials', '').lower()
                    if allow_credentials == 'true':
                        cors_info['allow_credentials'] = True
                        if allow_origin == '*':
                            cors_info['vulnerabilities'].append('Credentials allowed with wildcard origin')
                
                # Parse allowed methods
                allow_methods = response_headers.get('Access-Control-Allow-Methods', '')
                if allow_methods:
                    cors_info['allow_methods'] = [m.strip() for m in allow_methods.split(',')]
                
                # Parse allowed headers
                allow_headers = response_headers.get('Access-Control-Allow-Headers', '')
                if allow_headers:
                    cors_info['allow_headers'] = [h.strip() for h in allow_headers.split(',')]
                
                # Check max age
                max_age = response_headers.get('Access-Control-Max-Age', '')
                if max_age.isdigit():
                    cors_info['max_age'] = int(max_age)
                
        except Exception:
            pass
        
        return cors_info
    
    def _detect_api_type(self, url: str, methods: Dict[str, Any]) -> str:
        """Detect the type of API."""
        url_lower = url.lower()
        
        # Check URL patterns
        if '/graphql' in url_lower or '/graphiql' in url_lower:
            return 'graphql'
        elif '/api/' in url_lower:
            return 'rest'
        elif '/v1/' in url_lower or '/v2/' in url_lower:
            return 'rest'
        elif '.json' in url_lower:
            return 'json_api'
        elif '/rpc' in url_lower:
            return 'rpc'
        
        # Check response content
        for method, result in methods.items():
            if result and result.get('status_code') == 200:
                content = result.get('content_preview', '').lower()
                content_type = result.get('content_type', '').lower()
                
                if 'application/json' in content_type:
                    if 'data' in content and 'query' in content:
                        return 'graphql'
                    elif any(keyword in content for keyword in ['api', 'endpoint', 'resource']):
                        return 'rest'
                    else:
                        return 'json_api'
                elif 'application/xml' in content_type:
                    return 'soap'
        
        return 'unknown'
    
    async def _check_vulnerabilities(self, url: str, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for common API vulnerabilities."""
        vulnerabilities = []
        
        # Check for open endpoints (no authentication required)
        get_result = analysis['methods'].get('GET', {})
        if get_result and get_result.get('status_code') == 200:
            vulnerabilities.append({
                'type': 'open_endpoint',
                'severity': 'medium',
                'description': 'Endpoint accessible without authentication',
                'evidence': f"GET request returned {get_result.get('status_code')}"
            })
        
        # Check for verbose error messages
        for method, result in analysis['methods'].items():
            if result and result.get('status_code') in [400, 401, 403, 404, 500]:
                content = result.get('content_preview', '')
                if any(keyword in content.lower() for keyword in ['stack trace', 'exception', 'error', 'debug']):
                    vulnerabilities.append({
                        'type': 'verbose_errors',
                        'severity': 'low',
                        'description': 'Verbose error messages may leak information',
                        'evidence': f"{method} request revealed error details"
                    })
        
        # Check for missing security headers
        security_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']
        for method, result in analysis['methods'].items():
            if result and result.get('status_code') == 200:
                headers = result.get('headers', {})
                missing_headers = [h for h in security_headers if h not in headers]
                if missing_headers:
                    vulnerabilities.append({
                        'type': 'missing_security_headers',
                        'severity': 'low',
                        'description': f'Missing security headers: {", ".join(missing_headers)}',
                        'evidence': f"Headers missing in {method} response"
                    })
                break
        
        # Check CORS vulnerabilities
        cors_vulns = analysis.get('cors_config', {}).get('vulnerabilities', [])
        for vuln in cors_vulns:
            vulnerabilities.append({
                'type': 'cors_misconfiguration',
                'severity': 'high',
                'description': vuln,
                'evidence': 'CORS configuration analysis'
            })
        
        return vulnerabilities
    
    def _extract_parameters(self, methods: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract parameters from API responses."""
        parameters = []
        
        for method, result in methods.items():
            if result and result.get('status_code') == 200:
                content = result.get('content_preview', '')
                
                # Try to parse as JSON
                try:
                    if content.strip().startswith(('{', '[')):
                        json_data = json.loads(content)
                        params = self._extract_json_parameters(json_data)
                        parameters.extend(params)
                except Exception:
                    pass
                
                # Extract from query parameters in URL
                if '?' in result.get('url', ''):
                    query_params = self._extract_query_parameters(result['url'])
                    parameters.extend(query_params)
        
        # Remove duplicates
        seen_params = set()
        unique_params = []
        for param in parameters:
            param_key = param.get('name', '')
            if param_key and param_key not in seen_params:
                seen_params.add(param_key)
                unique_params.append(param)
        
        return unique_params
    
    def _extract_json_parameters(self, json_data: Any, prefix: str = "") -> List[Dict[str, Any]]:
        """Extract parameters from JSON data."""
        parameters = []
        
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                param_name = f"{prefix}.{key}" if prefix else key
                
                parameters.append({
                    'name': param_name,
                    'type': type(value).__name__,
                    'example_value': str(value)[:100] if value is not None else None,
                    'source': 'json_response'
                })
                
                # Recursively extract nested parameters
                if isinstance(value, (dict, list)) and len(str(value)) < 1000:
                    nested_params = self._extract_json_parameters(value, param_name)
                    parameters.extend(nested_params)
        
        elif isinstance(json_data, list) and json_data:
            # Analyze first item in array
            if isinstance(json_data[0], dict):
                nested_params = self._extract_json_parameters(json_data[0], prefix)
                parameters.extend(nested_params)
        
        return parameters
    
    def _extract_query_parameters(self, url: str) -> List[Dict[str, Any]]:
        """Extract parameters from URL query string."""
        parameters = []
        
        try:
            parsed = urlparse(url)
            if parsed.query:
                for param_pair in parsed.query.split('&'):
                    if '=' in param_pair:
                        name, value = param_pair.split('=', 1)
                        parameters.append({
                            'name': name,
                            'type': 'string',
                            'example_value': value,
                            'source': 'query_parameter'
                        })
        except Exception:
            pass
        
        return parameters
    
    def _analyze_security_headers(self, methods: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security headers in responses."""
        security_analysis = {
            'present_headers': [],
            'missing_headers': [],
            'header_values': {},
            'security_score': 0
        }
        
        # Security headers to check
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': None,
            'Content-Security-Policy': None,
            'Referrer-Policy': None
        }
        
        # Analyze headers from successful responses
        for method, result in methods.items():
            if result and result.get('status_code') == 200:
                headers = result.get('headers', {})
                
                for header_name, expected_value in security_headers.items():
                    header_value = headers.get(header_name, '')
                    
                    if header_value:
                        security_analysis['present_headers'].append(header_name)
                        security_analysis['header_values'][header_name] = header_value
                        security_analysis['security_score'] += 1
                        
                        # Check if value is secure
                        if expected_value:
                            if isinstance(expected_value, list):
                                if header_value not in expected_value:
                                    security_analysis['header_values'][f"{header_name}_warning"] = "Potentially insecure value"
                            elif expected_value not in header_value:
                                security_analysis['header_values'][f"{header_name}_warning"] = "Potentially insecure value"
                    else:
                        security_analysis['missing_headers'].append(header_name)
                
                break  # Only analyze first successful response
        
        # Calculate security score (0-100)
        total_headers = len(security_headers)
        security_analysis['security_score'] = int((security_analysis['security_score'] / total_headers) * 100)
        
        return security_analysis
    
    async def check_graphql_introspection(self, url: str) -> Dict[str, Any]:
        """Check if GraphQL introspection is enabled."""
        introspection_result = {
            'enabled': False,
            'schema': None,
            'types': [],
            'queries': [],
            'mutations': [],
            'vulnerabilities': []
        }
        
        # GraphQL introspection query
        introspection_query = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types {
                        ...FullType
                    }
                }
            }
            fragment FullType on __Type {
                kind
                name
                description
                fields(includeDeprecated: true) {
                    name
                    description
                    type {
                        ...TypeRef
                    }
                }
            }
            fragment TypeRef on __Type {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
            """
        }
        
        try:
            async with self.session.post(url, json=introspection_query) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if 'data' in data and '__schema' in data['data']:
                        introspection_result['enabled'] = True
                        introspection_result['schema'] = data['data']['__schema']
                        
                        # Extract types, queries, and mutations
                        schema = data['data']['__schema']
                        types = schema.get('types', [])
                        
                        for type_info in types:
                            if type_info.get('name') and not type_info['name'].startswith('__'):
                                introspection_result['types'].append({
                                    'name': type_info['name'],
                                    'kind': type_info.get('kind'),
                                    'description': type_info.get('description')
                                })
                        
                        # This is a vulnerability
                        introspection_result['vulnerabilities'].append({
                            'type': 'introspection_enabled',
                            'severity': 'high',
                            'description': 'GraphQL introspection is enabled, exposing schema'
                        })
                        
        except Exception:
            pass
        
        return introspection_result
    
    async def check_swagger_openapi(self, base_url: str) -> Dict[str, Any]:
        """Check for Swagger/OpenAPI documentation."""
        swagger_result = {
            'found': False,
            'endpoints': [],
            'spec_url': '',
            'spec_content': None,
            'vulnerabilities': []
        }
        
        # Common Swagger/OpenAPI paths
        swagger_paths = [
            '/swagger.json',
            '/swagger.yaml',
            '/swagger/v1/swagger.json',
            '/api/swagger.json',
            '/api-docs',
            '/api-docs.json',
            '/openapi.json',
            '/openapi.yaml',
            '/docs/swagger.json',
            '/swagger-ui.html',
            '/swagger-ui/',
            '/api/docs'
        ]
        
        for path in swagger_paths:
            try:
                test_url = urljoin(base_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content_type = response.headers.get('content-type', '').lower()
                        
                        if 'json' in content_type or 'yaml' in content_type:
                            try:
                                spec_content = await response.text()
                                
                                # Try to parse as JSON
                                if 'json' in content_type:
                                    spec_data = json.loads(spec_content)
                                else:
                                    # For YAML, we'd need PyYAML, so just store as text
                                    spec_data = spec_content
                                
                                swagger_result['found'] = True
                                swagger_result['spec_url'] = test_url
                                swagger_result['spec_content'] = spec_data
                                
                                # Extract endpoints if JSON
                                if isinstance(spec_data, dict):
                                    paths = spec_data.get('paths', {})
                                    for endpoint_path, methods in paths.items():
                                        swagger_result['endpoints'].append({
                                            'path': endpoint_path,
                                            'methods': list(methods.keys()) if isinstance(methods, dict) else []
                                        })
                                
                                # This could be a vulnerability if exposed in production
                                swagger_result['vulnerabilities'].append({
                                    'type': 'api_documentation_exposed',
                                    'severity': 'medium',
                                    'description': f'API documentation exposed at {test_url}'
                                })
                                
                                break
                                
                            except Exception:
                                continue
                        
            except Exception:
                continue
        
        return swagger_result