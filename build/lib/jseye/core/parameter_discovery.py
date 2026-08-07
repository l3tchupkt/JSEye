"""Advanced Parameter Discovery Engine for JSEye v3.0 - Bug Hunter Edition."""

import re
import json
import ast
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs
from .logging import get_logger

logger = get_logger(__name__)


@dataclass
class Parameter:
    """Represents a discovered parameter."""
    name: str
    param_type: str  # 'query', 'body', 'header', 'path'
    source: str  # 'javascript', 'api_schema', 'endpoint'
    context: str  # Where it was found
    confidence: float  # 0.0 to 1.0
    endpoint: Optional[str] = None
    example_value: Optional[str] = None
    is_hidden: bool = False
    risk_level: str = 'low'  # 'critical', 'high', 'medium', 'low'


@dataclass
class Endpoint:
    """Represents a discovered API endpoint."""
    url: str
    method: str
    parameters: List[Parameter]
    priority: str  # 'high', 'medium', 'low'
    confidence: float
    source: str
    has_auth: bool = False
    returns_json: bool = False
    is_graphql: bool = False
    is_swagger: bool = False
    risk_factors: List[str] = None

    def __post_init__(self):
        if self.risk_factors is None:
            self.risk_factors = []


class ParameterDiscoveryEngine:
    """Advanced parameter discovery for bug hunting."""
    
    def __init__(self):
        # High-risk parameter patterns
        self.hidden_flags = {
            'debug', 'admin', 'isSuper', 'preview', 'testMode', 'role', 
            'featureFlag', 'betaMode', 'internal', 'dev', 'test', 'staging',
            'bypass', 'override', 'force', 'skip', 'disable', 'enable',
            'superuser', 'root', 'system', 'config', 'settings', 'flags'
        }
        
        # Critical parameter names that indicate high-value targets
        self.critical_params = {
            'user_id', 'userId', 'uid', 'id', 'account_id', 'accountId',
            'role', 'permission', 'scope', 'access', 'token', 'key',
            'secret', 'password', 'pass', 'pwd', 'auth', 'session',
            'admin', 'root', 'super', 'privilege', 'level', 'group'
        }
        
        # API endpoint patterns that indicate high value
        self.high_value_patterns = [
            r'/api/v\d+/admin',
            r'/api/v\d+/internal',
            r'/api/v\d+/debug',
            r'/api/v\d+/test',
            r'/api/v\d+/users?/\d+',
            r'/api/v\d+/accounts?/\d+',
            r'/graphql',
            r'/swagger',
            r'/openapi',
            r'/_debug',
            r'/_internal',
            r'/management',
            r'/console'
        ]
        
        # JavaScript parameter extraction patterns
        self.js_patterns = {
            'url_search_params': r'new\s+URLSearchParams\([\'"`]([^\'"`]+)[\'"`]\)',
            'fetch_body': r'fetch\([^,]+,\s*{\s*[^}]*body:\s*([^}]+)}',
            'axios_data': r'axios\.[a-z]+\([^,]+,\s*([^,)]+)',
            'query_concat': r'[\'"`]\?([^\'"`]*[=&][^\'"`]*)[\'"`]',
            'json_stringify': r'JSON\.stringify\(([^)]+)\)',
            'form_data': r'new\s+FormData\(\)\s*\.append\([\'"`]([^\'"`]+)[\'"`]',
            'graphql_vars': r'variables:\s*({[^}]+})',
            'object_literal': r'{\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:',
        }
    
    def discover_parameters(self, js_files: List[Dict[str, Any]], 
                          endpoints: List[str] = None) -> Dict[str, Any]:
        """Main parameter discovery function."""
        all_parameters = []
        discovered_endpoints = []
        
        # Extract from JavaScript files
        for js_file in js_files:
            params = self._extract_from_javascript(js_file)
            all_parameters.extend(params)
            
            # Also discover endpoints from JS
            js_endpoints = self._extract_endpoints_from_js(js_file)
            discovered_endpoints.extend(js_endpoints)
        
        # Process provided endpoints
        if endpoints:
            for endpoint in endpoints:
                endpoint_params = self._extract_from_endpoint(endpoint)
                all_parameters.extend(endpoint_params)
        
        # Normalize and deduplicate
        normalized_params = self._normalize_parameters(all_parameters)
        
        # Classify and prioritize endpoints
        prioritized_endpoints = self._prioritize_endpoints(discovered_endpoints)
        
        # Generate wordlists
        wordlists = self._generate_wordlists(normalized_params)
        
        return {
            'parameters': normalized_params,
            'endpoints': prioritized_endpoints,
            'wordlists': wordlists,
            'statistics': {
                'total_parameters': len(normalized_params),
                'high_risk_parameters': len([p for p in normalized_params if p.risk_level in ['critical', 'high']]),
                'hidden_flags': len([p for p in normalized_params if p.is_hidden]),
                'total_endpoints': len(prioritized_endpoints),
                'high_priority_endpoints': len([e for e in prioritized_endpoints if e.priority == 'high'])
            }
        }
    
    def _extract_from_javascript(self, js_file: Dict[str, Any]) -> List[Parameter]:
        """Extract parameters from JavaScript content."""
        content = js_file.get('content', '')
        url = js_file.get('url', '')
        parameters = []
        
        # Extract using regex patterns
        for pattern_name, pattern in self.js_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                try:
                    if pattern_name == 'url_search_params':
                        # Parse query string
                        query_params = self._parse_query_string(match.group(1))
                        for param_name in query_params:
                            parameters.append(Parameter(
                                name=param_name,
                                param_type='query',
                                source='javascript',
                                context=f"URLSearchParams in {url}",
                                confidence=0.9,
                                endpoint=url,
                                is_hidden=self._is_hidden_flag(param_name),
                                risk_level=self._assess_param_risk(param_name)
                            ))
                    
                    elif pattern_name in ['fetch_body', 'axios_data']:
                        # Parse request body
                        body_params = self._parse_request_body(match.group(1))
                        for param_name in body_params:
                            parameters.append(Parameter(
                                name=param_name,
                                param_type='body',
                                source='javascript',
                                context=f"{pattern_name} in {url}",
                                confidence=0.8,
                                endpoint=url,
                                is_hidden=self._is_hidden_flag(param_name),
                                risk_level=self._assess_param_risk(param_name)
                            ))
                    
                    elif pattern_name == 'form_data':
                        param_name = match.group(1)
                        parameters.append(Parameter(
                            name=param_name,
                            param_type='body',
                            source='javascript',
                            context=f"FormData in {url}",
                            confidence=0.9,
                            endpoint=url,
                            is_hidden=self._is_hidden_flag(param_name),
                            risk_level=self._assess_param_risk(param_name)
                        ))
                    
                    elif pattern_name == 'graphql_vars':
                        # Parse GraphQL variables
                        gql_params = self._parse_graphql_variables(match.group(1))
                        for param_name in gql_params:
                            parameters.append(Parameter(
                                name=param_name,
                                param_type='body',
                                source='javascript',
                                context=f"GraphQL variables in {url}",
                                confidence=0.9,
                                endpoint=url,
                                is_hidden=self._is_hidden_flag(param_name),
                                risk_level=self._assess_param_risk(param_name)
                            ))
                    
                    elif pattern_name == 'object_literal':
                        param_name = match.group(1)
                        parameters.append(Parameter(
                            name=param_name,
                            param_type='body',
                            source='javascript',
                            context=f"Object literal in {url}",
                            confidence=0.6,
                            endpoint=url,
                            is_hidden=self._is_hidden_flag(param_name),
                            risk_level=self._assess_param_risk(param_name)
                        ))
                
                except Exception as e:
                    logger.debug(f"Error parsing {pattern_name}: {e}")
                    continue
        
        # Extract from inline URLs and API calls
        url_params = self._extract_url_parameters(content, url)
        parameters.extend(url_params)
        
        return parameters
    
    def _extract_endpoints_from_js(self, js_file: Dict[str, Any]) -> List[Endpoint]:
        """Extract API endpoints from JavaScript."""
        content = js_file.get('content', '')
        url = js_file.get('url', '')
        endpoints = []
        
        # API endpoint patterns
        api_patterns = [
            r'[\'"`](/api/[^\'"`\s]+)[\'"`]',
            r'[\'"`](https?://[^\'"`\s]+/api/[^\'"`\s]+)[\'"`]',
            r'fetch\([\'"`]([^\'"`]+)[\'"`]',
            r'axios\.[a-z]+\([\'"`]([^\'"`]+)[\'"`]',
            r'[\'"`](/graphql[^\'"`]*)[\'"`]',
            r'[\'"`](/swagger[^\'"`]*)[\'"`]',
            r'[\'"`]([^\'"`]*\.json)[\'"`]'
        ]
        
        for pattern in api_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                endpoint_url = match.group(1)
                
                # Skip if it's not a valid endpoint
                if not self._is_valid_endpoint(endpoint_url):
                    continue
                
                # Determine method (default to GET)
                method = self._determine_http_method(content, endpoint_url)
                
                # Assess priority
                priority = self._assess_endpoint_priority(endpoint_url)
                
                # Check for risk factors
                risk_factors = self._identify_risk_factors(endpoint_url, content)
                
                endpoints.append(Endpoint(
                    url=endpoint_url,
                    method=method,
                    parameters=[],  # Will be populated later
                    priority=priority,
                    confidence=0.8,
                    source='javascript',
                    returns_json='.json' in endpoint_url or 'api/' in endpoint_url,
                    is_graphql='graphql' in endpoint_url.lower(),
                    is_swagger='swagger' in endpoint_url.lower() or 'openapi' in endpoint_url.lower(),
                    risk_factors=risk_factors
                ))
        
        return endpoints
    
    def _extract_from_endpoint(self, endpoint: str) -> List[Parameter]:
        """Extract parameters from endpoint URL."""
        parameters = []
        
        try:
            parsed = urlparse(endpoint)
            
            # Extract query parameters
            if parsed.query:
                query_params = parse_qs(parsed.query)
                for param_name, values in query_params.items():
                    example_value = values[0] if values else None
                    
                    parameters.append(Parameter(
                        name=param_name,
                        param_type='query',
                        source='endpoint',
                        context=f"Query parameter in {endpoint}",
                        confidence=1.0,
                        endpoint=endpoint,
                        example_value=example_value,
                        is_hidden=self._is_hidden_flag(param_name),
                        risk_level=self._assess_param_risk(param_name)
                    ))
            
            # Extract path parameters (e.g., /api/users/{id})
            path_params = re.findall(r'\{([^}]+)\}', parsed.path)
            for param_name in path_params:
                parameters.append(Parameter(
                    name=param_name,
                    param_type='path',
                    source='endpoint',
                    context=f"Path parameter in {endpoint}",
                    confidence=1.0,
                    endpoint=endpoint,
                    is_hidden=self._is_hidden_flag(param_name),
                    risk_level=self._assess_param_risk(param_name)
                ))
        
        except Exception as e:
            logger.debug(f"Error parsing endpoint {endpoint}: {e}")
        
        return parameters
    
    def _parse_query_string(self, query_string: str) -> List[str]:
        """Parse query string and extract parameter names."""
        params = []
        
        # Handle both & and ; separators
        pairs = re.split(r'[&;]', query_string)
        
        for pair in pairs:
            if '=' in pair:
                param_name = pair.split('=')[0].strip()
                if param_name and param_name not in params:
                    params.append(param_name)
        
        return params
    
    def _parse_request_body(self, body_str: str) -> List[str]:
        """Parse request body and extract parameter names."""
        params = []
        
        try:
            # Try to parse as JSON
            if body_str.strip().startswith('{'):
                # Extract object keys
                keys = re.findall(r'[\'"`]?([a-zA-Z_$][a-zA-Z0-9_$]*)[\'"`]?\s*:', body_str)
                params.extend(keys)
            
            # Try to parse as form data
            elif '=' in body_str:
                form_params = self._parse_query_string(body_str)
                params.extend(form_params)
        
        except Exception:
            pass
        
        return list(set(params))
    
    def _parse_graphql_variables(self, variables_str: str) -> List[str]:
        """Parse GraphQL variables object."""
        params = []
        
        try:
            # Extract keys from object literal
            keys = re.findall(r'[\'"`]?([a-zA-Z_$][a-zA-Z0-9_$]*)[\'"`]?\s*:', variables_str)
            params.extend(keys)
        
        except Exception:
            pass
        
        return params
    
    def _extract_url_parameters(self, content: str, source_url: str) -> List[Parameter]:
        """Extract parameters from URLs in content."""
        parameters = []
        
        # Find all URLs in the content
        url_pattern = r'https?://[^\s\'"<>]+|\b/[^\s\'"<>]*\?[^\s\'"<>]+'
        urls = re.findall(url_pattern, content)
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    query_params = parse_qs(parsed.query)
                    for param_name in query_params.keys():
                        parameters.append(Parameter(
                            name=param_name,
                            param_type='query',
                            source='javascript',
                            context=f"URL in {source_url}",
                            confidence=0.7,
                            endpoint=url,
                            is_hidden=self._is_hidden_flag(param_name),
                            risk_level=self._assess_param_risk(param_name)
                        ))
            
            except Exception:
                continue
        
        return parameters
    
    def _is_hidden_flag(self, param_name: str) -> bool:
        """Check if parameter is a hidden flag."""
        param_lower = param_name.lower()
        
        # Direct match
        if param_lower in self.hidden_flags:
            return True
        
        # Partial match
        for flag in self.hidden_flags:
            if flag in param_lower or param_lower in flag:
                return True
        
        # Pattern-based detection
        hidden_patterns = [
            r'debug',
            r'admin',
            r'test',
            r'dev',
            r'internal',
            r'super',
            r'root',
            r'bypass',
            r'override'
        ]
        
        for pattern in hidden_patterns:
            if re.search(pattern, param_lower):
                return True
        
        return False
    
    def _assess_param_risk(self, param_name: str) -> str:
        """Assess parameter risk level."""
        param_lower = param_name.lower()
        
        # Critical parameters
        if param_lower in self.critical_params:
            return 'critical'
        
        # High-risk patterns
        high_risk_patterns = [
            r'admin', r'root', r'super', r'privilege', r'role', r'permission',
            r'token', r'key', r'secret', r'password', r'auth', r'session',
            r'user_?id', r'account_?id', r'bypass', r'override'
        ]
        
        for pattern in high_risk_patterns:
            if re.search(pattern, param_lower):
                return 'high'
        
        # Medium-risk patterns
        medium_risk_patterns = [
            r'debug', r'test', r'dev', r'internal', r'config', r'settings',
            r'flag', r'mode', r'level', r'access', r'scope'
        ]
        
        for pattern in medium_risk_patterns:
            if re.search(pattern, param_lower):
                return 'medium'
        
        return 'low'
    
    def _is_valid_endpoint(self, url: str) -> bool:
        """Check if URL is a valid API endpoint."""
        # Skip static assets
        static_extensions = ['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.ttf']
        if any(url.lower().endswith(ext) for ext in static_extensions):
            return False
        
        # Skip tracking/analytics
        tracking_domains = ['google-analytics', 'googletagmanager', 'facebook.com', 'doubleclick']
        if any(domain in url.lower() for domain in tracking_domains):
            return False
        
        # Must look like an API endpoint
        api_indicators = ['/api/', '/graphql', '/swagger', '.json', '/v1/', '/v2/', '/v3/']
        return any(indicator in url.lower() for indicator in api_indicators)
    
    def _determine_http_method(self, content: str, endpoint: str) -> str:
        """Determine HTTP method for endpoint."""
        # Look for method indicators around the endpoint
        context_window = 100
        
        # Find endpoint in content
        endpoint_pos = content.find(endpoint)
        if endpoint_pos == -1:
            return 'GET'
        
        # Extract context around endpoint
        start = max(0, endpoint_pos - context_window)
        end = min(len(content), endpoint_pos + len(endpoint) + context_window)
        context = content[start:end].lower()
        
        # Check for method indicators
        if any(method in context for method in ['post', 'put', 'patch']):
            if 'post' in context:
                return 'POST'
            elif 'put' in context:
                return 'PUT'
            elif 'patch' in context:
                return 'PATCH'
        
        return 'GET'
    
    def _assess_endpoint_priority(self, endpoint: str) -> str:
        """Assess endpoint priority for bug hunting."""
        endpoint_lower = endpoint.lower()
        
        # High priority indicators
        high_priority_indicators = [
            'admin', 'internal', 'debug', 'test', 'management', 'console',
            'graphql', 'swagger', 'openapi', '_debug', '_internal',
            '/users/', '/accounts/', '/profile', '/settings'
        ]
        
        for indicator in high_priority_indicators:
            if indicator in endpoint_lower:
                return 'high'
        
        # Medium priority indicators
        medium_priority_indicators = [
            '/api/', '/v1/', '/v2/', '/v3/', '.json', '/data/', '/info/'
        ]
        
        for indicator in medium_priority_indicators:
            if indicator in endpoint_lower:
                return 'medium'
        
        return 'low'
    
    def _identify_risk_factors(self, endpoint: str, content: str) -> List[str]:
        """Identify risk factors for endpoint."""
        risk_factors = []
        endpoint_lower = endpoint.lower()
        
        # Check for high-value patterns
        if 'admin' in endpoint_lower:
            risk_factors.append('admin_endpoint')
        
        if 'graphql' in endpoint_lower:
            risk_factors.append('graphql_endpoint')
        
        if 'swagger' in endpoint_lower or 'openapi' in endpoint_lower:
            risk_factors.append('api_documentation')
        
        if any(pattern in endpoint_lower for pattern in ['debug', 'test', 'internal']):
            risk_factors.append('debug_endpoint')
        
        # Check if endpoint appears multiple times (high confidence)
        if content.count(endpoint) > 1:
            risk_factors.append('multiple_references')
        
        # Check for authentication indicators
        auth_patterns = ['auth', 'token', 'login', 'session']
        if not any(pattern in content.lower() for pattern in auth_patterns):
            risk_factors.append('no_auth_required')
        
        return risk_factors
    
    def _normalize_parameters(self, parameters: List[Parameter]) -> List[Parameter]:
        """Normalize and deduplicate parameters."""
        # Group by name and type
        param_groups = {}
        
        for param in parameters:
            key = (param.name, param.param_type)
            
            if key not in param_groups:
                param_groups[key] = param
            else:
                # Keep the one with higher confidence
                if param.confidence > param_groups[key].confidence:
                    param_groups[key] = param
        
        return list(param_groups.values())
    
    def _prioritize_endpoints(self, endpoints: List[Endpoint]) -> List[Endpoint]:
        """Prioritize endpoints for bug hunting."""
        # Sort by priority and confidence
        priority_order = {'high': 3, 'medium': 2, 'low': 1}
        
        return sorted(endpoints, 
                     key=lambda e: (priority_order.get(e.priority, 0), e.confidence), 
                     reverse=True)
    
    def _generate_wordlists(self, parameters: List[Parameter]) -> Dict[str, List[str]]:
        """Generate parameter wordlists for fuzzing."""
        wordlists = {
            'all_parameters': [],
            'query_parameters': [],
            'body_parameters': [],
            'high_risk_parameters': [],
            'hidden_flags': []
        }
        
        for param in parameters:
            # All parameters
            if param.name not in wordlists['all_parameters']:
                wordlists['all_parameters'].append(param.name)
            
            # By type
            if param.param_type == 'query' and param.name not in wordlists['query_parameters']:
                wordlists['query_parameters'].append(param.name)
            
            if param.param_type == 'body' and param.name not in wordlists['body_parameters']:
                wordlists['body_parameters'].append(param.name)
            
            # By risk level
            if param.risk_level in ['critical', 'high'] and param.name not in wordlists['high_risk_parameters']:
                wordlists['high_risk_parameters'].append(param.name)
            
            # Hidden flags
            if param.is_hidden and param.name not in wordlists['hidden_flags']:
                wordlists['hidden_flags'].append(param.name)
        
        # Sort all wordlists
        for key in wordlists:
            wordlists[key].sort()
        
        return wordlists