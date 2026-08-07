"""API Intelligence Plugin for JSEye v2.0."""

import asyncio
from typing import Dict, List, Any
from jseye.plugins.base import BasePlugin, PluginMetadata, PluginContext, PluginResult, PluginCategory, ExploitationLikelihood, ExposureLevel
from jseye.core.api_engine import APIIntelligence
from jseye.core.logging import get_logger

logger = get_logger(__name__)


class APIIntelligencePlugin(BasePlugin):
    """Plugin for analyzing discovered API endpoints and configurations."""
    
    def __init__(self):
        super().__init__()
    
    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="api_intelligence",
            version="2.0.2",
            category=PluginCategory.INTELLIGENCE,
            risk_weight=0.7,  # Medium-high weight for API vulnerabilities
            description="Analyzes discovered API endpoints for security misconfigurations and vulnerabilities",
            author="JSEye Team",
            requires=[],
            enabled=True,
            execution_order=40
        )
    
    async def validate_context(self, context: PluginContext) -> bool:
        """Validate that context is valid (always true - can handle empty data)."""
        return True
    
    async def run(self, context: PluginContext) -> PluginResult:
        """Execute API intelligence analysis."""
        result = self.create_result()
        start_time = asyncio.get_event_loop().time()
        
        try:
            logger.info("Starting API intelligence analysis", 
                       target=context.target)
            
            # Handle case with no JavaScript files or endpoints
            if not context.js_files:
                logger.info("No JavaScript files to analyze for APIs", target=context.target)
                result.metadata = {
                    'total_js_files': 0,
                    'endpoints_discovered': 0,
                    'vulnerabilities_found': 0,
                    'analysis_summary': 'No JavaScript files found for API analysis'
                }
                return result
            
            # Collect endpoints from various sources
            all_endpoints = set()
            
            # Get endpoints from shared context (from other plugins)
            shared_endpoints = context.get_shared_data('discovered_endpoints', [])
            all_endpoints.update(shared_endpoints)
            
            # Extract endpoints from JavaScript files
            for js_file in context.js_files:
                content = js_file.get('content', '')
                if content:
                    # Simple endpoint extraction (could be enhanced)
                    import re
                    url_patterns = [
                        r'["\']https?://[^"\']+["\']',
                        r'["\']\/api\/[^"\']+["\']',
                        r'["\']\/v\d+\/[^"\']+["\']'
                    ]
                    
                    for pattern in url_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            endpoint = match.strip('"\'')
                            all_endpoints.add(endpoint)
            
            if not all_endpoints:
                logger.info("No API endpoints found for analysis", target=context.target)
                return result
            
            endpoints_list = list(all_endpoints)[:50]  # Limit to avoid overwhelming
            network_calls = 0
            
            async with APIIntelligence(timeout=10, max_concurrent=10) as api_engine:
                # Analyze endpoints
                api_analysis = await api_engine.analyze_endpoints(endpoints_list, context.target)
                network_calls += len(endpoints_list) * 3  # Approximate network calls
                
                # Check for GraphQL
                graphql_endpoints = [ep for ep in endpoints_list if 'graphql' in ep.lower()]
                for gql_endpoint in graphql_endpoints:
                    gql_analysis = await api_engine.check_graphql_introspection(gql_endpoint)
                    network_calls += 1
                    
                    if gql_analysis.get('enabled'):
                        api_analysis.append({
                            'url': gql_endpoint,
                            'type': 'graphql_introspection',
                            'analysis': gql_analysis
                        })
                
                # Check for Swagger/OpenAPI
                swagger_analysis = await api_engine.check_swagger_openapi(context.target)
                network_calls += 5  # Approximate swagger endpoint checks
                
                if swagger_analysis.get('found'):
                    api_analysis.append({
                        'url': swagger_analysis.get('spec_url', ''),
                        'type': 'swagger_openapi',
                        'analysis': swagger_analysis
                    })
                
                # Process analysis results into findings
                total_endpoints = len(api_analysis)
                vulnerable_endpoints = 0
                
                for api_result in api_analysis:
                    try:
                        findings = self._process_api_analysis(api_result)
                        for finding in findings:
                            result.add_finding(finding)
                            if finding.get('severity') in ['high', 'critical']:
                                vulnerable_endpoints += 1
                    except Exception as e:
                        logger.warning(f"Failed to process API analysis for {api_result.get('url', 'unknown')}: {e}")
                
                # Sort findings by risk score
                result.findings.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
                
                # Add metadata
                result.metadata = {
                    'total_endpoints_analyzed': total_endpoints,
                    'vulnerable_endpoints': vulnerable_endpoints,
                    'endpoint_types': self._get_endpoint_type_distribution(api_analysis),
                    'vulnerability_types': self._get_vulnerability_type_distribution(result.findings),
                    'cors_issues': len([f for f in result.findings if f.get('subtype') == 'cors_misconfiguration']),
                    'open_endpoints': len([f for f in result.findings if f.get('subtype') == 'open_endpoint']),
                    'security_headers_missing': len([f for f in result.findings if f.get('subtype') == 'missing_security_headers'])
                }
                
                # Update network calls count
                result.network_calls = network_calls
                
                # Store results in shared context
                context.add_shared_data('api_analysis', api_analysis)
                context.add_shared_data('api_findings', result.findings)
                
                logger.info("API intelligence analysis completed", 
                           target=context.target,
                           endpoints_analyzed=total_endpoints,
                           vulnerable_endpoints=vulnerable_endpoints)
                
        except Exception as e:
            error_msg = f"API intelligence plugin failed: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg, target=context.target)
        
        finally:
            result.execution_time = asyncio.get_event_loop().time() - start_time
        
        return result
    
    def _process_api_analysis(self, api_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process API analysis result into findings."""
        findings = []
        url = api_result.get('url', '')
        
        # Handle different analysis types
        analysis_type = api_result.get('type', 'endpoint')
        
        if analysis_type == 'graphql_introspection':
            finding = self._create_graphql_finding(api_result)
            if finding:
                findings.append(finding)
        
        elif analysis_type == 'swagger_openapi':
            finding = self._create_swagger_finding(api_result)
            if finding:
                findings.append(finding)
        
        else:
            # Regular endpoint analysis
            vulnerabilities = api_result.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                finding = self._create_vulnerability_finding(api_result, vuln)
                if finding:
                    findings.append(finding)
            
            # Check CORS issues
            cors_config = api_result.get('cors_config', {})
            cors_vulns = cors_config.get('vulnerabilities', [])
            
            for cors_vuln in cors_vulns:
                finding = self._create_cors_finding(api_result, cors_vuln)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _create_graphql_finding(self, api_result: Dict[str, Any]) -> Dict[str, Any]:
        """Create finding for GraphQL introspection vulnerability."""
        analysis = api_result.get('analysis', {})
        url = api_result.get('url', '')
        
        if not analysis.get('enabled'):
            return None
        
        # Calculate confidence and risk
        base_confidence = 95.0  # High confidence for confirmed introspection
        contributing_factors = [
            "GraphQL introspection query successful",
            "Schema information exposed",
            f"Types found: {len(analysis.get('types', []))}"
        ]
        
        confidence_factors = self.calculate_confidence(
            base_confidence=base_confidence,
            contributing_factors=contributing_factors
        )
        
        risk_metrics = self.create_risk_metrics(
            confidence_score=confidence_factors.final_confidence,
            exploitation_likelihood=ExploitationLikelihood.HIGH,
            stability_score=90.0,
            exposure_level=ExposureLevel.EXTERNAL,
            contributing_factors=contributing_factors
        )
        
        return {
            'id': f"graphql_introspection_{hash(url) % 10000}",
            'type': 'api_vulnerability',
            'subtype': 'graphql_introspection',
            'title': 'GraphQL Introspection Enabled',
            'description': 'GraphQL introspection is enabled, exposing schema information to attackers',
            'severity': 'high',
            'confidence_score': confidence_factors.final_confidence,
            'risk_score': 75,
            'source_file': url,
            'location': {
                'url': url,
                'endpoint_type': 'graphql'
            },
            'evidence': {
                'introspection_enabled': True,
                'schema_types': len(analysis.get('types', [])),
                'queries_available': len(analysis.get('queries', [])),
                'mutations_available': len(analysis.get('mutations', []))
            },
            'risk_metrics': vars(risk_metrics),
            'confidence_factors': vars(confidence_factors),
            'remediation': 'Disable GraphQL introspection in production environments',
            'references': [
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL'
            ],
            'raw_data': api_result
        }
    
    def _create_swagger_finding(self, api_result: Dict[str, Any]) -> Dict[str, Any]:
        """Create finding for exposed Swagger/OpenAPI documentation."""
        analysis = api_result.get('analysis', {})
        url = api_result.get('url', '')
        
        if not analysis.get('found'):
            return None
        
        base_confidence = 90.0
        contributing_factors = [
            "API documentation publicly accessible",
            f"Endpoints exposed: {len(analysis.get('endpoints', []))}"
        ]
        
        confidence_factors = self.calculate_confidence(
            base_confidence=base_confidence,
            contributing_factors=contributing_factors
        )
        
        risk_metrics = self.create_risk_metrics(
            confidence_score=confidence_factors.final_confidence,
            exploitation_likelihood=ExploitationLikelihood.MEDIUM,
            stability_score=85.0,
            exposure_level=ExposureLevel.EXTERNAL,
            contributing_factors=contributing_factors
        )
        
        return {
            'id': f"swagger_exposed_{hash(url) % 10000}",
            'type': 'api_vulnerability',
            'subtype': 'exposed_documentation',
            'title': 'API Documentation Publicly Accessible',
            'description': 'Swagger/OpenAPI documentation is publicly accessible, revealing API structure',
            'severity': 'medium',
            'confidence_score': confidence_factors.final_confidence,
            'risk_score': 50,
            'source_file': url,
            'location': {
                'url': url,
                'spec_url': analysis.get('spec_url', '')
            },
            'evidence': {
                'documentation_type': 'swagger/openapi',
                'endpoints_exposed': len(analysis.get('endpoints', [])),
                'spec_accessible': True
            },
            'risk_metrics': vars(risk_metrics),
            'confidence_factors': vars(confidence_factors),
            'remediation': 'Restrict access to API documentation in production environments',
            'references': [
                'https://owasp.org/www-project-api-security/'
            ],
            'raw_data': api_result
        }
    
    def _create_vulnerability_finding(self, api_result: Dict[str, Any], vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Create finding for API vulnerability."""
        url = api_result.get('url', '')
        vuln_type = vuln.get('type', 'unknown')
        severity = vuln.get('severity', 'medium')
        
        # Map severity to risk score
        severity_scores = {
            'critical': 90,
            'high': 75,
            'medium': 50,
            'low': 25
        }
        risk_score = severity_scores.get(severity, 50)
        
        base_confidence = 80.0
        contributing_factors = [
            f"Vulnerability type: {vuln_type}",
            f"Evidence: {vuln.get('evidence', 'Direct observation')}"
        ]
        
        confidence_factors = self.calculate_confidence(
            base_confidence=base_confidence,
            contributing_factors=contributing_factors
        )
        
        risk_metrics = self.create_risk_metrics(
            confidence_score=confidence_factors.final_confidence,
            exploitation_likelihood=self._map_severity_to_exploitation(severity),
            stability_score=75.0,
            exposure_level=ExposureLevel.EXTERNAL,
            contributing_factors=contributing_factors
        )
        
        return {
            'id': f"api_vuln_{vuln_type}_{hash(url) % 10000}",
            'type': 'api_vulnerability',
            'subtype': vuln_type,
            'title': f"API Vulnerability: {vuln.get('description', vuln_type)}",
            'description': vuln.get('description', f'{vuln_type} vulnerability detected'),
            'severity': severity,
            'confidence_score': confidence_factors.final_confidence,
            'risk_score': risk_score,
            'source_file': url,
            'location': {
                'url': url,
                'endpoint_type': api_result.get('api_type', 'unknown')
            },
            'evidence': {
                'vulnerability_type': vuln_type,
                'evidence': vuln.get('evidence', ''),
                'methods_tested': list(api_result.get('methods', {}).keys())
            },
            'risk_metrics': vars(risk_metrics),
            'confidence_factors': vars(confidence_factors),
            'remediation': self._get_vulnerability_remediation(vuln_type),
            'references': [
                'https://owasp.org/www-project-api-security/'
            ],
            'raw_data': vuln
        }
    
    def _create_cors_finding(self, api_result: Dict[str, Any], cors_vuln: str) -> Dict[str, Any]:
        """Create finding for CORS misconfiguration."""
        url = api_result.get('url', '')
        
        base_confidence = 85.0
        contributing_factors = [
            f"CORS issue: {cors_vuln}",
            "CORS configuration analysis"
        ]
        
        confidence_factors = self.calculate_confidence(
            base_confidence=base_confidence,
            contributing_factors=contributing_factors
        )
        
        risk_metrics = self.create_risk_metrics(
            confidence_score=confidence_factors.final_confidence,
            exploitation_likelihood=ExploitationLikelihood.HIGH,
            stability_score=80.0,
            exposure_level=ExposureLevel.EXTERNAL,
            contributing_factors=contributing_factors
        )
        
        return {
            'id': f"cors_vuln_{hash(url + cors_vuln) % 10000}",
            'type': 'api_vulnerability',
            'subtype': 'cors_misconfiguration',
            'title': f"CORS Misconfiguration: {cors_vuln}",
            'description': f'CORS misconfiguration detected: {cors_vuln}',
            'severity': 'high',
            'confidence_score': confidence_factors.final_confidence,
            'risk_score': 70,
            'source_file': url,
            'location': {
                'url': url,
                'cors_issue': cors_vuln
            },
            'evidence': {
                'cors_vulnerability': cors_vuln,
                'cors_config': api_result.get('cors_config', {})
            },
            'risk_metrics': vars(risk_metrics),
            'confidence_factors': vars(confidence_factors),
            'remediation': 'Configure CORS properly: avoid wildcard origins with credentials, restrict origins to trusted domains',
            'references': [
                'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'
            ],
            'raw_data': api_result.get('cors_config', {})
        }
    
    def _map_severity_to_exploitation(self, severity: str) -> ExploitationLikelihood:
        """Map severity to exploitation likelihood."""
        mapping = {
            'critical': ExploitationLikelihood.HIGH,
            'high': ExploitationLikelihood.HIGH,
            'medium': ExploitationLikelihood.MEDIUM,
            'low': ExploitationLikelihood.LOW
        }
        return mapping.get(severity, ExploitationLikelihood.MEDIUM)
    
    def _get_vulnerability_remediation(self, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type."""
        remediation_map = {
            'open_endpoint': 'Implement proper authentication and authorization for API endpoints',
            'verbose_errors': 'Configure error handling to avoid exposing sensitive information',
            'missing_security_headers': 'Implement security headers: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection',
            'cors_misconfiguration': 'Configure CORS properly: avoid wildcard origins, restrict to trusted domains'
        }
        
        return remediation_map.get(vuln_type, 'Review API security configuration and implement appropriate controls')
    
    def _get_endpoint_type_distribution(self, api_analysis: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of endpoint types."""
        distribution = {}
        for api in api_analysis:
            api_type = api.get('api_type', 'unknown')
            distribution[api_type] = distribution.get(api_type, 0) + 1
        return distribution
    
    def _get_vulnerability_type_distribution(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of vulnerability types."""
        distribution = {}
        for finding in findings:
            vuln_type = finding.get('subtype', 'unknown')
            distribution[vuln_type] = distribution.get(vuln_type, 0) + 1
        return distribution