"""JSON report generation for JSEye results."""

import json
from datetime import datetime
from typing import Dict, Any, List
from ..version import __version__


class JSONReportGenerator:
    """Generate JSON reports from scan results."""
    
    def __init__(self):
        self.report_version = "1.0"
    
    def generate_report(self, scan_results: Dict[str, Any], output_file: str = None) -> str:
        """Generate a comprehensive JSON report."""
        report = {
            'jseye_report': {
                'version': self.report_version,
                'jseye_version': __version__,
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'scan_info': self._generate_scan_info(scan_results),
                'summary': self._generate_summary(scan_results),
                'javascript_files': self._process_js_files(scan_results.get('js_files', [])),
                'secrets': self._process_secrets(scan_results.get('secrets', [])),
                'endpoints': self._process_endpoints(scan_results.get('endpoints', [])),
                'parameters': self._process_parameters(scan_results.get('parameters', [])),
                'api_analysis': self._process_api_analysis(scan_results.get('api_analysis', [])),
                'vulnerabilities': self._process_vulnerabilities(scan_results.get('vulnerabilities', [])),
                'statistics': scan_results.get('statistics', {}),
                'errors': scan_results.get('errors', [])
            }
        }
        
        # Add v3.0 prioritization data
        if 'prioritized_endpoints' in scan_results:
            report['jseye_report']['prioritized_endpoints'] = scan_results['prioritized_endpoints']
        
        if 'prioritized_secrets' in scan_results:
            report['jseye_report']['prioritized_secrets'] = scan_results['prioritized_secrets']
        
        if 'prioritized_vulnerabilities' in scan_results:
            report['jseye_report']['prioritized_vulnerabilities'] = scan_results['prioritized_vulnerabilities']
        
        if 'actionable_summary' in scan_results:
            report['jseye_report']['actionable_summary'] = scan_results['actionable_summary']
        
        # Add headless analysis if available
        if 'headless_analysis' in scan_results:
            report['jseye_report']['headless_analysis'] = scan_results['headless_analysis']
        
        # Convert to JSON string
        json_output = json.dumps(report, indent=2, ensure_ascii=False)
        
        # Save to file if specified
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(json_output)
            except Exception as e:
                raise Exception(f"Failed to write JSON report: {str(e)}")
        
        return json_output

    def generate(self, scan_results: Dict[str, Any], output_file: str = None) -> str:
        """Alias for generate_report() for backward compatibility."""
        return self.generate_report(scan_results, output_file)

    def _generate_scan_info(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate scan information section."""
        return {
            'target': scan_results.get('target', ''),
            'scan_config': scan_results.get('scan_config', {}),
            'scan_duration': 'N/A',  # Could be calculated if timing is tracked
            'scan_type': 'full_deep_scan'
        }
    
    def _generate_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary section."""
        stats = scan_results.get('statistics', {})
        
        # Calculate risk score
        risk_distribution = stats.get('risk_distribution', {})
        risk_score = (
            risk_distribution.get('Critical', 0) * 25 +
            risk_distribution.get('High', 0) * 15 +
            risk_distribution.get('Medium', 0) * 8 +
            risk_distribution.get('Low', 0) * 3
        )
        
        # Determine overall risk level
        if risk_score >= 80:
            overall_risk = 'Critical'
        elif risk_score >= 50:
            overall_risk = 'High'
        elif risk_score >= 20:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'
        
        return {
            'total_js_files': stats.get('total_js_files', 0),
            'total_secrets_found': stats.get('total_secrets', 0),
            'total_endpoints_discovered': stats.get('total_endpoints', 0),
            'total_apis_analyzed': stats.get('total_apis_analyzed', 0),
            'total_vulnerabilities': len(scan_results.get('vulnerabilities', [])),
            'risk_score': risk_score,
            'overall_risk_level': overall_risk,
            'file_size_analyzed_mb': round(stats.get('total_js_size', 0) / (1024 * 1024), 2),
            'scan_errors': stats.get('total_errors', 0)
        }
    
    def _process_js_files(self, js_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process JavaScript files for the report."""
        processed_files = []
        
        for js_file in js_files:
            processed_file = {
                'url': js_file.get('url', ''),
                'size_bytes': js_file.get('size', 0),
                'hash': js_file.get('hash', ''),
                'source': js_file.get('source', 'direct'),
                'type': js_file.get('type', 'unknown'),
                'source_map': js_file.get('source_map'),
                'content_preview': js_file.get('content', '')[:200] + '...' if js_file.get('content') else None
            }
            
            # Remove content from report to keep size manageable
            if 'content' in processed_file:
                del processed_file['content']
            
            processed_files.append(processed_file)
        
        return processed_files
    
    def _process_secrets(self, secrets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process secrets for the report."""
        processed_secrets = []
        
        for secret in secrets:
            processed_secret = {
                'type': secret.get('type', ''),
                'description': secret.get('description', ''),
                'value_masked': secret.get('value_masked', ''),
                'severity': secret.get('severity', ''),
                'confidence': secret.get('confidence', 0),
                'risk_score': secret.get('risk_score', 0),
                'risk_level': secret.get('risk_level', ''),
                'risk_factors': secret.get('risk_factors', []),
                'source_file': secret.get('source_file', ''),
                'context': secret.get('context', ''),
                'detection_method': secret.get('detection_method', ''),
                'remediation': secret.get('remediation', ''),
                'entropy': secret.get('entropy')
            }
            
            processed_secrets.append(processed_secret)
        
        return processed_secrets

    def _process_parameters(self, parameters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process parameter data for report."""
        from dataclasses import asdict, is_dataclass
        processed = []
        
        for param in parameters:
            # Handle dataclass objects
            if is_dataclass(param):
                param = asdict(param)
            
            processed_param = {
                'name': param.get('name', ''),
                'type': param.get('param_type', param.get('type', 'unknown')),
                'source': param.get('source', ''),
                'context': param.get('context', ''),
                'risk_level': param.get('risk_level', 'low'),
                'is_hidden_flag': param.get('is_hidden', param.get('is_hidden_flag', False)),
                'confidence_score': param.get('confidence', param.get('confidence_score', 0)),
                'file_path': param.get('file_path', ''),
                'line_number': param.get('line_number', 0)
            }
            
            # Add additional metadata if available
            if 'endpoint' in param:
                processed_param['endpoint'] = param['endpoint']
            
            if 'method' in param:
                processed_param['method'] = param['method']
            
            if 'example_value' in param:
                processed_param['example_value'] = param['example_value']
            
            processed.append(processed_param)
        
        return processed
    
    def _process_endpoints(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Process endpoints for the report."""
        processed_endpoints = []
        
        for endpoint in endpoints:
            processed_endpoint = {
                'url': endpoint,
                'method': 'GET',  # Default, could be enhanced
                'discovered_from': 'javascript_analysis'
            }
            processed_endpoints.append(processed_endpoint)
        
        return processed_endpoints
    
    def _process_api_analysis(self, api_analysis: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process API analysis results for the report."""
        processed_apis = []
        
        for api in api_analysis:
            if not isinstance(api, dict):
                continue
            
            processed_api = {
                'url': api.get('url', ''),
                'api_type': api.get('api_type', 'unknown'),
                'methods_supported': list(api.get('methods', {}).keys()),
                'authentication_required': self._check_auth_required(api),
                'cors_enabled': api.get('cors_config', {}).get('enabled', False),
                'cors_vulnerabilities': api.get('cors_config', {}).get('vulnerabilities', []),
                'security_headers': api.get('security_headers', {}),
                'vulnerabilities': api.get('vulnerabilities', []),
                'parameters': api.get('parameters', []),
                'response_codes': self._extract_response_codes(api)
            }
            
            # Add specific analysis for special API types
            if api.get('type') == 'graphql_introspection':
                processed_api['graphql_introspection'] = api.get('analysis', {})
            elif api.get('type') == 'swagger_openapi':
                processed_api['swagger_openapi'] = api.get('analysis', {})
            
            processed_apis.append(processed_api)
        
        return processed_apis
    
    def _process_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process vulnerabilities for the report."""
        processed_vulns = []
        
        for vuln in vulnerabilities:
            processed_vuln = {
                'type': vuln.get('type', ''),
                'severity': vuln.get('severity', ''),
                'count': vuln.get('count', 1),
                'description': vuln.get('description', ''),
                'recommendation': vuln.get('recommendation', ''),
                'affected_resources': vuln.get('affected_resources', [])
            }
            processed_vulns.append(processed_vuln)
        
        return processed_vulns
    
    def _check_auth_required(self, api: Dict[str, Any]) -> bool:
        """Check if API requires authentication."""
        methods = api.get('methods', {})
        
        # Check if any method returns 401 or 403
        for method_data in methods.values():
            if isinstance(method_data, dict):
                status_code = method_data.get('status_code', 0)
                if status_code in [401, 403]:
                    return True
        
        return False
    
    def _extract_response_codes(self, api: Dict[str, Any]) -> Dict[str, int]:
        """Extract response codes from API analysis."""
        response_codes = {}
        methods = api.get('methods', {})
        
        for method, method_data in methods.items():
            if isinstance(method_data, dict):
                status_code = method_data.get('status_code', 0)
                if status_code:
                    response_codes[method] = status_code
        
        return response_codes
    
    def generate_minimal_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate a minimal JSON report with only key findings."""
        minimal_report = {
            'target': scan_results.get('target', ''),
            'scan_time': datetime.utcnow().isoformat() + 'Z',
            'summary': {
                'js_files': len(scan_results.get('js_files', [])),
                'secrets': len(scan_results.get('secrets', [])),
                'endpoints': len(scan_results.get('endpoints', [])),
                'vulnerabilities': len(scan_results.get('vulnerabilities', []))
            },
            'critical_findings': {
                'critical_secrets': [
                    s for s in scan_results.get('secrets', []) 
                    if s.get('risk_level') == 'Critical'
                ],
                'high_risk_vulnerabilities': [
                    v for v in scan_results.get('vulnerabilities', [])
                    if v.get('severity') in ['Critical', 'High']
                ]
            }
        }
        
        return json.dumps(minimal_report, indent=2, ensure_ascii=False)
    
    def export_secrets_only(self, scan_results: Dict[str, Any]) -> str:
        """Export only secrets in JSON format."""
        secrets_report = {
            'target': scan_results.get('target', ''),
            'export_time': datetime.utcnow().isoformat() + 'Z',
            'secrets': self._process_secrets(scan_results.get('secrets', []))
        }
        
        return json.dumps(secrets_report, indent=2, ensure_ascii=False)
    
    def export_endpoints_only(self, scan_results: Dict[str, Any]) -> str:
        """Export only endpoints in JSON format."""
        endpoints_report = {
            'target': scan_results.get('target', ''),
            'export_time': datetime.utcnow().isoformat() + 'Z',
            'endpoints': self._process_endpoints(scan_results.get('endpoints', [])),
            'api_analysis': self._process_api_analysis(scan_results.get('api_analysis', []))
        }
        
        return json.dumps(endpoints_report, indent=2, ensure_ascii=False)