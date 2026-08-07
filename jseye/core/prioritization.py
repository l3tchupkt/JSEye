"""Prioritization Engine for JSEye v3.0 - High Signal Mode."""

import re
from typing import Dict, List, Any, Set
from dataclasses import dataclass
from urllib.parse import urlparse
from .logging import get_logger

logger = get_logger(__name__)


@dataclass
class PriorityScore:
    """Priority scoring for findings."""
    score: int  # 0-100
    level: str  # 'critical', 'high', 'medium', 'low'
    factors: List[str]  # Contributing factors
    actionable: bool  # Is this actionable for bug hunters?


class PrioritizationEngine:
    """Prioritizes findings for bug hunting focus."""
    
    def __init__(self):
        # High-value endpoint patterns
        self.high_value_patterns = [
            r'/api/v\d+/admin',
            r'/api/v\d+/internal',
            r'/api/v\d+/debug',
            r'/api/v\d+/test',
            r'/api/v\d+/management',
            r'/api/v\d+/console',
            r'/api/v\d+/users?/\d+',
            r'/api/v\d+/accounts?/\d+',
            r'/graphql',
            r'/swagger',
            r'/openapi',
            r'/_debug',
            r'/_internal',
            r'/\.well-known/',
            r'/actuator/',
            r'/health',
            r'/status',
            r'/metrics'
        ]
        
        # Critical security indicators
        self.security_indicators = {
            'admin_access': ['admin', 'administrator', 'root', 'superuser'],
            'debug_mode': ['debug', 'test', 'dev', 'development', 'staging'],
            'internal_api': ['internal', 'private', 'restricted', 'protected'],
            'auth_bypass': ['bypass', 'skip', 'override', 'force', 'disable'],
            'privilege_escalation': ['role', 'permission', 'privilege', 'access', 'scope'],
            'data_exposure': ['dump', 'export', 'backup', 'archive', 'download'],
            'config_access': ['config', 'settings', 'environment', 'env', 'properties']
        }
        
        # Noise patterns to filter out
        self.noise_patterns = [
            r'\.js$', r'\.css$', r'\.png$', r'\.jpg$', r'\.gif$', r'\.svg$',
            r'\.ico$', r'\.woff$', r'\.ttf$', r'\.eot$', r'\.map$',
            r'/static/', r'/assets/', r'/public/', r'/resources/',
            r'google-analytics', r'googletagmanager', r'facebook\.com',
            r'doubleclick', r'googlesyndication', r'amazon-adsystem',
            r'/tracking/', r'/analytics/', r'/metrics/client',
            r'\.min\.js$', r'\.bundle\.js$'
        ]
    
    def prioritize_findings(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prioritize all findings for actionable output."""
        prioritized = {
            'critical_findings': [],
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'actionable_summary': {},
            'noise_filtered': 0
        }
        
        # Process different types of findings
        if 'endpoints' in scan_results:
            endpoint_priorities = self._prioritize_endpoints(scan_results['endpoints'])
            self._merge_priorities(prioritized, endpoint_priorities)
        
        if 'secrets' in scan_results:
            secret_priorities = self._prioritize_secrets(scan_results['secrets'])
            self._merge_priorities(prioritized, secret_priorities)
        
        if 'vulnerabilities' in scan_results:
            vuln_priorities = self._prioritize_vulnerabilities(scan_results['vulnerabilities'])
            self._merge_priorities(prioritized, vuln_priorities)
        
        if 'all_findings' in scan_results:
            finding_priorities = self._prioritize_generic_findings(scan_results['all_findings'])
            self._merge_priorities(prioritized, finding_priorities)
        
        # Generate actionable summary
        prioritized['actionable_summary'] = self._generate_actionable_summary(prioritized)
        
        return prioritized
    
    def _prioritize_endpoints(self, endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Prioritize API endpoints."""
        priorities = {'critical_findings': [], 'high_priority': [], 'medium_priority': [], 'low_priority': []}
        
        for endpoint in endpoints:
            # Defensive: raw strings (plain URL paths) are coerced to minimal dicts
            if isinstance(endpoint, str):
                endpoint = {'url': endpoint, 'method': 'GET'}
            elif not isinstance(endpoint, dict):
                continue

            url = endpoint.get('url', '')
            
            # Skip noise
            if self._is_noise(url):
                continue
            
            score = self._score_endpoint(endpoint)
            
            # Add priority metadata
            endpoint['priority_score'] = score.score
            endpoint['priority_level'] = score.level
            endpoint['priority_factors'] = score.factors
            endpoint['actionable'] = score.actionable
            
            # Categorize
            if score.level == 'critical':
                priorities['critical_findings'].append(endpoint)
            elif score.level == 'high':
                priorities['high_priority'].append(endpoint)
            elif score.level == 'medium':
                priorities['medium_priority'].append(endpoint)
            else:
                priorities['low_priority'].append(endpoint)
        
        return priorities
    
    def _prioritize_secrets(self, secrets: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Prioritize secret findings."""
        priorities = {'critical_findings': [], 'high_priority': [], 'medium_priority': [], 'low_priority': []}
        
        for secret in secrets:
            score = self._score_secret(secret)
            
            # Add priority metadata
            secret['priority_score'] = score.score
            secret['priority_level'] = score.level
            secret['priority_factors'] = score.factors
            secret['actionable'] = score.actionable
            
            # Categorize
            if score.level == 'critical':
                priorities['critical_findings'].append(secret)
            elif score.level == 'high':
                priorities['high_priority'].append(secret)
            elif score.level == 'medium':
                priorities['medium_priority'].append(secret)
            else:
                priorities['low_priority'].append(secret)
        
        return priorities
    
    def _prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Prioritize vulnerability findings."""
        priorities = {'critical_findings': [], 'high_priority': [], 'medium_priority': [], 'low_priority': []}
        
        for vuln in vulnerabilities:
            score = self._score_vulnerability(vuln)
            
            # Add priority metadata
            vuln['priority_score'] = score.score
            vuln['priority_level'] = score.level
            vuln['priority_factors'] = score.factors
            vuln['actionable'] = score.actionable
            
            # Categorize
            if score.level == 'critical':
                priorities['critical_findings'].append(vuln)
            elif score.level == 'high':
                priorities['high_priority'].append(vuln)
            elif score.level == 'medium':
                priorities['medium_priority'].append(vuln)
            else:
                priorities['low_priority'].append(vuln)
        
        return priorities
    
    def _prioritize_generic_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Prioritize generic findings."""
        priorities = {'critical_findings': [], 'high_priority': [], 'medium_priority': [], 'low_priority': []}
        
        for finding in findings:
            # Defensive: raw strings are coerced to minimal dicts
            if isinstance(finding, str):
                finding = {
                    'type': 'generic',
                    'target': finding,
                    'url': finding,
                    'severity': 'low',
                    'confidence_score': 50,
                }
            elif not isinstance(finding, dict):
                continue

            score = self._score_generic_finding(finding)
            
            # Add priority metadata
            finding['priority_score'] = score.score
            finding['priority_level'] = score.level
            finding['priority_factors'] = score.factors
            finding['actionable'] = score.actionable
            
            # Categorize
            if score.level == 'critical':
                priorities['critical_findings'].append(finding)
            elif score.level == 'high':
                priorities['high_priority'].append(finding)
            elif score.level == 'medium':
                priorities['medium_priority'].append(finding)
            else:
                priorities['low_priority'].append(finding)
        
        return priorities
    
    def _score_endpoint(self, endpoint: Dict[str, Any]) -> PriorityScore:
        """Score an endpoint for priority."""
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET')
        factors = []
        score = 0
        
        # Base score by method
        if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            score += 20
            factors.append(f'{method}_method')
        
        # High-value patterns
        for pattern in self.high_value_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                score += 30
                factors.append('high_value_pattern')
                break
        
        # Security indicators
        url_lower = url.lower()
        for category, indicators in self.security_indicators.items():
            for indicator in indicators:
                if indicator in url_lower:
                    if category in ['admin_access', 'auth_bypass']:
                        score += 40
                    elif category in ['debug_mode', 'internal_api']:
                        score += 30
                    else:
                        score += 20
                    factors.append(category)
                    break
        
        # JSON response indicator
        if endpoint.get('returns_json', False):
            score += 15
            factors.append('json_response')
        
        # GraphQL endpoint
        if endpoint.get('is_graphql', False):
            score += 25
            factors.append('graphql_endpoint')
        
        # Swagger/OpenAPI
        if endpoint.get('is_swagger', False):
            score += 35
            factors.append('api_documentation')
        
        # No authentication required
        if not endpoint.get('has_auth', True):
            score += 20
            factors.append('no_auth_required')
        
        # Multiple sources (high confidence)
        if endpoint.get('source_count', 1) > 1:
            score += 15
            factors.append('multiple_sources')
        
        # Risk factors
        risk_factors = endpoint.get('risk_factors', [])
        for risk_factor in risk_factors:
            if risk_factor in ['admin_endpoint', 'debug_endpoint']:
                score += 25
            elif risk_factor in ['graphql_endpoint', 'api_documentation']:
                score += 20
            else:
                score += 10
            factors.append(risk_factor)
        
        # Determine level
        if score >= 80:
            level = 'critical'
        elif score >= 60:
            level = 'high'
        elif score >= 40:
            level = 'medium'
        else:
            level = 'low'
        
        # Actionable if high priority or has specific indicators
        actionable = (score >= 60 or 
                     any(factor in factors for factor in ['admin_access', 'graphql_endpoint', 'api_documentation', 'debug_mode']))
        
        return PriorityScore(score=min(score, 100), level=level, factors=factors, actionable=actionable)
    
    def _score_secret(self, secret: Dict[str, Any]) -> PriorityScore:
        """Score a secret finding."""
        secret_type = secret.get('type', '').lower()
        confidence = secret.get('confidence_score', 0)
        factors = []
        score = int(confidence)
        
        # High-value secret types
        high_value_secrets = [
            'api_key', 'private_key', 'password', 'token', 'secret',
            'aws_access_key', 'github_token', 'slack_token', 'jwt'
        ]
        
        if any(sv_type in secret_type for sv_type in high_value_secrets):
            score += 30
            factors.append('high_value_secret')
        
        # Production indicators
        context = secret.get('context', '').lower()
        if any(indicator in context for indicator in ['prod', 'production', 'live']):
            score += 25
            factors.append('production_context')
        
        # Valid format indicators
        if secret.get('entropy', 0) > 4.0:
            score += 15
            factors.append('high_entropy')
        
        # Determine level
        if score >= 85:
            level = 'critical'
        elif score >= 70:
            level = 'high'
        elif score >= 50:
            level = 'medium'
        else:
            level = 'low'
        
        actionable = score >= 70
        
        return PriorityScore(score=min(score, 100), level=level, factors=factors, actionable=actionable)
    
    def _score_vulnerability(self, vulnerability: Dict[str, Any]) -> PriorityScore:
        """Score a vulnerability finding."""
        vuln_type = vulnerability.get('type', '').lower()
        severity = vulnerability.get('severity', 'low').lower()
        confidence = vulnerability.get('confidence_score', 0)
        factors = []
        
        # Base score from severity
        severity_scores = {'critical': 90, 'high': 70, 'medium': 50, 'low': 30}
        score = severity_scores.get(severity, 30)
        
        # Adjust by confidence
        score = int(score * (confidence / 100))
        
        # High-impact vulnerability types
        high_impact_vulns = [
            'dom_xss', 'sql_injection', 'command_injection', 'path_traversal',
            'ssrf', 'xxe', 'deserialization', 'authentication_bypass'
        ]
        
        if any(vuln in vuln_type for vuln in high_impact_vulns):
            score += 20
            factors.append('high_impact_vulnerability')
        
        # Exploitability indicators
        if vulnerability.get('exploitable', False):
            score += 15
            factors.append('exploitable')
        
        # Determine level
        if score >= 85:
            level = 'critical'
        elif score >= 65:
            level = 'high'
        elif score >= 45:
            level = 'medium'
        else:
            level = 'low'
        
        actionable = score >= 65 or vuln_type in ['dom_xss', 'graphql_introspection', 'swagger_exposure']
        
        return PriorityScore(score=min(score, 100), level=level, factors=factors, actionable=actionable)
    
    def _score_generic_finding(self, finding: Dict[str, Any]) -> PriorityScore:
        """Score a generic finding."""
        finding_type = finding.get('type', '').lower()
        severity = finding.get('severity', 'low').lower()
        confidence = finding.get('confidence_score', 0)
        factors = []
        
        # Base score
        severity_scores = {'critical': 80, 'high': 60, 'medium': 40, 'low': 20}
        score = severity_scores.get(severity, 20)
        
        # Adjust by confidence
        score = int(score * (confidence / 100))
        
        # Bug hunting relevant types
        hunter_relevant = [
            'parameter_pollution', 'cors_misconfiguration', 'csp_bypass',
            'prototype_pollution', 'client_side_template_injection'
        ]
        
        if any(relevant in finding_type for relevant in hunter_relevant):
            score += 25
            factors.append('hunter_relevant')
        
        # Determine level
        if score >= 75:
            level = 'critical'
        elif score >= 55:
            level = 'high'
        elif score >= 35:
            level = 'medium'
        else:
            level = 'low'
        
        actionable = score >= 55
        
        return PriorityScore(score=min(score, 100), level=level, factors=factors, actionable=actionable)
    
    def _is_noise(self, url: str) -> bool:
        """Check if URL is noise that should be filtered."""
        for pattern in self.noise_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False
    
    def _merge_priorities(self, target: Dict[str, List], source: Dict[str, List]) -> None:
        """Merge priority results."""
        for key in ['critical_findings', 'high_priority', 'medium_priority', 'low_priority']:
            if key in source:
                target[key].extend(source[key])
    
    def _generate_actionable_summary(self, prioritized: Dict[str, Any]) -> Dict[str, Any]:
        """Generate actionable summary for hunters."""
        summary = {
            'total_actionable': 0,
            'critical_count': len(prioritized['critical_findings']),
            'high_priority_count': len(prioritized['high_priority']),
            'top_targets': [],
            'quick_wins': [],
            'attack_vectors': []
        }
        
        # Count actionable findings
        for category in ['critical_findings', 'high_priority', 'medium_priority']:
            actionable_count = sum(1 for item in prioritized[category] 
                                 if item.get('actionable', False))
            summary['total_actionable'] += actionable_count
        
        # Identify top targets (critical + high priority)
        all_high_value = prioritized['critical_findings'] + prioritized['high_priority']
        
        # Sort by score and take top 10
        top_targets = sorted(all_high_value, 
                           key=lambda x: x.get('priority_score', 0), 
                           reverse=True)[:10]
        
        summary['top_targets'] = [
            {
                'type': item.get('type', 'unknown'),
                'target': item.get('url', item.get('title', 'Unknown')),
                'score': item.get('priority_score', 0),
                'factors': item.get('priority_factors', [])
            }
            for item in top_targets
        ]
        
        # Identify quick wins (high confidence, easy to exploit)
        quick_wins = []
        for item in all_high_value:
            if (item.get('confidence_score', 0) > 80 and 
                any(factor in item.get('priority_factors', []) 
                    for factor in ['graphql_endpoint', 'api_documentation', 'no_auth_required'])):
                quick_wins.append(item)
        
        summary['quick_wins'] = quick_wins[:5]
        
        # Identify attack vectors
        attack_vectors = set()
        for item in all_high_value:
            item_type = item.get('type', '')
            if 'xss' in item_type:
                attack_vectors.add('XSS')
            elif 'graphql' in item_type:
                attack_vectors.add('GraphQL')
            elif 'swagger' in item_type or 'openapi' in item_type:
                attack_vectors.add('API Documentation')
            elif 'admin' in str(item.get('priority_factors', [])):
                attack_vectors.add('Admin Access')
            elif 'secret' in item_type:
                attack_vectors.add('Secret Exposure')
        
        summary['attack_vectors'] = list(attack_vectors)
        
        return summary
    
    def filter_noise(self, findings: List[Dict[str, Any]], aggressive: bool = True) -> List[Dict[str, Any]]:
        """Filter out noise from findings."""
        filtered = []
        
        for finding in findings:
            # Get URL or target
            target = finding.get('url', finding.get('target', finding.get('source_file', '')))
            
            # Skip if noise
            if self._is_noise(target):
                continue
            
            # Skip low confidence findings in aggressive mode
            if aggressive and finding.get('confidence_score', 100) < 60:
                continue
            
            # Skip duplicate endpoints (normalize)
            normalized_target = self._normalize_url(target)
            if not self._is_duplicate_endpoint(normalized_target, filtered):
                filtered.append(finding)
        
        return filtered
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        # Remove query parameters for comparison
        if '?' in url:
            url = url.split('?')[0]
        
        # Remove trailing slash
        url = url.rstrip('/')
        
        # Replace numeric IDs with placeholder
        url = re.sub(r'/\d+', '/{id}', url)
        
        return url
    
    def _is_duplicate_endpoint(self, normalized_url: str, existing_findings: List[Dict[str, Any]]) -> bool:
        """Check if endpoint is duplicate."""
        for finding in existing_findings:
            existing_url = finding.get('url', finding.get('target', ''))
            if self._normalize_url(existing_url) == normalized_url:
                return True
        return False