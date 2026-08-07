"""CVE Intelligence Plugin for JSEye v2.0."""

import asyncio
from typing import Dict, List, Any
from jseye.plugins.base import BasePlugin, PluginMetadata, PluginContext, PluginResult, PluginCategory, ExploitationLikelihood, ExposureLevel
from jseye.core.cve_engine import CVEIntelligenceEngine
from jseye.core.logging import get_logger

logger = get_logger(__name__)


class CVEIntelligencePlugin(BasePlugin):
    """Plugin for analyzing JavaScript libraries for known CVE vulnerabilities."""
    
    def __init__(self):
        super().__init__()
    
    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="cve_intelligence",
            version="2.0.2",
            category=PluginCategory.INTELLIGENCE,
            risk_weight=0.85,  # High weight for known vulnerabilities
            description="Analyzes JavaScript libraries for known CVE vulnerabilities using free APIs",
            author="JSEye Team",
            requires=[],
            enabled=True,
            execution_order=30
        )
    
    async def validate_context(self, context: PluginContext) -> bool:
        """Validate that context is valid (always true - can handle empty JS files)."""
        return True
    
    async def run(self, context: PluginContext) -> PluginResult:
        """Execute CVE intelligence analysis."""
        result = self.create_result()
        start_time = asyncio.get_event_loop().time()
        
        try:
            logger.info("Starting CVE intelligence analysis", 
                       target=context.target, 
                       js_files=len(context.js_files))
            
            # Handle case with no JavaScript files
            if not context.js_files:
                logger.info("No JavaScript files to analyze for CVEs", target=context.target)
                result.metadata = {
                    'total_js_files': 0,
                    'libraries_analyzed': 0,
                    'vulnerabilities_found': 0,
                    'analysis_summary': 'No JavaScript files found for CVE analysis'
                }
                return result
            
            # Track network calls for profiling
            network_calls = 0
            
            async with CVEIntelligenceEngine(timeout=30) as cve_engine:
                vulnerabilities = await cve_engine.analyze_libraries_and_cves(context.js_files)
                
                # Estimate network calls (rough approximation)
                network_calls = len(vulnerabilities) * 2  # Approximate API calls per library
                
                total_cves = 0
                critical_cves = 0
                
                # Process each vulnerable library
                for vuln in vulnerabilities:
                    library_info = vuln.get('library', {})
                    cves = vuln.get('cves', [])
                    
                    total_cves += len(cves)
                    
                    # Process each CVE for this library
                    for cve in cves:
                        if cve.get('severity') == 'critical':
                            critical_cves += 1
                        
                        # Calculate confidence based on CVE data quality
                        base_confidence = 90.0  # High confidence for known CVEs
                        
                        contributing_factors = [
                            f"Library: {library_info.get('name', 'Unknown')} v{library_info.get('version', 'Unknown')}",
                            f"CVE ID: {cve.get('id', 'Unknown')}",
                            f"Detection method: {library_info.get('detection_method', 'Unknown')}"
                        ]
                        
                        if cve.get('cvss_score'):
                            contributing_factors.append(f"CVSS Score: {cve.get('cvss_score')}")
                        
                        if cve.get('published_date'):
                            contributing_factors.append(f"Published: {cve.get('published_date')}")
                        
                        confidence_factors = self.calculate_confidence(
                            base_confidence=base_confidence,
                            contributing_factors=contributing_factors
                        )
                        
                        # Create risk metrics
                        risk_metrics = self.create_risk_metrics(
                            confidence_score=confidence_factors.final_confidence,
                            exploitation_likelihood=self._map_severity_to_exploitation(cve.get('severity', 'medium')),
                            stability_score=95.0,  # CVEs are very stable findings
                            exposure_level=ExposureLevel.EXTERNAL,  # Client-side libraries
                            contributing_factors=contributing_factors
                        )
                        
                        # Calculate risk score
                        risk_score = self._calculate_cve_risk_score(cve, library_info)
                        
                        # Create standardized finding
                        finding = {
                            'id': f"cve_{cve.get('id', 'unknown').replace('-', '_')}",
                            'type': 'vulnerable_library',
                            'subtype': cve.get('severity', 'medium'),
                            'title': f"Vulnerable Library: {library_info.get('name', 'Unknown')} - {cve.get('id', 'Unknown')}",
                            'description': cve.get('summary', 'No description available'),
                            'severity': cve.get('severity', 'medium'),
                            'confidence_score': confidence_factors.final_confidence,
                            'risk_score': risk_score,
                            'source_file': library_info.get('file_url', ''),
                            'location': {
                                'file': library_info.get('file_url', ''),
                                'line': library_info.get('line_number', 0),
                                'library': library_info.get('name', 'Unknown'),
                                'version': library_info.get('version', 'Unknown')
                            },
                            'evidence': {
                                'cve_id': cve.get('id', ''),
                                'cvss_score': cve.get('cvss_score'),
                                'published_date': cve.get('published_date', ''),
                                'modified_date': cve.get('modified_date', ''),
                                'detection_method': library_info.get('detection_method', ''),
                                'detection_confidence': library_info.get('confidence', 0)
                            },
                            'risk_metrics': vars(risk_metrics),
                            'confidence_factors': vars(confidence_factors),
                            'remediation': self._get_remediation_advice(library_info, cve),
                            'references': cve.get('references', []),
                            'raw_data': {
                                'library': library_info,
                                'cve': cve,
                                'vulnerability': vuln
                            }
                        }
                        
                        result.add_finding(finding)
                
                # Sort findings by risk score
                result.findings.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
                
                # Add metadata
                result.metadata = {
                    'total_libraries_analyzed': len(vulnerabilities),
                    'total_cves_found': total_cves,
                    'critical_cves': critical_cves,
                    'high_cves': len([f for f in result.findings if f.get('severity') == 'high']),
                    'medium_cves': len([f for f in result.findings if f.get('severity') == 'medium']),
                    'low_cves': len([f for f in result.findings if f.get('severity') == 'low']),
                    'library_distribution': self._get_library_distribution(vulnerabilities),
                    'severity_distribution': self._get_severity_distribution(result.findings),
                    'files_analyzed': len(context.js_files)
                }
                
                # Update network calls count
                result.network_calls = network_calls
                
                # Store results in shared context
                context.add_shared_data('library_vulnerabilities', vulnerabilities)
                context.add_shared_data('cve_findings', result.findings)
                
                logger.info("CVE intelligence analysis completed", 
                           target=context.target,
                           libraries_analyzed=len(vulnerabilities),
                           cves_found=total_cves,
                           critical_cves=critical_cves)
                
        except Exception as e:
            error_msg = f"CVE intelligence plugin failed: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg, target=context.target)
        
        finally:
            result.execution_time = asyncio.get_event_loop().time() - start_time
        
        return result
    
    def _map_severity_to_exploitation(self, severity: str) -> ExploitationLikelihood:
        """Map CVE severity to exploitation likelihood."""
        mapping = {
            'critical': ExploitationLikelihood.HIGH,
            'high': ExploitationLikelihood.HIGH,
            'medium': ExploitationLikelihood.MEDIUM,
            'low': ExploitationLikelihood.LOW
        }
        return mapping.get(severity.lower(), ExploitationLikelihood.MEDIUM)
    
    def _calculate_cve_risk_score(self, cve: Dict[str, Any], library_info: Dict[str, Any]) -> int:
        """Calculate risk score for a CVE."""
        base_score = 0
        
        # Base score from severity
        severity_scores = {
            'critical': 40,
            'high': 30,
            'medium': 20,
            'low': 10
        }
        base_score += severity_scores.get(cve.get('severity', 'medium'), 20)
        
        # CVSS score bonus
        cvss_score = cve.get('cvss_score', 0)
        if cvss_score:
            base_score += min(cvss_score * 2, 20)  # Max 20 points from CVSS
        
        # Detection confidence bonus
        detection_confidence = library_info.get('confidence', 0)
        base_score += detection_confidence * 10  # Max 10 points
        
        # Recent CVE bonus (if published recently, it's more concerning)
        published_date = cve.get('published_date', '')
        if published_date:
            try:
                from datetime import datetime
                pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                days_old = (datetime.now().replace(tzinfo=pub_date.tzinfo) - pub_date).days
                if days_old < 30:  # Recent CVE
                    base_score += 10
                elif days_old < 90:
                    base_score += 5
            except Exception:
                pass
        
        return min(base_score, 100)
    
    def _get_remediation_advice(self, library_info: Dict[str, Any], cve: Dict[str, Any]) -> str:
        """Get remediation advice for a vulnerable library."""
        library_name = library_info.get('name', 'Unknown')
        library_version = library_info.get('version', 'Unknown')
        cve_id = cve.get('id', 'Unknown')
        
        advice = f"Vulnerable Library Remediation:\n\n"
        advice += f"Library: {library_name} v{library_version}\n"
        advice += f"CVE: {cve_id}\n"
        advice += f"Severity: {cve.get('severity', 'Unknown')}\n\n"
        
        advice += "Recommended Actions:\n"
        advice += f"1. Update {library_name} to the latest secure version\n"
        advice += "2. Check the library's security advisories for patch information\n"
        advice += "3. Consider alternative libraries if no patch is available\n"
        advice += "4. Implement additional security controls if update is not possible\n"
        advice += "5. Monitor for security updates regularly\n\n"
        
        advice += "General Library Security:\n"
        advice += "- Use dependency scanning tools in CI/CD pipeline\n"
        advice += "- Regularly audit and update dependencies\n"
        advice += "- Subscribe to security advisories for used libraries\n"
        advice += "- Implement Software Composition Analysis (SCA)\n"
        
        return advice
    
    def _get_library_distribution(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of vulnerable libraries."""
        distribution = {}
        for vuln in vulnerabilities:
            library_info = vuln.get('library', {})
            library_name = library_info.get('name', 'unknown')
            distribution[library_name] = distribution.get(library_name, 0) + 1
        return distribution
    
    def _get_severity_distribution(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of CVE severities."""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            severity = finding.get('severity', 'medium')
            if severity in distribution:
                distribution[severity] += 1
        return distribution