"""Secret Detection Plugin for JSEye v2.0."""

import asyncio
from typing import Dict, List, Any
from jseye.plugins.base import BasePlugin, PluginMetadata, PluginContext, PluginResult, PluginCategory, ExploitationLikelihood, ExposureLevel
from jseye.core.secret_engine import SecretDetector
from jseye.core.logging import get_logger

logger = get_logger(__name__)


class SecretDetectionPlugin(BasePlugin):
    """Plugin for detecting secrets in JavaScript files."""
    
    def __init__(self):
        super().__init__()
        self.secret_detector = SecretDetector()
    
    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="secret_detection",
            version="2.0.2",
            category=PluginCategory.DETECTION,
            risk_weight=0.9,  # High weight for secrets
            description="Detects hardcoded secrets, API keys, and credentials in JavaScript files",
            author="JSEye Team",
            requires=[],
            enabled=True,
            execution_order=10
        )
    
    async def validate_context(self, context: PluginContext) -> bool:
        """Validate that context is valid (always true - can handle empty JS files)."""
        return True
    
    async def run(self, context: PluginContext) -> PluginResult:
        """Execute secret detection analysis."""
        result = self.create_result()
        start_time = asyncio.get_event_loop().time()
        
        try:
            logger.info("Starting secret detection analysis", 
                       target=context.target, 
                       js_files=len(context.js_files))
            
            # Handle case with no JavaScript files
            if not context.js_files:
                logger.info("No JavaScript files to analyze for secrets", target=context.target)
                result.metadata = {
                    'total_js_files': 0,
                    'total_secrets': 0,
                    'analysis_summary': 'No JavaScript files found for secret detection'
                }
                return result
            
            all_secrets = []
            
            # Process each JavaScript file
            for js_file in context.js_files:
                try:
                    content = js_file.get('content', '')
                    if not content:
                        continue
                    
                    file_url = js_file.get('url', '')
                    
                    # Detect secrets
                    secrets = self.secret_detector.detect_secrets(content, file_url)
                    
                    # Enhanced analysis for each secret
                    for secret in secrets:
                        # Risk analysis
                        risk_analysis = self.secret_detector.analyze_secret_risk(secret)
                        secret.update(risk_analysis)
                        
                        # Remediation advice
                        secret['remediation'] = self.secret_detector.get_remediation_advice(secret)
                        
                        # Create confidence factors
                        confidence_factors = self.calculate_confidence(
                            base_confidence=secret.get('enhanced_confidence', secret.get('confidence', 0.5)) * 100,
                            contributing_factors=secret.get('scoring_factors', []),
                            penalty_factors=[]
                        )
                        
                        # Create risk metrics
                        risk_metrics = self.create_risk_metrics(
                            confidence_score=confidence_factors.final_confidence,
                            exploitation_likelihood=self._map_risk_to_exploitation(secret.get('risk_level', 'Low')),
                            stability_score=85.0,  # Secrets are generally stable findings
                            exposure_level=ExposureLevel.EXTERNAL,  # JavaScript is client-side
                            contributing_factors=secret.get('scoring_factors', [])
                        )
                        
                        # Create standardized finding
                        finding = {
                            'id': f"secret_{len(all_secrets) + 1}",
                            'type': 'secret',
                            'subtype': secret.get('type', 'unknown'),
                            'title': f"{secret.get('description', 'Secret')} Detected",
                            'description': f"Detected {secret.get('description', 'secret')} in JavaScript file",
                            'severity': secret.get('severity', 'medium'),
                            'confidence_score': confidence_factors.final_confidence,
                            'risk_score': secret.get('risk_score', 0),
                            'risk_level': secret.get('risk_level', 'Low'),
                            'source_file': file_url,
                            'location': {
                                'file': file_url,
                                'position': secret.get('position', 0),
                                'context': secret.get('context', '')
                            },
                            'evidence': {
                                'value_masked': secret.get('value_masked', ''),
                                'detection_method': secret.get('detection_method', 'pattern'),
                                'entropy': secret.get('entropy', 0)
                            },
                            'risk_metrics': vars(risk_metrics),
                            'confidence_factors': vars(confidence_factors),
                            'remediation': secret.get('remediation', ''),
                            'references': [
                                'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
                                'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'
                            ],
                            'raw_data': secret
                        }
                        
                        result.add_finding(finding)
                        all_secrets.append(secret)
                        
                except Exception as e:
                    error_msg = f"Secret detection failed for {js_file.get('url', 'unknown')}: {str(e)}"
                    result.errors.append(error_msg)
                    logger.warning(error_msg)
            
            # Sort findings by risk score
            result.findings.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
            
            # Add metadata
            result.metadata = {
                'total_secrets': len(all_secrets),
                'secret_types': self._get_secret_type_distribution(all_secrets),
                'risk_distribution': self._get_risk_distribution(all_secrets),
                'high_confidence_secrets': len([s for s in all_secrets if s.get('enhanced_confidence', 0) > 0.8]),
                'files_analyzed': len(context.js_files),
                'detection_methods': self._get_detection_methods(all_secrets)
            }
            
            # Store results in shared context
            context.add_shared_data('detected_secrets', all_secrets)
            context.add_shared_data('secret_findings', result.findings)
            
            logger.info("Secret detection completed", 
                       target=context.target,
                       secrets_found=len(all_secrets),
                       high_risk=len([s for s in all_secrets if s.get('risk_level') == 'Critical']))
            
        except Exception as e:
            error_msg = f"Secret detection plugin failed: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg, target=context.target)
        
        finally:
            result.execution_time = asyncio.get_event_loop().time() - start_time
        
        return result
    
    def _map_risk_to_exploitation(self, risk_level: str) -> ExploitationLikelihood:
        """Map risk level to exploitation likelihood."""
        mapping = {
            'Critical': ExploitationLikelihood.HIGH,
            'High': ExploitationLikelihood.HIGH,
            'Medium': ExploitationLikelihood.MEDIUM,
            'Low': ExploitationLikelihood.LOW
        }
        return mapping.get(risk_level, ExploitationLikelihood.MEDIUM)
    
    def _get_secret_type_distribution(self, secrets: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of secret types."""
        distribution = {}
        for secret in secrets:
            secret_type = secret.get('type', 'unknown')
            distribution[secret_type] = distribution.get(secret_type, 0) + 1
        return distribution
    
    def _get_risk_distribution(self, secrets: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of risk levels."""
        distribution = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for secret in secrets:
            risk_level = secret.get('risk_level', 'Low')
            if risk_level in distribution:
                distribution[risk_level] += 1
        return distribution
    
    def _get_detection_methods(self, secrets: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of detection methods."""
        distribution = {}
        for secret in secrets:
            method = secret.get('detection_method', 'unknown')
            distribution[method] = distribution.get(method, 0) + 1
        return distribution