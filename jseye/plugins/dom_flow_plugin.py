"""DOM Flow Analysis Plugin for JSEye v2.0."""

import asyncio
from typing import Dict, List, Any
from jseye.plugins.base import BasePlugin, PluginMetadata, PluginContext, PluginResult, PluginCategory, ExploitationLikelihood, ExposureLevel
from jseye.core.dom_flow import DOMFlowAnalyzer
from jseye.core.logging import get_logger

logger = get_logger(__name__)


class DOMFlowPlugin(BasePlugin):
    """Plugin for analyzing DOM-based data flows and XSS vulnerabilities."""
    
    def __init__(self):
        super().__init__()
        self.dom_analyzer = DOMFlowAnalyzer()
    
    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="dom_flow_analysis",
            version="2.0.2",
            category=PluginCategory.ANALYSIS,
            risk_weight=0.8,  # High weight for XSS vulnerabilities
            description="Analyzes DOM-based data flows to detect potential XSS vulnerabilities",
            author="JSEye Team",
            requires=[],
            enabled=True,
            execution_order=20
        )
    
    async def validate_context(self, context: PluginContext) -> bool:
        """Validate that context is valid (always true - can handle empty JS files)."""
        return True
    
    async def run(self, context: PluginContext) -> PluginResult:
        """Execute DOM flow analysis."""
        result = self.create_result()
        start_time = asyncio.get_event_loop().time()
        
        try:
            logger.info("Starting DOM flow analysis", 
                       target=context.target, 
                       js_files=len(context.js_files))
            
            # Handle case with no JavaScript files
            if not context.js_files:
                logger.info("No JavaScript files to analyze for DOM flows", target=context.target)
                result.metadata = {
                    'total_js_files': 0,
                    'total_sources': 0,
                    'total_sinks': 0,
                    'total_flows': 0,
                    'analysis_summary': 'No JavaScript files found for DOM flow analysis'
                }
                return result
            
            all_dom_flows = []
            total_sources = 0
            total_sinks = 0
            total_flows = 0
            
            # Process each JavaScript file
            for js_file in context.js_files:
                try:
                    content = js_file.get('content', '')
                    if not content:
                        continue
                    
                    file_url = js_file.get('url', '')
                    
                    # Analyze DOM flows
                    flow_analysis = self.dom_analyzer.analyze_dom_flows(content, file_url)
                    
                    if not flow_analysis.get('flow_paths'):
                        continue
                    
                    all_dom_flows.append(flow_analysis)
                    
                    # Count sources, sinks, and flows
                    total_sources += len(flow_analysis.get('sources', []))
                    total_sinks += len(flow_analysis.get('sinks', []))
                    total_flows += len(flow_analysis.get('flow_paths', []))
                    
                    # Create findings for each flow path
                    for i, flow_path in enumerate(flow_analysis.get('flow_paths', [])):
                        # Flow paths are now dictionaries from DOM analyzer
                        source = flow_path.get('source', {})
                        sink = flow_path.get('sink', {})
                        path_variables = flow_path.get('path_variables', [])
                        confidence = flow_path.get('confidence', 0.5)
                        risk_score = flow_path.get('risk_score', 0)
                        
                        # Calculate confidence and risk
                        base_confidence = confidence * 100
                        
                        # Determine severity based on sink risk level
                        sink_risk = sink.get('risk_level', 'low')
                        severity_map = {
                            'critical': 'critical',
                            'high': 'high',
                            'medium': 'medium',
                            'low': 'low'
                        }
                        severity = severity_map.get(sink_risk, 'medium')
                        
                        # Create confidence factors
                        source_desc = source.get('description', 'Unknown')
                        sink_desc = sink.get('description', 'Unknown')
                        
                        contributing_factors = [
                            f"Source: {source_desc}",
                            f"Sink: {sink_desc}",
                            f"Flow confidence: {confidence:.2f}"
                        ]
                        
                        if path_variables:
                            contributing_factors.append(f"Variables in path: {', '.join(path_variables)}")
                        
                        confidence_factors = self.calculate_confidence(
                            base_confidence=base_confidence,
                            contributing_factors=contributing_factors
                        )
                        
                        # Create risk metrics
                        risk_metrics = self.create_risk_metrics(
                            confidence_score=confidence_factors.final_confidence,
                            exploitation_likelihood=self._map_sink_to_exploitation(sink_risk),
                            stability_score=70.0,  # DOM flows can be somewhat unstable
                            exposure_level=ExposureLevel.EXTERNAL,  # Client-side vulnerability
                            contributing_factors=contributing_factors
                        )
                        
                        # Extract names safely
                        source_name = source.get('name', 'unknown')
                        sink_name = sink.get('name', 'unknown')
                        source_line = source.get('line', 0)
                        sink_line = sink.get('line', 0)
                        source_context = source.get('context', '')
                        sink_context = sink.get('context', '')
                        
                        # Create standardized finding
                        finding = {
                            'id': f"dom_flow_{len(result.findings) + 1}",
                            'type': 'dom_xss',
                            'subtype': f"{source_name}_to_{sink_name}",
                            'title': f"Potential DOM-based XSS: {source_name} → {sink_name}",
                            'description': f"Data flow from {source_desc} to {sink_desc} may allow XSS",
                            'severity': severity,
                            'confidence_score': confidence_factors.final_confidence,
                            'risk_score': risk_score,
                            'source_file': file_url,
                            'location': {
                                'file': file_url,
                                'source_line': source_line,
                                'sink_line': sink_line,
                                'source_context': source_context,
                                'sink_context': sink_context
                            },
                            'evidence': {
                                'source_name': source_name,
                                'sink_name': sink_name,
                                'path_variables': path_variables,
                                'flow_confidence': confidence
                            },
                            'risk_metrics': vars(risk_metrics),
                            'confidence_factors': vars(confidence_factors),
                            'remediation': self._get_remediation_advice(source, sink),
                            'references': [
                                'https://owasp.org/www-community/attacks/DOM_Based_XSS',
                                'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html'
                            ],
                            'raw_data': flow_path
                        }
                        
                        result.add_finding(finding)
                        
                except Exception as e:
                    error_msg = f"DOM flow analysis failed for {js_file.get('url', 'unknown')}: {str(e)}"
                    result.errors.append(error_msg)
                    logger.warning(error_msg)
            
            # Sort findings by risk score
            result.findings.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
            
            # Add metadata
            result.metadata = {
                'total_dom_flows': len(all_dom_flows),
                'total_sources': total_sources,
                'total_sinks': total_sinks,
                'total_flow_paths': total_flows,
                'files_with_flows': len(all_dom_flows),
                'files_analyzed': len(context.js_files),
                'risk_distribution': self._get_flow_risk_distribution(all_dom_flows),
                'source_types': self._get_source_distribution(all_dom_flows),
                'sink_types': self._get_sink_distribution(all_dom_flows)
            }
            
            # Store results in shared context
            context.add_shared_data('dom_flows', all_dom_flows)
            context.add_shared_data('dom_flow_findings', result.findings)
            
            logger.info("DOM flow analysis completed", 
                       target=context.target,
                       flows_found=total_flows,
                       high_risk=len([f for f in result.findings if f.get('severity') in ['critical', 'high']]))
            
        except Exception as e:
            error_msg = f"DOM flow analysis plugin failed: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg, target=context.target)
        
        finally:
            result.execution_time = asyncio.get_event_loop().time() - start_time
        
        return result
    
    def _map_sink_to_exploitation(self, sink_risk: str) -> ExploitationLikelihood:
        """Map sink risk level to exploitation likelihood."""
        mapping = {
            'critical': ExploitationLikelihood.HIGH,
            'high': ExploitationLikelihood.HIGH,
            'medium': ExploitationLikelihood.MEDIUM,
            'low': ExploitationLikelihood.LOW
        }
        return mapping.get(sink_risk, ExploitationLikelihood.MEDIUM)
    
    def _get_remediation_advice(self, source: Dict[str, Any], sink: Dict[str, Any]) -> str:
        """Get remediation advice for DOM flow vulnerability."""
        source_name = source.get('name', '')
        sink_name = sink.get('name', '')
        
        advice = "General DOM XSS Prevention:\n"
        advice += "1. Validate and sanitize all user input\n"
        advice += "2. Use textContent instead of innerHTML when possible\n"
        advice += "3. Implement Content Security Policy (CSP)\n"
        advice += "4. Use DOM purification libraries like DOMPurify\n\n"
        
        # Specific advice based on sink type
        if 'innerHTML' in sink_name:
            advice += "Specific: Replace innerHTML with textContent or use DOMPurify for sanitization.\n"
        elif 'eval' in sink_name:
            advice += "Specific: Avoid eval() - use JSON.parse() for data or safer alternatives.\n"
        elif 'setTimeout' in sink_name or 'setInterval' in sink_name:
            advice += "Specific: Use function references instead of string arguments in setTimeout/setInterval.\n"
        elif 'location' in sink_name:
            advice += "Specific: Validate URLs before redirecting and use allowlists for trusted domains.\n"
        
        return advice
    
    def _get_flow_risk_distribution(self, dom_flows: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of flow risk levels."""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for flow in dom_flows:
            risk_level = flow.get('overall_risk', 'low')
            if risk_level in distribution:
                distribution[risk_level] += 1
        return distribution
    
    def _get_source_distribution(self, dom_flows: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of source types."""
        distribution = {}
        for flow in dom_flows:
            for source in flow.get('sources', []):
                source_name = source.get('name', 'unknown')
                distribution[source_name] = distribution.get(source_name, 0) + 1
        return distribution
    
    def _get_sink_distribution(self, dom_flows: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of sink types."""
        distribution = {}
        for flow in dom_flows:
            for sink in flow.get('sinks', []):
                sink_name = sink.get('name', 'unknown')
                distribution[sink_name] = distribution.get(sink_name, 0) + 1
        return distribution