"""DOM sink and source flow analysis engine for XSS detection."""

import re
from typing import Dict, List, Any, Set, Tuple, Optional
from dataclasses import dataclass
from .logging import get_logger

logger = get_logger(__name__)


@dataclass
class DOMSource:
    """Represents a DOM source that can introduce user input."""
    name: str
    line: int
    context: str
    risk_level: str  # 'high', 'medium', 'low'
    description: str


@dataclass
class DOMSink:
    """Represents a DOM sink that can execute code or modify DOM."""
    name: str
    line: int
    context: str
    risk_level: str  # 'critical', 'high', 'medium', 'low'
    description: str


@dataclass
class FlowPath:
    """Represents a data flow from source to sink."""
    source: DOMSource
    sink: DOMSink
    path_variables: List[str]
    confidence: float
    risk_score: int


class DOMFlowAnalyzer:
    """Analyzes DOM-based data flows for XSS vulnerabilities."""
    
    def __init__(self):
        # DOM sources (user input)
        self.sources = {
            'location.search': {'risk': 'high', 'desc': 'URL query parameters'},
            'location.hash': {'risk': 'high', 'desc': 'URL fragment'},
            'location.href': {'risk': 'medium', 'desc': 'Full URL'},
            'location.pathname': {'risk': 'medium', 'desc': 'URL path'},
            'document.cookie': {'risk': 'medium', 'desc': 'HTTP cookies'},
            'window.name': {'risk': 'medium', 'desc': 'Window name property'},
            'document.referrer': {'risk': 'low', 'desc': 'HTTP referrer'},
            'localStorage.getItem': {'risk': 'medium', 'desc': 'Local storage'},
            'sessionStorage.getItem': {'risk': 'medium', 'desc': 'Session storage'},
            'postMessage': {'risk': 'high', 'desc': 'Cross-frame messaging'},
            'addEventListener.*message': {'risk': 'high', 'desc': 'Message event listener'},
            'XMLHttpRequest.responseText': {'risk': 'medium', 'desc': 'AJAX response'},
            'fetch.*then': {'risk': 'medium', 'desc': 'Fetch API response'},
        }
        
        # DOM sinks (code execution or DOM modification)
        self.sinks = {
            'innerHTML': {'risk': 'critical', 'desc': 'Direct HTML injection'},
            'outerHTML': {'risk': 'critical', 'desc': 'Outer HTML replacement'},
            'insertAdjacentHTML': {'risk': 'critical', 'desc': 'Adjacent HTML insertion'},
            'document.write': {'risk': 'critical', 'desc': 'Document write'},
            'document.writeln': {'risk': 'critical', 'desc': 'Document write line'},
            'eval': {'risk': 'critical', 'desc': 'Code evaluation'},
            'Function': {'risk': 'critical', 'desc': 'Function constructor'},
            'setTimeout.*string': {'risk': 'high', 'desc': 'Timeout with string'},
            'setInterval.*string': {'risk': 'high', 'desc': 'Interval with string'},
            'execScript': {'risk': 'critical', 'desc': 'Script execution (IE)'},
            'location.href': {'risk': 'high', 'desc': 'URL redirection'},
            'location.replace': {'risk': 'high', 'desc': 'Location replacement'},
            'location.assign': {'risk': 'high', 'desc': 'Location assignment'},
            'window.open': {'risk': 'medium', 'desc': 'Window opening'},
            'document.domain': {'risk': 'high', 'desc': 'Domain modification'},
            'script.src': {'risk': 'high', 'desc': 'Script source modification'},
            'iframe.src': {'risk': 'medium', 'desc': 'Iframe source modification'},
        }
    
    def analyze_dom_flows(self, content: str, source_url: str = "") -> Dict[str, Any]:
        """Analyze DOM-based data flows in JavaScript content."""
        try:
            lines = content.split('\n')
            
            # Find sources and sinks
            found_sources = self._find_sources(lines)
            found_sinks = self._find_sinks(lines)
            
            # Analyze data flows
            flow_paths = self._analyze_flows(lines, found_sources, found_sinks)
            
            # Calculate overall risk
            overall_risk = self._calculate_overall_risk(flow_paths)
            
            return {
                'source_url': source_url,
                'sources': [vars(s) for s in found_sources],
                'sinks': [vars(s) for s in found_sinks],
                'flow_paths': [self._flow_path_to_dict(fp) for fp in flow_paths],
                'overall_risk': overall_risk,
                'xss_risk_score': self._calculate_xss_risk_score(flow_paths),
                'recommendations': self._generate_recommendations(flow_paths)
            }
            
        except Exception as e:
            logger.error(f"DOM flow analysis failed for {source_url}", error=str(e))
            return {
                'source_url': source_url,
                'sources': [],
                'sinks': [],
                'flow_paths': [],
                'overall_risk': 'unknown',
                'xss_risk_score': 0,
                'recommendations': []
            }
    
    def _find_sources(self, lines: List[str]) -> List[DOMSource]:
        """Find DOM sources in the code."""
        sources = []
        
        for line_num, line in enumerate(lines, 1):
            for source_pattern, source_info in self.sources.items():
                # Create regex pattern
                if '.*' in source_pattern:
                    pattern = source_pattern.replace('.*', r'[^(]*')
                else:
                    pattern = re.escape(source_pattern)
                
                if re.search(pattern, line, re.IGNORECASE):
                    sources.append(DOMSource(
                        name=source_pattern,
                        line=line_num,
                        context=line.strip(),
                        risk_level=source_info['risk'],
                        description=source_info['desc']
                    ))
        
        return sources
    
    def _find_sinks(self, lines: List[str]) -> List[DOMSink]:
        """Find DOM sinks in the code."""
        sinks = []
        
        for line_num, line in enumerate(lines, 1):
            for sink_pattern, sink_info in self.sinks.items():
                # Handle special patterns
                if '.*' in sink_pattern:
                    # For patterns like setTimeout.*string
                    base_pattern = sink_pattern.split('.*')[0]
                    if base_pattern in line and self._is_string_argument(line, base_pattern):
                        sinks.append(DOMSink(
                            name=sink_pattern,
                            line=line_num,
                            context=line.strip(),
                            risk_level=sink_info['risk'],
                            description=sink_info['desc']
                        ))
                else:
                    # Direct pattern matching
                    if re.search(rf'\b{re.escape(sink_pattern)}\b', line):
                        sinks.append(DOMSink(
                            name=sink_pattern,
                            line=line_num,
                            context=line.strip(),
                            risk_level=sink_info['risk'],
                            description=sink_info['desc']
                        ))
        
        return sinks
    
    def _is_string_argument(self, line: str, function_name: str) -> bool:
        """Check if function is called with string argument."""
        # Look for function calls with string literals
        pattern = rf'{re.escape(function_name)}\s*\(\s*["\'][^"\']*["\']'
        return bool(re.search(pattern, line))
    
    def _analyze_flows(self, lines: List[str], sources: List[DOMSource], 
                      sinks: List[DOMSink]) -> List[FlowPath]:
        """Analyze data flows between sources and sinks."""
        flow_paths = []
        
        if not sources or not sinks:
            return flow_paths
        
        # Extract variable assignments and usage
        variable_flows = self._track_variable_flows(lines)
        
        # For each source-sink pair, check if there's a potential flow
        for source in sources:
            for sink in sinks:
                flow_path = self._find_flow_path(source, sink, variable_flows, lines)
                if flow_path:
                    flow_paths.append(flow_path)
        
        return flow_paths
    
    def _track_variable_flows(self, lines: List[str]) -> Dict[str, List[Tuple[int, str]]]:
        """Track variable assignments and usage."""
        variable_flows = {}
        
        for line_num, line in enumerate(lines, 1):
            # Find variable assignments
            assignment_patterns = [
                r'(?:var|let|const)\s+(\w+)\s*=\s*([^;]+)',
                r'(\w+)\s*=\s*([^;]+)',
            ]
            
            for pattern in assignment_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    var_name = match.group(1)
                    var_value = match.group(2).strip()
                    
                    if var_name not in variable_flows:
                        variable_flows[var_name] = []
                    
                    variable_flows[var_name].append((line_num, var_value))
        
        return variable_flows
    
    def _find_flow_path(self, source: DOMSource, sink: DOMSink, 
                       variable_flows: Dict[str, List[Tuple[int, str]]], 
                       lines: List[str]) -> Optional[FlowPath]:
        """Find a flow path between source and sink."""
        # Simple heuristic-based flow detection
        
        # Check if source and sink are on the same line (direct flow)
        if source.line == sink.line:
            return FlowPath(
                source=source,
                sink=sink,
                path_variables=[],
                confidence=0.9,
                risk_score=self._calculate_flow_risk_score(source, sink, [])
            )
        
        # Check for variable-mediated flows
        path_variables = []
        confidence = 0.0
        
        # Look for variables that might connect source to sink
        for var_name, assignments in variable_flows.items():
            source_connected = False
            sink_connected = False
            
            # Check if variable is assigned from source
            for line_num, value in assignments:
                if abs(line_num - source.line) <= 5:  # Within 5 lines
                    if any(src_keyword in value for src_keyword in ['location', 'document', 'window']):
                        source_connected = True
            
            # Check if variable is used in sink
            if sink.line < len(lines):
                sink_line = lines[sink.line - 1]
                if var_name in sink_line:
                    sink_connected = True
            
            if source_connected and sink_connected:
                path_variables.append(var_name)
                confidence += 0.3
        
        # Check for proximity-based flows (same function, nearby lines)
        line_distance = abs(source.line - sink.line)
        if line_distance <= 10:
            confidence += max(0, (10 - line_distance) / 10 * 0.4)
        
        # Require minimum confidence for flow detection
        if confidence >= 0.3:
            return FlowPath(
                source=source,
                sink=sink,
                path_variables=path_variables,
                confidence=min(confidence, 1.0),
                risk_score=self._calculate_flow_risk_score(source, sink, path_variables)
            )
        
        return None
    
    def _calculate_flow_risk_score(self, source: DOMSource, sink: DOMSink, 
                                  path_variables: List[str]) -> int:
        """Calculate risk score for a flow path."""
        # Base scores
        source_scores = {'high': 30, 'medium': 20, 'low': 10}
        sink_scores = {'critical': 50, 'high': 35, 'medium': 20, 'low': 10}
        
        base_score = source_scores.get(source.risk_level, 10) + sink_scores.get(sink.risk_level, 10)
        
        # Adjust for path complexity
        if not path_variables:
            # Direct flow is higher risk
            base_score += 10
        else:
            # More variables in path might indicate sanitization
            base_score -= min(len(path_variables) * 5, 15)
        
        return min(max(base_score, 0), 100)
    
    def _calculate_overall_risk(self, flow_paths: List[FlowPath]) -> str:
        """Calculate overall DOM XSS risk level."""
        if not flow_paths:
            return 'low'
        
        max_risk_score = max(fp.risk_score for fp in flow_paths)
        
        if max_risk_score >= 80:
            return 'critical'
        elif max_risk_score >= 60:
            return 'high'
        elif max_risk_score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_xss_risk_score(self, flow_paths: List[FlowPath]) -> int:
        """Calculate numerical XSS risk score."""
        if not flow_paths:
            return 0
        
        # Weight by confidence and combine scores
        total_score = 0
        total_weight = 0
        
        for fp in flow_paths:
            weight = fp.confidence
            total_score += fp.risk_score * weight
            total_weight += weight
        
        if total_weight == 0:
            return 0
        
        return min(int(total_score / total_weight), 100)
    
    def _generate_recommendations(self, flow_paths: List[FlowPath]) -> List[str]:
        """Generate security recommendations based on found flows."""
        recommendations = []
        
        if not flow_paths:
            return ["No DOM-based data flows detected."]
        
        # General recommendations
        recommendations.append("Validate and sanitize all user input before using in DOM operations.")
        recommendations.append("Use textContent instead of innerHTML when possible.")
        recommendations.append("Implement Content Security Policy (CSP) to prevent XSS.")
        
        # Specific recommendations based on sinks found
        sink_types = set(fp.sink.name for fp in flow_paths)
        
        if any('innerHTML' in sink for sink in sink_types):
            recommendations.append("Replace innerHTML with safer alternatives like textContent or use DOMPurify for sanitization.")
        
        if any('eval' in sink for sink in sink_types):
            recommendations.append("Avoid using eval() - use JSON.parse() for data or safer alternatives for code execution.")
        
        if any('setTimeout' in sink or 'setInterval' in sink for sink in sink_types):
            recommendations.append("Use function references instead of string arguments in setTimeout/setInterval.")
        
        if any('location' in sink for sink in sink_types):
            recommendations.append("Validate URLs before redirecting and use allowlists for trusted domains.")
        
        return recommendations
    
    def _flow_path_to_dict(self, flow_path: FlowPath) -> Dict[str, Any]:
        """Convert FlowPath dataclass to dictionary."""
        return {
            'source': vars(flow_path.source),
            'sink': vars(flow_path.sink),
            'path_variables': flow_path.path_variables,
            'confidence': flow_path.confidence,
            'risk_score': flow_path.risk_score
        }