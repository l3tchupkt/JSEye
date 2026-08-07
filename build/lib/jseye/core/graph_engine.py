"""Attack Surface Graph Engine for JSEye v2.1."""

import json
from typing import Dict, List, Any, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
from .logging import get_logger

logger = get_logger(__name__)


@dataclass
class GraphNode:
    """Represents a node in the attack surface graph."""
    id: str
    type: str  # 'js_file', 'endpoint', 'secret', 'library', 'domain', 'vulnerability'
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = 'low'
    size: int = 10  # Visual size for rendering


@dataclass
class GraphEdge:
    """Represents an edge (relationship) in the attack surface graph."""
    source: str
    target: str
    type: str  # 'contains', 'calls', 'exposes', 'vulnerable_to', 'connects_to'
    label: str = ''
    properties: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0


@dataclass
class AttackSurfaceGraph:
    """Complete attack surface graph representation."""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    metadata: Dict[str, Any]
    statistics: Dict[str, Any]


class GraphEngine:
    """Engine for generating attack surface relationship graphs."""
    
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.node_counter = 0
    
    def generate_attack_surface_graph(self, scan_results: Dict[str, Any]) -> AttackSurfaceGraph:
        """Generate complete attack surface graph from scan results."""
        try:
            logger.info("Generating attack surface graph", target=scan_results.get('target', 'unknown'))
            
            # Reset graph state
            self.nodes.clear()
            self.edges.clear()
            self.node_counter = 0
            
            # Create nodes for different entities
            self._create_js_file_nodes(scan_results)
            self._create_endpoint_nodes(scan_results)
            self._create_secret_nodes(scan_results)
            self._create_library_nodes(scan_results)
            self._create_domain_nodes(scan_results)
            self._create_vulnerability_nodes(scan_results)
            
            # Create relationships (edges)
            self._create_file_relationships(scan_results)
            self._create_endpoint_relationships(scan_results)
            self._create_secret_relationships(scan_results)
            self._create_library_relationships(scan_results)
            self._create_vulnerability_relationships(scan_results)
            
            # Generate statistics
            statistics = self._generate_graph_statistics()
            
            # Create metadata
            metadata = {
                'target': scan_results.get('target', ''),
                'generation_time': scan_results.get('scan_metadata', {}).get('end_time', 0),
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges),
                'node_types': self._get_node_type_distribution(),
                'edge_types': self._get_edge_type_distribution()
            }
            
            graph = AttackSurfaceGraph(
                nodes=list(self.nodes.values()),
                edges=self.edges,
                metadata=metadata,
                statistics=statistics
            )
            
            logger.info("Attack surface graph generated",
                       nodes=len(self.nodes),
                       edges=len(self.edges))
            
            return graph
            
        except Exception as e:
            logger.error(f"Failed to generate attack surface graph: {e}")
            return AttackSurfaceGraph(
                nodes=[],
                edges=[],
                metadata={'error': str(e)},
                statistics={}
            )
    
    def _create_js_file_nodes(self, scan_results: Dict[str, Any]) -> None:
        """Create nodes for JavaScript files."""
        js_files = scan_results.get('js_files', [])
        
        for js_file in js_files:
            url = js_file.get('url', '')
            if not url:
                continue
            
            node_id = self._generate_node_id('js_file')
            
            # Determine risk level based on file properties
            risk_level = 'low'
            size = js_file.get('size', 0)
            
            if size > 1024 * 1024:  # > 1MB
                risk_level = 'medium'
            if size > 5 * 1024 * 1024:  # > 5MB
                risk_level = 'high'
            
            # Check if file contains secrets or vulnerabilities
            secrets_in_file = [s for s in scan_results.get('secrets', []) if s.get('source_file') == url]
            if secrets_in_file:
                risk_level = 'high'
                if any(s.get('risk_level') == 'Critical' for s in secrets_in_file):
                    risk_level = 'critical'
            
            node = GraphNode(
                id=node_id,
                type='js_file',
                label=self._get_filename_from_url(url),
                properties={
                    'url': url,
                    'size': size,
                    'source': js_file.get('source', 'direct'),
                    'hash': js_file.get('hash', ''),
                    'secrets_count': len(secrets_in_file)
                },
                risk_level=risk_level,
                size=min(max(size // 10000, 10), 50)  # Scale size for visualization
            )
            
            self.nodes[node_id] = node
    
    def _create_endpoint_nodes(self, scan_results: Dict[str, Any]) -> None:
        """Create nodes for API endpoints."""
        endpoints = scan_results.get('endpoints', [])
        api_analysis = scan_results.get('api_analysis', [])
        
        # Create endpoint nodes
        for endpoint in endpoints:
            if not endpoint:
                continue
            
            node_id = self._generate_node_id('endpoint')
            
            # Find corresponding API analysis
            endpoint_analysis = None
            for api in api_analysis:
                if isinstance(api, dict) and api.get('url') == endpoint:
                    endpoint_analysis = api
                    break
            
            # Determine risk level
            risk_level = 'low'
            if endpoint_analysis:
                vulnerabilities = endpoint_analysis.get('vulnerabilities', [])
                if vulnerabilities:
                    risk_level = 'medium'
                    if any(v.get('severity') in ['high', 'critical'] for v in vulnerabilities):
                        risk_level = 'high'
            
            node = GraphNode(
                id=node_id,
                type='endpoint',
                label=self._truncate_url(endpoint),
                properties={
                    'url': endpoint,
                    'domain': self._extract_domain(endpoint),
                    'path': self._extract_path(endpoint),
                    'vulnerabilities': len(endpoint_analysis.get('vulnerabilities', [])) if endpoint_analysis else 0,
                    'api_type': endpoint_analysis.get('api_type', 'unknown') if endpoint_analysis else 'unknown'
                },
                risk_level=risk_level,
                size=15
            )
            
            self.nodes[node_id] = node
    
    def _create_secret_nodes(self, scan_results: Dict[str, Any]) -> None:
        """Create nodes for detected secrets."""
        secrets = scan_results.get('secrets', [])
        
        for secret in secrets:
            node_id = self._generate_node_id('secret')
            
            # Map risk level
            risk_level = secret.get('risk_level', 'Low').lower()
            
            node = GraphNode(
                id=node_id,
                type='secret',
                label=f"{secret.get('description', 'Secret')} ({secret.get('type', 'unknown')})",
                properties={
                    'type': secret.get('type', 'unknown'),
                    'severity': secret.get('severity', 'medium'),
                    'confidence': secret.get('enhanced_confidence', secret.get('confidence', 0)),
                    'risk_score': secret.get('risk_score', 0),
                    'source_file': secret.get('source_file', ''),
                    'detection_method': secret.get('detection_method', 'unknown')
                },
                risk_level=risk_level,
                size=20 if risk_level in ['high', 'critical'] else 15
            )
            
            self.nodes[node_id] = node
    
    def _create_library_nodes(self, scan_results: Dict[str, Any]) -> None:
        """Create nodes for JavaScript libraries."""
        library_vulns = scan_results.get('library_vulnerabilities', [])
        
        for lib_vuln in library_vulns:
            library_info = lib_vuln.get('library', {})
            cves = lib_vuln.get('cves', [])
            
            node_id = self._generate_node_id('library')
            
            # Determine risk level based on CVEs
            risk_level = 'low'
            if cves:
                risk_level = 'medium'
                if any(cve.get('severity') == 'critical' for cve in cves):
                    risk_level = 'critical'
                elif any(cve.get('severity') == 'high' for cve in cves):
                    risk_level = 'high'
            
            node = GraphNode(
                id=node_id,
                type='library',
                label=f"{library_info.get('name', 'Unknown')} v{library_info.get('version', 'Unknown')}",
                properties={
                    'name': library_info.get('name', 'Unknown'),
                    'version': library_info.get('version', 'Unknown'),
                    'detection_method': library_info.get('detection_method', 'unknown'),
                    'confidence': library_info.get('confidence', 0),
                    'cve_count': len(cves),
                    'file_url': library_info.get('file_url', '')
                },
                risk_level=risk_level,
                size=25 if len(cves) > 0 else 15
            )
            
            self.nodes[node_id] = node
    
    def _create_domain_nodes(self, scan_results: Dict[str, Any]) -> None:
        """Create nodes for external domains."""
        domains = set()
        
        # Extract domains from endpoints
        for endpoint in scan_results.get('endpoints', []):
            domain = self._extract_domain(endpoint)
            if domain:
                domains.add(domain)
        
        # Extract domains from JS files
        for js_file in scan_results.get('js_files', []):
            url = js_file.get('url', '')
            domain = self._extract_domain(url)
            if domain:
                domains.add(domain)
        
        # Create domain nodes
        target_domain = self._extract_domain(scan_results.get('target', ''))
        
        for domain in domains:
            node_id = self._generate_node_id('domain')
            
            # Determine if external domain
            is_external = domain != target_domain
            risk_level = 'medium' if is_external else 'low'
            
            node = GraphNode(
                id=node_id,
                type='domain',
                label=domain,
                properties={
                    'domain': domain,
                    'is_external': is_external,
                    'is_target': domain == target_domain
                },
                risk_level=risk_level,
                size=30 if domain == target_domain else 20
            )
            
            self.nodes[node_id] = node
    
    def _create_vulnerability_nodes(self, scan_results: Dict[str, Any]) -> None:
        """Create nodes for vulnerabilities."""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            node_id = self._generate_node_id('vulnerability')
            
            severity = vuln.get('severity', 'Medium')
            risk_level = severity.lower()
            
            node = GraphNode(
                id=node_id,
                type='vulnerability',
                label=vuln.get('type', 'Unknown Vulnerability'),
                properties={
                    'type': vuln.get('type', 'unknown'),
                    'severity': severity,
                    'count': vuln.get('count', 1),
                    'description': vuln.get('description', ''),
                    'affected_resources': vuln.get('affected_resources', [])
                },
                risk_level=risk_level,
                size=30 if risk_level in ['high', 'critical'] else 20
            )
            
            self.nodes[node_id] = node
    
    def _create_file_relationships(self, scan_results: Dict[str, Any]) -> None:
        """Create relationships between files and other entities."""
        # Connect JS files to domains
        for js_file_node in [n for n in self.nodes.values() if n.type == 'js_file']:
            file_url = js_file_node.properties.get('url', '')
            file_domain = self._extract_domain(file_url)
            
            # Find corresponding domain node
            domain_node = self._find_node_by_property('domain', 'domain', file_domain)
            if domain_node:
                self._add_edge(domain_node.id, js_file_node.id, 'hosts', 'hosts')
    
    def _create_endpoint_relationships(self, scan_results: Dict[str, Any]) -> None:
        """Create relationships for endpoints."""
        # Connect endpoints to domains
        for endpoint_node in [n for n in self.nodes.values() if n.type == 'endpoint']:
            endpoint_domain = endpoint_node.properties.get('domain', '')
            
            # Find corresponding domain node
            domain_node = self._find_node_by_property('domain', 'domain', endpoint_domain)
            if domain_node:
                self._add_edge(domain_node.id, endpoint_node.id, 'exposes', 'exposes')
        
        # Connect JS files to endpoints they reference
        for js_file in scan_results.get('js_files', []):
            js_file_url = js_file.get('url', '')
            js_file_node = self._find_node_by_property('js_file', 'url', js_file_url)
            
            if js_file_node:
                # Simple heuristic: if endpoint URL appears in JS file content
                content = js_file.get('content', '')
                for endpoint in scan_results.get('endpoints', []):
                    if endpoint in content:
                        endpoint_node = self._find_node_by_property('endpoint', 'url', endpoint)
                        if endpoint_node:
                            self._add_edge(js_file_node.id, endpoint_node.id, 'calls', 'calls')
    
    def _create_secret_relationships(self, scan_results: Dict[str, Any]) -> None:
        """Create relationships for secrets."""
        # Connect secrets to their source files
        for secret in scan_results.get('secrets', []):
            source_file = secret.get('source_file', '')
            if source_file:
                js_file_node = self._find_node_by_property('js_file', 'url', source_file)
                secret_node = self._find_node_by_secret_properties(secret)
                
                if js_file_node and secret_node:
                    self._add_edge(js_file_node.id, secret_node.id, 'contains', 'contains secret')
    
    def _create_library_relationships(self, scan_results: Dict[str, Any]) -> None:
        """Create relationships for libraries."""
        # Connect libraries to their source files
        for lib_vuln in scan_results.get('library_vulnerabilities', []):
            library_info = lib_vuln.get('library', {})
            file_url = library_info.get('file_url', '')
            
            if file_url:
                js_file_node = self._find_node_by_property('js_file', 'url', file_url)
                library_node = self._find_node_by_library_info(library_info)
                
                if js_file_node and library_node:
                    self._add_edge(js_file_node.id, library_node.id, 'includes', 'includes library')
    
    def _create_vulnerability_relationships(self, scan_results: Dict[str, Any]) -> None:
        """Create relationships for vulnerabilities."""
        # Connect vulnerabilities to affected resources
        for vuln in scan_results.get('vulnerabilities', []):
            vuln_node = self._find_node_by_vulnerability(vuln)
            if not vuln_node:
                continue
            
            affected_resources = vuln.get('affected_resources', [])
            for resource in affected_resources:
                # Try to find corresponding node
                target_node = (
                    self._find_node_by_property('js_file', 'url', resource) or
                    self._find_node_by_property('endpoint', 'url', resource) or
                    self._find_node_by_property('library', 'name', resource)
                )
                
                if target_node:
                    self._add_edge(target_node.id, vuln_node.id, 'vulnerable_to', 'vulnerable to')
    
    def _generate_node_id(self, node_type: str) -> str:
        """Generate unique node ID."""
        self.node_counter += 1
        return f"{node_type}_{self.node_counter}"
    
    def _add_edge(self, source_id: str, target_id: str, edge_type: str, label: str, weight: float = 1.0) -> None:
        """Add edge to the graph."""
        edge = GraphEdge(
            source=source_id,
            target=target_id,
            type=edge_type,
            label=label,
            weight=weight
        )
        self.edges.append(edge)
    
    def _find_node_by_property(self, node_type: str, property_name: str, property_value: str) -> GraphNode:
        """Find node by type and property value."""
        for node in self.nodes.values():
            if (node.type == node_type and 
                node.properties.get(property_name) == property_value):
                return node
        return None
    
    def _find_node_by_secret_properties(self, secret: Dict[str, Any]) -> GraphNode:
        """Find secret node by properties."""
        secret_type = secret.get('type', 'unknown')
        source_file = secret.get('source_file', '')
        
        for node in self.nodes.values():
            if (node.type == 'secret' and 
                node.properties.get('type') == secret_type and
                node.properties.get('source_file') == source_file):
                return node
        return None
    
    def _find_node_by_library_info(self, library_info: Dict[str, Any]) -> GraphNode:
        """Find library node by library info."""
        lib_name = library_info.get('name', 'Unknown')
        lib_version = library_info.get('version', 'Unknown')
        
        for node in self.nodes.values():
            if (node.type == 'library' and 
                node.properties.get('name') == lib_name and
                node.properties.get('version') == lib_version):
                return node
        return None
    
    def _find_node_by_vulnerability(self, vuln: Dict[str, Any]) -> GraphNode:
        """Find vulnerability node by vulnerability info."""
        vuln_type = vuln.get('type', 'unknown')
        
        for node in self.nodes.values():
            if (node.type == 'vulnerability' and 
                node.properties.get('type') == vuln_type):
                return node
        return None
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return ''
    
    def _extract_path(self, url: str) -> str:
        """Extract path from URL."""
        try:
            parsed = urlparse(url)
            return parsed.path
        except Exception:
            return ''
    
    def _get_filename_from_url(self, url: str) -> str:
        """Extract filename from URL."""
        try:
            parsed = urlparse(url)
            path = parsed.path
            if '/' in path:
                return path.split('/')[-1] or 'index.js'
            return path or 'script.js'
        except Exception:
            return 'script.js'
    
    def _truncate_url(self, url: str, max_length: int = 50) -> str:
        """Truncate URL for display."""
        if len(url) <= max_length:
            return url
        return url[:max_length-3] + '...'
    
    def _generate_graph_statistics(self) -> Dict[str, Any]:
        """Generate graph statistics."""
        node_types = {}
        edge_types = {}
        risk_distribution = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for node in self.nodes.values():
            node_types[node.type] = node_types.get(node.type, 0) + 1
            risk_distribution[node.risk_level] = risk_distribution.get(node.risk_level, 0) + 1
        
        for edge in self.edges:
            edge_types[edge.type] = edge_types.get(edge.type, 0) + 1
        
        return {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'node_types': node_types,
            'edge_types': edge_types,
            'risk_distribution': risk_distribution,
            'graph_density': len(self.edges) / (len(self.nodes) * (len(self.nodes) - 1)) if len(self.nodes) > 1 else 0,
            'average_degree': (2 * len(self.edges)) / len(self.nodes) if len(self.nodes) > 0 else 0
        }
    
    def _get_node_type_distribution(self) -> Dict[str, int]:
        """Get distribution of node types."""
        distribution = {}
        for node in self.nodes.values():
            distribution[node.type] = distribution.get(node.type, 0) + 1
        return distribution
    
    def _get_edge_type_distribution(self) -> Dict[str, int]:
        """Get distribution of edge types."""
        distribution = {}
        for edge in self.edges:
            distribution[edge.type] = distribution.get(edge.type, 0) + 1
        return distribution
    
    def export_graph_json(self, graph: AttackSurfaceGraph, filepath: str) -> bool:
        """Export graph to JSON format."""
        try:
            graph_data = {
                'nodes': [
                    {
                        'id': node.id,
                        'type': node.type,
                        'label': node.label,
                        'properties': node.properties,
                        'risk_level': node.risk_level,
                        'size': node.size
                    }
                    for node in graph.nodes
                ],
                'edges': [
                    {
                        'source': edge.source,
                        'target': edge.target,
                        'type': edge.type,
                        'label': edge.label,
                        'properties': edge.properties,
                        'weight': edge.weight
                    }
                    for edge in graph.edges
                ],
                'metadata': graph.metadata,
                'statistics': graph.statistics
            }
            
            with open(filepath, 'w') as f:
                json.dump(graph_data, f, indent=2, default=str)
            
            logger.info(f"Attack surface graph exported to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export graph: {e}")
            return False