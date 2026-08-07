"""Enhanced main crawler v2 orchestrating all analysis components."""

import asyncio
import time
from typing import List, Dict, Any, Optional
from .collector import JSCollector
from .js_parser import JSParser
from .ast_engine import JSASTAnalyzer
from .secret_engine import SecretDetector
from .api_engine import APIIntelligence
from .dom_flow import DOMFlowAnalyzer
from .cve_engine import CVEIntelligenceEngine
from .wayback import WaybackIntegration
from .gau import GAUIntegration
from .headless import HeadlessBrowser
from .export_engine import ExportEngine
from .utils import calculate_sha256, deduplicate_by_hash
from .logging import get_logger
from .exceptions import JSEyeAnalysisError
from ..version import __version__

logger = get_logger(__name__)


class JSEyeCrawler:
    """Enhanced main crawler v2 that orchestrates all analysis components."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Validate and set configuration with defaults
        self.timeout = max(config.get('timeout', 10), 1)  # Minimum 1 second
        self.threads = max(config.get('threads', 20), 1)  # Minimum 1 thread
        
        self.enable_wayback = config.get('wayback', True)
        self.enable_gau = config.get('gau', True)
        self.enable_headless = config.get('headless', False)
        self.verbose = config.get('verbose', False)
        self.debug = config.get('debug', False)
        
        # Initialize enhanced components
        self.js_parser = JSParser()
        self.ast_analyzer = JSASTAnalyzer()
        self.secret_detector = SecretDetector()
        self.dom_analyzer = DOMFlowAnalyzer()
        self.export_engine = ExportEngine()
        
        # Results storage with enhanced structure
        self.results = {
            'target': '',
            'scan_config': config,
            'scan_metadata': {
                'start_time': None,
                'end_time': None,
                'duration': 0,
                'jseye_version': __version__
            },
            'js_files': [],
            'secrets': [],
            'endpoints': [],
            'api_analysis': [],
            'dom_flows': [],
            'library_vulnerabilities': [],
            'vulnerabilities': [],
            'statistics': {},
            'errors': []
        }
    
    async def scan_target(self, target: str) -> Dict[str, Any]:
        """Enhanced scan with timing and comprehensive analysis."""
        self.results['target'] = target
        self.results['scan_metadata']['start_time'] = time.time()
        
        try:
            logger.info(f"Starting enhanced scan of {target}")
            
            # Phase 1: JavaScript Collection
            if self.verbose:
                logger.info("Phase 1: Collecting JavaScript files", target=target)
            
            js_files = await self._collect_javascript_files(target)
            self.results['js_files'] = js_files
            
            logger.info(f"Collected {len(js_files)} JavaScript files", target=target, count=len(js_files))
            
            # Phase 2: Enhanced JavaScript Analysis
            if self.verbose:
                logger.info("Phase 2: Enhanced JavaScript analysis", target=target)
            
            analysis_results = await self._analyze_javascript_files(js_files)
            
            # Phase 3: Enhanced Secret Detection
            if self.verbose:
                logger.info("Phase 3: Enhanced secret detection", target=target)
            
            secrets = await self._detect_secrets(js_files)
            self.results['secrets'] = secrets
            
            logger.info(f"Detected {len(secrets)} potential secrets", target=target, count=len(secrets))
            
            # Phase 4: DOM Flow Analysis (New in v2)
            if self.verbose:
                logger.info("Phase 4: DOM flow analysis", target=target)
            
            dom_flows = await self._analyze_dom_flows(js_files)
            self.results['dom_flows'] = dom_flows
            
            # Phase 5: CVE Intelligence (New in v2)
            if self.verbose:
                logger.info("Phase 5: CVE intelligence analysis", target=target)
            
            library_vulns = await self._analyze_library_vulnerabilities(js_files)
            self.results['library_vulnerabilities'] = library_vulns
            
            # Phase 6: Enhanced API Intelligence
            if self.verbose:
                logger.info("Phase 6: Enhanced API intelligence", target=target)
            
            api_analysis = await self._analyze_apis(analysis_results)
            self.results['api_analysis'] = api_analysis
            
            # Phase 7: Headless Analysis (if enabled)
            if self.enable_headless:
                if self.verbose:
                    logger.info("Phase 7: Headless browser analysis", target=target)
                
                headless_results = await self._headless_analysis(target)
                self._merge_headless_results(headless_results)
            
            # Phase 8: Enhanced Risk Assessment
            if self.verbose:
                logger.info("Phase 8: Enhanced risk assessment", target=target)
            
            self._generate_statistics()
            self._assess_risks_v2()
            
            # Record completion
            self.results['scan_metadata']['end_time'] = time.time()
            self.results['scan_metadata']['duration'] = (
                self.results['scan_metadata']['end_time'] - 
                self.results['scan_metadata']['start_time']
            )
            
            logger.info("Enhanced scan completed successfully", 
                       target=target, 
                       duration=self.results['scan_metadata']['duration'])
            
            return self.results
            
        except Exception as e:
            error_msg = f"Enhanced scan failed: {str(e)}"
            self.results['errors'].append(error_msg)
            logger.error(error_msg, target=target, error=str(e))
            
            # Still record timing even on failure
            if self.results['scan_metadata']['start_time']:
                self.results['scan_metadata']['end_time'] = time.time()
                self.results['scan_metadata']['duration'] = (
                    self.results['scan_metadata']['end_time'] - 
                    self.results['scan_metadata']['start_time']
                )
            
            return self.results
    
    async def scan_multiple_targets(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Scan multiple targets."""
        results = []
        
        for target in targets:
            if self.verbose:
                print(f"\n[*] Scanning target: {target}")
            
            # Create new crawler instance for each target
            crawler = JSEyeCrawler(self.config)
            result = await crawler.scan_target(target)
            results.append(result)
        
        return results
    
    async def _collect_javascript_files(self, target: str) -> List[Dict[str, Any]]:
        """Collect JavaScript files from all sources."""
        all_js_files = []
        
        # Direct collection from target
        async with JSCollector(timeout=self.timeout, max_concurrent=self.threads) as collector:
            direct_result = await collector.collect_from_url(target)
            if direct_result.get('js_files'):
                all_js_files.extend(direct_result['js_files'])
        
        # Wayback Machine collection
        if self.enable_wayback:
            try:
                async with WaybackIntegration(timeout=30, max_concurrent=5) as wayback:
                    from .utils import extract_domain
                    domain = extract_domain(target)
                    wayback_files = await wayback.discover_historical_js(domain, limit=500)
                    
                    # Convert wayback format to standard format
                    for wb_file in wayback_files:
                        if wb_file.get('content'):
                            js_file = {
                                'url': wb_file['url'],
                                'content': wb_file['content'],
                                'size': wb_file['size'],
                                'hash': calculate_sha256(wb_file['content']),
                                'source': 'wayback',
                                'type': 'historical'
                            }
                            all_js_files.append(js_file)
            except Exception as e:
                self.results['errors'].append(f"Wayback collection failed: {str(e)}")
        
        # GAU collection
        if self.enable_gau:
            try:
                gau = GAUIntegration(timeout=60)
                if gau.is_available():
                    from .utils import extract_domain
                    domain = extract_domain(target)
                    gau_js_urls = await gau.discover_js_urls(domain)
                    
                    # Fetch content for GAU URLs
                    async with JSCollector(timeout=self.timeout, max_concurrent=self.threads) as collector:
                        for gau_url in gau_js_urls[:100]:  # Limit to avoid overwhelming
                            js_result = await collector.collect_from_url(gau_url['url'])
                            if js_result.get('js_files'):
                                for js_file in js_result['js_files']:
                                    js_file['source'] = 'gau'
                                    all_js_files.append(js_file)
                else:
                    self.results['errors'].append("GAU tool not available")
            except Exception as e:
                self.results['errors'].append(f"GAU collection failed: {str(e)}")
        
        # Deduplicate by hash
        unique_js_files = deduplicate_by_hash(all_js_files, 'hash')
        
        return unique_js_files
    
    async def _analyze_javascript_files(self, js_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhanced JavaScript analysis with AST and advanced parsing."""
        analysis_results = []
        
        for js_file in js_files:
            try:
                content = js_file.get('content', '')
                if not content:
                    continue
                
                file_url = js_file.get('url', '')
                loop = asyncio.get_running_loop()
                
                # Enhanced parsing with original parser in executor
                basic_analysis = await loop.run_in_executor(None, self.js_parser.parse_javascript, content, file_url)
                
                # Advanced AST analysis in executor
                try:
                    ast_analysis = await loop.run_in_executor(None, self.ast_analyzer.analyze, content, file_url)
                    basic_analysis['ast_analysis'] = ast_analysis
                except Exception as e:
                    logger.warning(f"AST analysis failed for {file_url}: {e}")
                    basic_analysis['ast_analysis'] = {}
                
                # Add file metadata
                basic_analysis['file_info'] = {
                    'url': file_url,
                    'size': js_file.get('size', 0),
                    'hash': js_file.get('hash', ''),
                    'source': js_file.get('source', 'direct'),
                    'type': js_file.get('type', 'unknown')
                }
                
                analysis_results.append(basic_analysis)
                
            except Exception as e:
                error_msg = f"Enhanced analysis failed for {js_file.get('url', 'unknown')}: {str(e)}"
                self.results['errors'].append(error_msg)
                logger.error(error_msg)
        
        # Extract and consolidate endpoints from both analyses
        all_endpoints = []
        for analysis in analysis_results:
            # Original endpoints
            endpoints = analysis.get('endpoints', [])
            for endpoint in endpoints:
                if isinstance(endpoint, dict):
                    endpoint['source_file'] = analysis['file_info']['url']
                    all_endpoints.append(endpoint['url'])
                else:
                    all_endpoints.append(str(endpoint))
            
            # AST-derived endpoints
            ast_analysis = analysis.get('ast_analysis', {})
            ast_endpoints = ast_analysis.get('endpoints', [])
            for ast_endpoint in ast_endpoints:
                if isinstance(ast_endpoint, dict):
                    all_endpoints.append(ast_endpoint.get('normalized', ast_endpoint.get('original', '')))
        
        self.results['endpoints'] = list(set(all_endpoints))  # Deduplicate
        
        return analysis_results
    
    async def _detect_secrets(self, js_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect secrets in JavaScript files."""
        all_secrets = []
        
        for js_file in js_files:
            try:
                content = js_file.get('content', '')
                if not content:
                    continue
                
                # Detect secrets
                secrets = self.secret_detector.detect_secrets(content, js_file.get('url', ''))
                
                # Add risk analysis
                for secret in secrets:
                    risk_analysis = self.secret_detector.analyze_secret_risk(secret)
                    secret.update(risk_analysis)
                    secret['remediation'] = self.secret_detector.get_remediation_advice(secret)
                
                all_secrets.extend(secrets)
                
            except Exception as e:
                self.results['errors'].append(f"Secret detection failed for {js_file.get('url', 'unknown')}: {str(e)}")
        
        # Sort by risk score
        all_secrets.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        return all_secrets
    
    async def _analyze_dom_flows(self, js_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze DOM-based data flows for XSS vulnerabilities."""
        dom_flows = []
        
        for js_file in js_files:
            try:
                content = js_file.get('content', '')
                if not content:
                    continue
                
                file_url = js_file.get('url', '')
                
                # Analyze DOM flows
                flow_analysis = self.dom_analyzer.analyze_dom_flows(content, file_url)
                
                if flow_analysis.get('flow_paths'):
                    dom_flows.append(flow_analysis)
                
            except Exception as e:
                error_msg = f"DOM flow analysis failed for {js_file.get('url', 'unknown')}: {str(e)}"
                self.results['errors'].append(error_msg)
                logger.warning(error_msg)
        
        return dom_flows
    
    async def _analyze_library_vulnerabilities(self, js_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze JavaScript libraries for known CVEs."""
        try:
            async with CVEIntelligenceEngine(timeout=30) as cve_engine:
                vulnerabilities = await cve_engine.analyze_libraries_and_cves(js_files)
                return [vars(vuln) for vuln in vulnerabilities]
        except Exception as e:
            error_msg = f"CVE analysis failed: {str(e)}"
            self.results['errors'].append(error_msg)
            logger.warning(error_msg)
            return []
    
    async def _analyze_apis(self, analysis_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze discovered API endpoints."""
        # Collect all unique endpoints
        all_endpoints = set()
        base_url = self.results['target']
        
        for analysis in analysis_results:
            endpoints = analysis.get('endpoints', [])
            for endpoint_info in endpoints:
                if isinstance(endpoint_info, dict):
                    all_endpoints.add(endpoint_info.get('url', ''))
                else:
                    all_endpoints.add(str(endpoint_info))
        
        if not all_endpoints:
            return []
        
        # Analyze endpoints
        try:
            async with APIIntelligence(timeout=self.timeout, max_concurrent=10) as api_engine:
                api_analysis = await api_engine.analyze_endpoints(list(all_endpoints), base_url)
                
                # Check for GraphQL
                graphql_endpoints = [ep for ep in all_endpoints if 'graphql' in ep.lower()]
                for gql_endpoint in graphql_endpoints:
                    gql_analysis = await api_engine.check_graphql_introspection(gql_endpoint)
                    if gql_analysis.get('enabled'):
                        api_analysis.append({
                            'url': gql_endpoint,
                            'type': 'graphql_introspection',
                            'analysis': gql_analysis
                        })
                
                # Check for Swagger/OpenAPI
                swagger_analysis = await api_engine.check_swagger_openapi(base_url)
                if swagger_analysis.get('found'):
                    api_analysis.append({
                        'url': swagger_analysis.get('spec_url', ''),
                        'type': 'swagger_openapi',
                        'analysis': swagger_analysis
                    })
                
                return api_analysis
                
        except Exception as e:
            self.results['errors'].append(f"API analysis failed: {str(e)}")
            return []
    
    async def _headless_analysis(self, target: str) -> Dict[str, Any]:
        """Perform headless browser analysis."""
        try:
            async with HeadlessBrowser(timeout=self.timeout) as browser:
                if not browser.is_available():
                    return {'error': 'Headless browser not available'}
                
                # Analyze main page
                main_analysis = await browser.analyze_page(target)
                
                # Extract dynamic content
                dynamic_content = await browser.extract_dynamic_content(target)
                
                return {
                    'main_analysis': main_analysis,
                    'dynamic_content': dynamic_content
                }
                
        except Exception as e:
            return {'error': str(e)}
    
    def _merge_headless_results(self, headless_results: Dict[str, Any]) -> None:
        """Merge headless browser results into main results."""
        if headless_results.get('error'):
            self.results['errors'].append(f"Headless analysis: {headless_results['error']}")
            return
        
        # Add intercepted network requests to endpoints
        main_analysis = headless_results.get('main_analysis', {})
        network_requests = main_analysis.get('network_requests', [])
        
        for request in network_requests:
            url = request.get('url', '')
            if url and url not in self.results['endpoints']:
                self.results['endpoints'].append(url)
        
        # Add intercepted data
        intercepted_data = main_analysis.get('intercepted_data', {})
        
        # Process fetch calls and XHR requests
        for fetch_call in intercepted_data.get('fetchCalls', []):
            url = fetch_call.get('url', '')
            if url and url not in self.results['endpoints']:
                self.results['endpoints'].append(url)
        
        for xhr_request in intercepted_data.get('xhrRequests', []):
            url = xhr_request.get('url', '')
            if url and url not in self.results['endpoints']:
                self.results['endpoints'].append(url)
        
        # Store headless results
        self.results['headless_analysis'] = headless_results
    
    def _generate_statistics(self) -> None:
        """Generate scan statistics."""
        stats = {
            'total_js_files': len(self.results['js_files']),
            'total_secrets': len(self.results['secrets']),
            'total_endpoints': len(self.results['endpoints']),
            'total_apis_analyzed': len(self.results['api_analysis']),
            'total_errors': len(self.results['errors']),
            'file_sources': {},
            'secret_types': {},
            'risk_distribution': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        }
        
        # File source distribution
        for js_file in self.results['js_files']:
            source = js_file.get('source', 'unknown')
            stats['file_sources'][source] = stats['file_sources'].get(source, 0) + 1
        
        # Secret type distribution
        for secret in self.results['secrets']:
            secret_type = secret.get('type', 'unknown')
            stats['secret_types'][secret_type] = stats['secret_types'].get(secret_type, 0) + 1
            
            # Risk distribution
            risk_level = secret.get('risk_level', 'Low')
            if risk_level in stats['risk_distribution']:
                stats['risk_distribution'][risk_level] += 1
        
        # Calculate total file size
        total_size = sum(js_file.get('size', 0) for js_file in self.results['js_files'])
        stats['total_js_size'] = total_size
        stats['average_file_size'] = total_size // stats['total_js_files'] if stats['total_js_files'] > 0 else 0
        
        self.results['statistics'] = stats
    
    def _assess_risks_v2(self) -> None:
        """Enhanced risk assessment with v2 scoring model."""
        vulnerabilities = []
        
        # High-risk secrets (updated thresholds)
        critical_secrets = [s for s in self.results['secrets'] if s.get('risk_level') == 'Critical']
        if critical_secrets:
            vulnerabilities.append({
                'type': 'critical_secrets_exposed',
                'severity': 'Critical',
                'count': len(critical_secrets),
                'description': f'Found {len(critical_secrets)} critical secrets in JavaScript files',
                'recommendation': 'Immediately rotate all exposed credentials and implement proper secret management',
                'affected_resources': [s.get('source_file', 'unknown') for s in critical_secrets]
            })
        
        # DOM XSS vulnerabilities (new in v2)
        dom_xss_risks = []
        for dom_flow in self.results.get('dom_flows', []):
            if dom_flow.get('overall_risk') in ['critical', 'high']:
                dom_xss_risks.append(dom_flow)
        
        if dom_xss_risks:
            vulnerabilities.append({
                'type': 'dom_xss_vulnerabilities',
                'severity': 'High',
                'count': len(dom_xss_risks),
                'description': f'Found {len(dom_xss_risks)} potential DOM-based XSS vulnerabilities',
                'recommendation': 'Implement input validation and output encoding for DOM operations',
                'affected_resources': [flow.get('source_url', 'unknown') for flow in dom_xss_risks]
            })
        
        # Library vulnerabilities (new in v2)
        critical_cves = []
        for lib_vuln in self.results.get('library_vulnerabilities', []):
            lib_cves = lib_vuln.get('cves', [])
            critical_lib_cves = [cve for cve in lib_cves if cve.get('severity') == 'critical']
            critical_cves.extend(critical_lib_cves)
        
        if critical_cves:
            vulnerabilities.append({
                'type': 'vulnerable_libraries',
                'severity': 'High',
                'count': len(critical_cves),
                'description': f'Found {len(critical_cves)} critical vulnerabilities in JavaScript libraries',
                'recommendation': 'Update vulnerable libraries to latest secure versions',
                'affected_resources': [cve.get('id', 'unknown') for cve in critical_cves]
            })
        
        # Open API endpoints
        open_endpoints = []
        for api in self.results['api_analysis']:
            if isinstance(api, dict):
                methods = api.get('methods', {})
                if methods.get('GET', {}).get('status_code') == 200:
                    open_endpoints.append(api.get('url', ''))
        
        if open_endpoints:
            vulnerabilities.append({
                'type': 'open_api_endpoints',
                'severity': 'Medium',
                'count': len(open_endpoints),
                'description': f'Found {len(open_endpoints)} API endpoints accessible without authentication',
                'recommendation': 'Review API endpoints and implement proper authentication where needed',
                'affected_resources': open_endpoints
            })
        
        # GraphQL introspection
        graphql_introspection = [api for api in self.results['api_analysis'] 
                               if api.get('type') == 'graphql_introspection']
        if graphql_introspection:
            vulnerabilities.append({
                'type': 'graphql_introspection_enabled',
                'severity': 'High',
                'count': len(graphql_introspection),
                'description': 'GraphQL introspection is enabled, exposing schema information',
                'recommendation': 'Disable GraphQL introspection in production environments',
                'affected_resources': [api.get('url', '') for api in graphql_introspection]
            })
        
        # Exposed API documentation
        swagger_docs = [api for api in self.results['api_analysis'] 
                       if api.get('type') == 'swagger_openapi']
        if swagger_docs:
            vulnerabilities.append({
                'type': 'api_documentation_exposed',
                'severity': 'Medium',
                'count': len(swagger_docs),
                'description': 'API documentation is publicly accessible',
                'recommendation': 'Restrict access to API documentation in production',
                'affected_resources': [api.get('url', '') for api in swagger_docs]
            })
        
        self.results['vulnerabilities'] = vulnerabilities
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of scan results."""
        stats = self.results.get('statistics', {})
        
        return {
            'target': self.results['target'],
            'scan_status': 'completed' if not self.results['errors'] else 'completed_with_errors',
            'total_js_files': stats.get('total_js_files', 0),
            'total_secrets': stats.get('total_secrets', 0),
            'critical_secrets': stats.get('risk_distribution', {}).get('Critical', 0),
            'total_endpoints': stats.get('total_endpoints', 0),
            'total_vulnerabilities': len(self.results.get('vulnerabilities', [])),
            'dom_xss_risks': len([f for f in self.results.get('dom_flows', []) if f.get('overall_risk') in ['critical', 'high']]),
            'library_vulnerabilities': len(self.results.get('library_vulnerabilities', [])),
            'errors': len(self.results.get('errors', [])),
            'file_size_mb': round(stats.get('total_js_size', 0) / (1024 * 1024), 2),
            'scan_duration': self.results.get('scan_metadata', {}).get('duration', 0)
        }
    
    async def export_results(self, output_dir: str, formats: List[str]) -> Dict[str, bool]:
        """Export scan results in specified formats."""
        export_results = {}
        
        try:
            # Export wordlist
            if 'wordlist' in formats:
                wordlist_file = f"{output_dir}/endpoints_wordlist.txt"
                export_results['wordlist'] = self.export_engine.export_wordlist(self.results, wordlist_file)
            
            # Export cURL commands
            if 'curl' in formats:
                curl_file = f"{output_dir}/curl_commands.sh"
                export_results['curl'] = self.export_engine.export_curl_commands(self.results, curl_file)
            
            # Export ffuf config
            if 'ffuf' in formats:
                ffuf_file = f"{output_dir}/ffuf_config.json"
                export_results['ffuf'] = self.export_engine.export_ffuf_config(self.results, ffuf_file)
            
            # Export Burp config
            if 'burp' in formats:
                burp_file = f"{output_dir}/burp_sitemap.xml"
                export_results['burp'] = self.export_engine.export_burp_config(self.results, burp_file)
            
            # Export CSV
            if 'csv' in formats:
                csv_file = f"{output_dir}/scan_summary.csv"
                export_results['csv'] = self.export_engine.export_csv(self.results, csv_file)
            
            return export_results
            
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return {fmt: False for fmt in formats}