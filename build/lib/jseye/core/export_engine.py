"""Export engine for hunter-friendly automation formats (v3.0)."""

import csv
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode
from pathlib import Path
from .logging import get_logger

logger = get_logger(__name__)


class ExportEngine:
    """Export scan results to various formats for bug hunting automation."""
    
    def __init__(self):
        pass
    
    def export_wordlist(self, scan_results: Dict[str, Any], output_file: str, wordlist_type: str = 'all') -> bool:
        """
        Export comprehensive parameter wordlist for fuzzing.
        Includes ALL discoveries: endpoints, parameters, API keys, libraries, etc.
        """
        try:
            wordlist_items = set()
            
            # 1. Extract from linkfinder endpoints
            linkfinder_endpoints = scan_results.get('linkfinder_endpoints', [])
            for endpoint in linkfinder_endpoints:
                if isinstance(endpoint, dict):
                    ep_url = endpoint.get('endpoint', '')
                    if ep_url:
                        # Extract path components
                        parts = [p for p in ep_url.split('/') if p and len(p) > 2 and not p.startswith(('http', 'www'))]
                        wordlist_items.update(parts)
                        
                        # Extract from query parameters
                        if '?' in ep_url:
                            query_part = ep_url.split('?')[1]
                            params = [p.split('=')[0] for p in query_part.split('&') if '=' in p]
                            wordlist_items.update(params)
            
            # 2. Extract from regular endpoints
            endpoints = scan_results.get('endpoints', [])
            for endpoint in endpoints:
                if isinstance(endpoint, dict):
                    url = endpoint.get('url', endpoint.get('endpoint', ''))
                else:
                    url = str(endpoint)
                
                if url:
                    parsed = urlparse(url)
                    path_parts = [p for p in parsed.path.split('/') if p and len(p) > 2]
                    wordlist_items.update(path_parts)
                    
                    # Extract query parameters
                    if parsed.query:
                        query_params = parse_qs(parsed.query)
                        wordlist_items.update(query_params.keys())
            
            # 3. Extract from parameters
            parameters = scan_results.get('parameters', [])
            if isinstance(parameters, list):
                for param in parameters:
                    if hasattr(param, 'name'):  # Dataclass
                        wordlist_items.add(param.name)
                    elif isinstance(param, dict):
                        param_name = param.get('name', param.get('parameter', ''))
                        if param_name and len(param_name) > 1:
                            wordlist_items.add(param_name)
            
            # 4. Extract from API endpoints
            api_endpoints = scan_results.get('api_endpoints', [])
            for api_ep in api_endpoints:
                if isinstance(api_ep, dict):
                    # Extract endpoint path parts
                    ep = api_ep.get('endpoint', '')
                    if ep:
                        parts = [p for p in ep.split('/') if p and len(p) > 2]
                        wordlist_items.update(parts)
                    
                    # Extract parameters
                    params = api_ep.get('parameters', [])
                    wordlist_items.update(params)
                    
                    # Extract from classification
                    classification = api_ep.get('classification', '')
                    if classification and len(classification) > 3:
                        wordlist_items.add(classification.lower().replace(' ', '_'))
            
            # 5. Extract from detected libraries (for version fuzzing)
            version_analysis = scan_results.get('version_analysis', {})
            if version_analysis:
                libraries = version_analysis.get('unique_libraries', [])
                for lib in libraries:
                    if len(lib) > 2:
                        wordlist_items.add(lib)
                        wordlist_items.add(f"{lib}.js")
                        wordlist_items.add(f"{lib}.min.js")
            
            # 6. Extract from API key findings (parameter names)
            api_key_findings = scan_results.get('api_key_findings', [])
            for finding in api_key_findings:
                if isinstance(finding, dict):
                    param = finding.get('parameter', '')
                    if param:
                        wordlist_items.add(param)
            
            # 7. Add common high-value parameters
            common_params = [
                # Authentication
                'api_key', 'apikey', 'key', 'token', 'access_token', 'auth', 'authorization',
                'bearer', 'jwt', 'session', 'sessionid', 'csrf', 'xsrf',
                # User data
                'id', 'user', 'username', 'email', 'password', 'passwd', 'pwd',
                'name', 'firstname', 'lastname', 'phone', 'address',
                # Query/Search
                'search', 'query', 'q', 'keyword', 'term', 'find',
                # Pagination
                'page', 'limit', 'offset', 'count', 'size', 'per_page',
                # Sorting/Filtering
                'sort', 'order', 'orderby', 'filter', 'where', 'group',
                # Actions
                'action', 'method', 'operation', 'cmd', 'command', 'exec',
                # Data
                'data', 'value', 'content', 'body', 'payload', 'json', 'xml',
                # File operations
                'file', 'filename', 'path', 'dir', 'folder', 'upload', 'download',
                # Admin/Debug
                'admin', 'debug', 'test', 'dev', 'staging', 'prod', 'env',
                # Callbacks
                'callback', 'redirect', 'return', 'next', 'url', 'link',
                # Categories
                'category', 'type', 'status', 'state', 'mode', 'format',
                # IDs
                'uid', 'gid', 'pid', 'tid', 'sid', 'cid',
            ]
            wordlist_items.update(common_params)
            
            # Write wordlist with header
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# JSEye Comprehensive Wordlist\n")
                f.write(f"# Target: {scan_results.get('target', 'unknown')}\n")
                f.write(f"# Total items: {len(wordlist_items)}\n")
                f.write("# Sources: endpoints, parameters, APIs, libraries, common params\n")
                f.write("#\n")
                f.write("# Usage:\n")
                f.write("# - ffuf -u https://target.com/FUZZ -w this_file.txt\n")
                f.write("# - wfuzz -u https://target.com/FUZZ -w this_file.txt\n")
                f.write("#\n\n")
                
                for item in sorted(wordlist_items):
                    f.write(f"{item}\n")
            
            logger.info(f"Comprehensive wordlist exported to {output_file}", items=len(wordlist_items))
            return True
            
        except Exception as e:
            logger.error(f"Failed to export wordlist: {e}")
            return False
    
    def export_parameters(self, scan_results: Dict[str, Any], output_file: str) -> bool:
        """Export discovered parameters in clean format."""
        try:
            params_data = scan_results.get('parameters', {})
            
            if isinstance(params_data, dict) and 'wordlists' in params_data:
                wordlists = params_data['wordlists']
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    # Write high-risk parameters first
                    f.write("# HIGH RISK PARAMETERS\n")
                    for param in wordlists.get('high_risk_parameters', []):
                        f.write(f"{param}\n")
                    
                    f.write("\n# HIDDEN FLAGS\n")
                    for param in wordlists.get('hidden_flags', []):
                        f.write(f"{param}\n")
                    
                    f.write("\n# QUERY PARAMETERS\n")
                    for param in wordlists.get('query_parameters', []):
                        f.write(f"{param}\n")
                    
                    f.write("\n# BODY PARAMETERS\n")
                    for param in wordlists.get('body_parameters', []):
                        f.write(f"{param}\n")
                
                logger.info(f"Parameters exported to {output_file}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to export parameters: {e}")
            return False
    
    def export_ffuf(self, scan_results: Dict[str, Any], output_file: str) -> bool:
        """Export comprehensive ffuf commands with ALL discoveries."""
        try:
            target = scan_results.get('target', '')
            if not target.startswith(('http://', 'https://')):
                base_url = f"https://{target}"
            else:
                base_url = target
            
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("#!/bin/bash\n")
                f.write("# JSEye Comprehensive ffuf Commands\n")
                f.write(f"# Target: {target}\n")
                f.write("# Replace WORDLIST with your wordlist path\n")
                f.write("#\n")
                f.write("# Recommended wordlists:\n")
                f.write("# - SecLists: /usr/share/seclists/Discovery/Web-Content/\n")
                f.write("# - JSEye wordlist: wordlist_endpoints.txt (generated)\n")
                f.write("#\n\n")
                
                f.write("WORDLIST=\"wordlist_endpoints.txt\"\n")
                f.write("THREADS=40\n")
                f.write("RATE=100\n\n")
                
                # 1. Basic directory fuzzing
                f.write("# === DIRECTORY FUZZING ===\n")
                f.write(f"echo \"[*] Fuzzing directories on {base_domain}\"\n")
                f.write(f"ffuf -u '{base_domain}/FUZZ' -w $WORDLIST -mc 200,204,301,302,307,401,403,405 -t $THREADS -rate $RATE -o ffuf_dirs.json\n\n")
                
                # 2. File fuzzing with extensions
                f.write("# === FILE FUZZING ===\n")
                f.write(f"echo \"[*] Fuzzing files with extensions\"\n")
                f.write(f"ffuf -u '{base_domain}/FUZZ' -w $WORDLIST -e .js,.json,.xml,.txt,.php,.asp,.aspx,.jsp,.bak,.old,.zip -mc 200,204,301,302,307,401,403 -t $THREADS -rate $RATE -o ffuf_files.json\n\n")
                
                # 3. API endpoint fuzzing
                f.write("# === API ENDPOINT FUZZING ===\n")
                f.write(f"echo \"[*] Fuzzing API endpoints\"\n")
                f.write(f"ffuf -u '{base_domain}/api/FUZZ' -w $WORDLIST -mc 200,204,301,302,307,401,403,405 -t $THREADS -rate $RATE -o ffuf_api.json\n")
                f.write(f"ffuf -u '{base_domain}/v1/FUZZ' -w $WORDLIST -mc 200,204,301,302,307,401,403,405 -t $THREADS -rate $RATE -o ffuf_v1.json\n")
                f.write(f"ffuf -u '{base_domain}/api/v1/FUZZ' -w $WORDLIST -mc 200,204,301,302,307,401,403,405 -t $THREADS -rate $RATE -o ffuf_api_v1.json\n\n")
                
                # 4. Parameter fuzzing
                f.write("# === PARAMETER FUZZING ===\n")
                f.write(f"echo \"[*] Fuzzing GET parameters\"\n")
                f.write(f"ffuf -u '{base_domain}/?FUZZ=test' -w $WORDLIST -mc 200,204,301,302,307,401,403,500 -t $THREADS -rate $RATE -o ffuf_params.json\n\n")
                
                # 5. Discovered endpoints fuzzing
                linkfinder_endpoints = scan_results.get('linkfinder_endpoints', [])
                if linkfinder_endpoints:
                    f.write("# === DISCOVERED ENDPOINTS FUZZING ===\n")
                    f.write(f"echo \"[*] Fuzzing discovered endpoints\"\n")
                    
                    seen_paths = set()
                    for endpoint in linkfinder_endpoints[:20]:  # Top 20
                        if isinstance(endpoint, dict):
                            ep_url = endpoint.get('endpoint', '')
                            if ep_url and ep_url.startswith('/'):
                                # Get directory path
                                if '/' in ep_url[1:]:
                                    dir_path = ep_url.rsplit('/', 1)[0]
                                    if dir_path not in seen_paths:
                                        seen_paths.add(dir_path)
                                        f.write(f"ffuf -u '{base_domain}{dir_path}/FUZZ' -w $WORDLIST -mc 200,204,301,302,307,401,403 -t $THREADS -rate $RATE\n")
                    f.write("\n")
                
                # 6. API endpoints from detection
                api_endpoints = scan_results.get('api_endpoints', [])
                if api_endpoints:
                    f.write("# === API ENDPOINTS FROM DETECTION ===\n")
                    f.write(f"echo \"[*] Testing detected API endpoints\"\n")
                    
                    for api_ep in api_endpoints[:15]:  # Top 15
                        if isinstance(api_ep, dict):
                            ep = api_ep.get('endpoint', '')
                            method = api_ep.get('method', 'GET')
                            if ep and ep.startswith('/'):
                                if method == 'GET':
                                    f.write(f"ffuf -u '{base_domain}{ep}' -w $WORDLIST -mc 200,204,301,302,307,401,403 -t $THREADS -rate $RATE\n")
                                else:
                                    f.write(f"ffuf -u '{base_domain}{ep}' -w $WORDLIST -X {method} -mc 200,204,301,302,307,401,403 -t $THREADS -rate $RATE\n")
                    f.write("\n")
                
                # 7. Admin/sensitive paths
                f.write("# === ADMIN & SENSITIVE PATHS ===\n")
                f.write(f"echo \"[*] Fuzzing admin and sensitive paths\"\n")
                sensitive_paths = ['/admin', '/administrator', '/panel', '/dashboard', '/console', '/manage']
                for path in sensitive_paths:
                    f.write(f"ffuf -u '{base_domain}{path}/FUZZ' -w $WORDLIST -mc 200,204,301,302,307,401,403 -t $THREADS -rate $RATE\n")
                f.write("\n")
                
                # 8. Backup/config files
                f.write("# === BACKUP & CONFIG FILES ===\n")
                f.write(f"echo \"[*] Searching for backup and config files\"\n")
                f.write(f"ffuf -u '{base_domain}/FUZZ' -w $WORDLIST -e .bak,.old,.backup,.zip,.tar,.tar.gz,.sql,.db,.config,.conf,.env -mc 200,204,301,302,307,401,403 -t $THREADS -rate $RATE -o ffuf_backups.json\n\n")
                
                # 9. Source maps
                f.write("# === SOURCE MAPS ===\n")
                f.write(f"echo \"[*] Searching for source maps\"\n")
                f.write(f"ffuf -u '{base_domain}/FUZZ.js.map' -w $WORDLIST -mc 200,204 -t $THREADS -rate $RATE -o ffuf_sourcemaps.json\n\n")
                
                f.write("echo \"[+] ffuf fuzzing complete! Check output files for results.\"\n")
            
            # Make executable
            import os
            os.chmod(output_file, 0o755)
            
            logger.info(f"Comprehensive ffuf commands exported to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export ffuf commands: {e}")
            return False
    
    def export_curl_commands(self, scan_results: Dict[str, Any], output_file: str) -> bool:
        """Export comprehensive cURL commands for ALL discoveries."""
        try:
            target = scan_results.get('target', '')
            if not target.startswith(('http://', 'https://')):
                base_url = f"https://{target}"
            else:
                base_url = target
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("#!/bin/bash\n")
                f.write("# JSEye Comprehensive cURL Test Commands\n")
                f.write(f"# Target: {target}\n")
                f.write("# Generated by JSEye v3.0.1\n")
                f.write("#\n")
                f.write("# Usage: bash this_file.sh\n")
                f.write("#\n\n")
                
                f.write("# Colors for output\n")
                f.write("RED='\\033[0;31m'\n")
                f.write("GREEN='\\033[0;32m'\n")
                f.write("YELLOW='\\033[1;33m'\n")
                f.write("NC='\\033[0m' # No Color\n\n")
                
                # 1. Base URL test
                f.write("# === BASE URL TEST ===\n")
                f.write(f"echo -e \"${{YELLOW}}[*] Testing base URL${{NC}}\"\n")
                f.write(f"curl -X GET '{base_url}' -H 'User-Agent: JSEye/3.0.1' -H 'Accept: */*' -i -s -o /dev/null -w \"Status: %{{http_code}} | Size: %{{size_download}} bytes\\n\"\n\n")
                
                # 2. API endpoints from detection
                api_endpoints = scan_results.get('api_endpoints', [])
                if api_endpoints:
                    f.write("# === DETECTED API ENDPOINTS ===\n")
                    f.write(f"echo -e \"${{YELLOW}}[*] Testing {len(api_endpoints)} detected API endpoints${{NC}}\"\n\n")
                    
                    for idx, api_ep in enumerate(api_endpoints[:30], 1):  # Top 30
                        if isinstance(api_ep, dict):
                            ep = api_ep.get('endpoint', '')
                            method = api_ep.get('method', 'GET')
                            classification = api_ep.get('classification', 'API')
                            
                            if ep:
                                if ep.startswith('http'):
                                    full_url = ep
                                elif ep.startswith('/'):
                                    full_url = f"{base_url}{ep}"
                                else:
                                    continue
                                
                                f.write(f"# {idx}. {classification}: {ep}\n")
                                if method == 'GET':
                                    f.write(f"curl -X GET '{full_url}' -H 'User-Agent: JSEye/3.0.1' -H 'Accept: application/json' -i -s\n\n")
                                elif method == 'POST':
                                    f.write(f"curl -X POST '{full_url}' -H 'User-Agent: JSEye/3.0.1' -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{{}}' -i -s\n\n")
                                else:
                                    f.write(f"curl -X {method} '{full_url}' -H 'User-Agent: JSEye/3.0.1' -H 'Accept: application/json' -i -s\n\n")
                
                # 3. LinkFinder endpoints
                linkfinder_endpoints = scan_results.get('linkfinder_endpoints', [])
                if linkfinder_endpoints:
                    f.write("# === LINKFINDER DISCOVERED ENDPOINTS ===\n")
                    f.write(f"echo -e \"${{YELLOW}}[*] Testing {len(linkfinder_endpoints)} LinkFinder endpoints${{NC}}\"\n\n")
                    
                    for idx, endpoint in enumerate(linkfinder_endpoints[:30], 1):  # Top 30
                        if isinstance(endpoint, dict):
                            ep_url = endpoint.get('endpoint', '')
                            ep_type = endpoint.get('type', 'unknown')
                            
                            if ep_url:
                                if ep_url.startswith('http'):
                                    full_url = ep_url
                                elif ep_url.startswith('/'):
                                    full_url = f"{base_url}{ep_url}"
                                else:
                                    continue
                                
                                f.write(f"# {idx}. Type: {ep_type} - {ep_url}\n")
                                f.write(f"curl -X GET '{full_url}' -H 'User-Agent: JSEye/3.0.1' -i -s -o /dev/null -w \"Status: %{{http_code}}\\n\"\n\n")
                
                # 4. Common API paths
                f.write("# === COMMON API PATHS ===\n")
                f.write(f"echo -e \"${{YELLOW}}[*] Testing common API paths${{NC}}\"\n\n")
                
                common_paths = [
                    '/api', '/api/v1', '/api/v2', '/api/v3',
                    '/graphql', '/graphiql',
                    '/swagger', '/swagger-ui', '/swagger.json',
                    '/api/docs', '/api/documentation',
                    '/admin', '/admin/api',
                    '/v1', '/v2', '/v3'
                ]
                
                for path in common_paths:
                    f.write(f"curl -X GET '{base_url}{path}' -H 'User-Agent: JSEye/3.0.1' -i -s -o /dev/null -w \"{path}: %{{http_code}}\\n\"\n")
                f.write("\n")
                
                # 5. API key testing (if found)
                api_key_findings = scan_results.get('api_key_findings', [])
                if api_key_findings:
                    f.write("# === API KEY TESTING ===\n")
                    f.write(f"echo -e \"${{RED}}[!] WARNING: {len(api_key_findings)} API keys found in URLs${{NC}}\"\n")
                    f.write(f"echo -e \"${{YELLOW}}[*] Test these manually - keys may be valid${{NC}}\"\n\n")
                    
                    for idx, finding in enumerate(api_key_findings[:10], 1):  # Top 10
                        if isinstance(finding, dict):
                            param = finding.get('parameter', '')
                            value = finding.get('value', '')[:50]  # First 50 chars
                            url = finding.get('url', '')
                            
                            f.write(f"# {idx}. Parameter: {param}\n")
                            f.write(f"# Value: {value}...\n")
                            f.write(f"# URL: {url}\n")
                            f.write(f"# curl -X GET '{url}' -H 'User-Agent: JSEye/3.0.1' -i -s\n\n")
                
                # 6. Source maps
                sourcemaps = [f for f in scan_results.get('js_files', []) if f.get('type') == 'sourcemap']
                if sourcemaps:
                    f.write("# === SOURCE MAPS ===\n")
                    f.write(f"echo -e \"${{GREEN}}[+] {len(sourcemaps)} source maps found${{NC}}\"\n\n")
                    
                    for idx, smap in enumerate(sourcemaps[:10], 1):
                        url = smap.get('url', '')
                        if url:
                            f.write(f"# {idx}. {url}\n")
                            f.write(f"curl -X GET '{url}' -H 'User-Agent: JSEye/3.0.1' -o sourcemap_{idx}.map -s\n\n")
                
                f.write("echo -e \"${{GREEN}}[+] cURL testing complete!${{NC}}\"\n")
            
            # Make executable
            import os
            os.chmod(output_file, 0o755)
            
            logger.info(f"Comprehensive cURL commands exported to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export cURL commands: {e}")
            return False
    
    def export_burp(self, scan_results: Dict[str, Any], output_file: str) -> bool:
        """Export Burp Suite compatible site map XML."""
        try:
            # Create XML structure
            root = ET.Element('items', burpVersion='2023.1', exportTime=str(int(__import__('time').time())))
            
            urls_added = set()
            
            # Get target base URL
            target = scan_results.get('target', '')
            if target:
                if not target.startswith(('http://', 'https://')):
                    base_url = f"https://{target}"
                else:
                    base_url = target
                
                # Add base URL
                self._add_burp_item(root, base_url, 'GET')
                urls_added.add(base_url)
            
            # Extract from linkfinder endpoints
            linkfinder_endpoints = scan_results.get('linkfinder_endpoints', [])
            for endpoint in linkfinder_endpoints:
                if isinstance(endpoint, dict):
                    ep_url = endpoint.get('endpoint', '')
                    if ep_url:
                        if ep_url.startswith('http'):
                            full_url = ep_url
                        elif ep_url.startswith('/') and base_url:
                            full_url = f"{base_url}{ep_url}"
                        else:
                            continue
                        
                        if full_url not in urls_added:
                            self._add_burp_item(root, full_url, 'GET')
                            urls_added.add(full_url)
            
            # Extract from API endpoints
            api_endpoints = scan_results.get('api_endpoints', [])
            for api_ep in api_endpoints:
                if isinstance(api_ep, dict):
                    ep_url = api_ep.get('endpoint', '')
                    method = api_ep.get('method', 'GET')
                    if ep_url:
                        if ep_url.startswith('http'):
                            full_url = ep_url
                        elif ep_url.startswith('/') and base_url:
                            full_url = f"{base_url}{ep_url}"
                        else:
                            continue
                        
                        if full_url not in urls_added:
                            self._add_burp_item(root, full_url, method)
                            urls_added.add(full_url)
            
            # Write XML
            tree = ET.ElementTree(root)
            ET.indent(tree, space='  ')
            tree.write(output_file, encoding='utf-8', xml_declaration=True)
            
            logger.info(f"Burp site map exported to {output_file}", items=len(urls_added))
            return True
            
        except Exception as e:
            logger.error(f"Failed to export Burp site map: {e}")
            return False
    
    def _add_burp_item(self, root, url: str, method: str = 'GET'):
        """Add an item to Burp XML."""
        try:
            parsed = urlparse(url)
            
            item = ET.SubElement(root, 'item')
            ET.SubElement(item, 'time').text = str(int(__import__('time').time()))
            ET.SubElement(item, 'url').text = url
            
            host_elem = ET.SubElement(item, 'host')
            host_elem.set('ip', '')
            host_elem.text = parsed.netloc
            
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            ET.SubElement(item, 'port').text = str(port)
            ET.SubElement(item, 'protocol').text = parsed.scheme
            ET.SubElement(item, 'method').text = method
            ET.SubElement(item, 'path').text = parsed.path or '/'
            ET.SubElement(item, 'status').text = '200'
            ET.SubElement(item, 'responselength').text = '0'
            ET.SubElement(item, 'mimetype').text = 'JSON' if 'api' in url.lower() else 'HTML'
        except:
            pass
    
    def export_nuclei_template(self, scan_results: Dict[str, Any], output_file: str) -> bool:
        """Export Nuclei template for discovered endpoints."""
        try:
            # Get target
            target = scan_results.get('target', 'example.com')
            if not target.startswith(('http://', 'https://')):
                base_url = f"https://{target}"
            else:
                base_url = target
            
            # Collect endpoints
            endpoints_to_test = []
            
            # From linkfinder
            linkfinder_endpoints = scan_results.get('linkfinder_endpoints', [])
            for endpoint in linkfinder_endpoints[:15]:  # Limit to 15
                if isinstance(endpoint, dict):
                    ep_url = endpoint.get('endpoint', '')
                    if ep_url:
                        if ep_url.startswith('/'):
                            endpoints_to_test.append(ep_url)
                        elif ep_url.startswith('http'):
                            parsed = urlparse(ep_url)
                            endpoints_to_test.append(parsed.path or '/')
            
            # From API endpoints
            api_endpoints = scan_results.get('api_endpoints', [])
            for api_ep in api_endpoints[:15]:  # Limit to 15
                if isinstance(api_ep, dict):
                    ep_url = api_ep.get('endpoint', '')
                    if ep_url and ep_url.startswith('/'):
                        endpoints_to_test.append(ep_url)
            
            # Add default paths if none found
            if not endpoints_to_test:
                endpoints_to_test = [
                    '/',
                    '/api',
                    '/api/v1',
                    '/admin',
                    '/login'
                ]
            
            # Create Nuclei template
            template_content = f"""id: jseye-discovered-endpoints

info:
  name: JSEye Discovered Endpoints - {target}
  author: jseye
  severity: info
  description: Testing endpoints discovered by JSEye for {target}
  tags: jseye,discovery,endpoints

http:
"""
            
            # Add requests
            for endpoint in endpoints_to_test[:20]:  # Limit to 20
                template_content += f"""  - method: GET
    path:
      - "{{{{BaseURL}}}}{endpoint}"
    
    matchers:
      - type: status
        status:
          - 200
          - 201
          - 204
          - 301
          - 302
    
"""
            
            # Write template
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(template_content)
            
            logger.info(f"Nuclei template exported to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export Nuclei template: {e}")
            return False
    
    def _generate_curl_command(self, url: str, method: str = 'GET') -> str:
        """Generate a cURL command for an endpoint."""
        cmd = f"curl -X {method}"
        
        # Add common headers
        cmd += " -H 'User-Agent: Mozilla/5.0'"
        cmd += " -H 'Accept: application/json, text/plain, */*'"
        
        # Add method-specific options
        if method in ['POST', 'PUT', 'PATCH']:
            cmd += " -H 'Content-Type: application/json'"
            cmd += " -d '{}'"
        
        # Add URL
        cmd += f" '{url}'"
        
        # Add options
        cmd += " -i"  # Include headers
        cmd += " -s"  # Silent mode
        
        return cmd
    
    def export_actionable_json(self, scan_results: Dict[str, Any], output_file: str) -> bool:
        """Export only actionable findings in clean JSON format."""
        try:
            actionable_data = {
                'scan_info': {
                    'target': scan_results.get('target', ''),
                    'scan_time': scan_results.get('scan_metadata', {}).get('start_time', ''),
                    'jseye_version': scan_results.get('scan_metadata', {}).get('jseye_version', '3.0')
                },
                'actionable_findings': {
                    'critical': [],
                    'high_priority': [],
                    'quick_wins': []
                },
                'statistics': {}
            }
            
            # Extract prioritized findings
            if 'prioritized' in scan_results:
                prioritized = scan_results['prioritized']
                
                # Critical findings
                actionable_data['actionable_findings']['critical'] = [
                    self._clean_finding(f) for f in prioritized.get('critical_findings', [])
                    if f.get('actionable', False)
                ]
                
                # High priority
                actionable_data['actionable_findings']['high_priority'] = [
                    self._clean_finding(f) for f in prioritized.get('high_priority', [])
                    if f.get('actionable', False)
                ][:20]  # Limit to top 20
                
                # Quick wins
                if 'actionable_summary' in prioritized:
                    quick_wins = prioritized['actionable_summary'].get('quick_wins', [])
                    actionable_data['actionable_findings']['quick_wins'] = [
                        self._clean_finding(f) for f in quick_wins
                    ]
                
                # Statistics
                if 'actionable_summary' in prioritized:
                    summary = prioritized['actionable_summary']
                    actionable_data['statistics'] = {
                        'total_actionable': summary.get('total_actionable', 0),
                        'critical_count': summary.get('critical_count', 0),
                        'high_priority_count': summary.get('high_priority_count', 0),
                        'attack_vectors': summary.get('attack_vectors', [])
                    }
            
            # Write JSON
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(actionable_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Actionable JSON exported to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export actionable JSON: {e}")
            return False
    
    def _clean_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Clean finding for export (remove unnecessary metadata)."""
        cleaned = {
            'type': finding.get('type', 'unknown'),
            'priority': finding.get('priority_level', finding.get('priority', 'unknown')),
            'score': finding.get('priority_score', 0),
            'confidence': finding.get('confidence_score', 0)
        }
        
        # Add relevant fields based on type
        if 'url' in finding:
            cleaned['url'] = finding['url']
        
        if 'title' in finding:
            cleaned['title'] = finding['title']
        
        if 'description' in finding:
            cleaned['description'] = finding['description']
        
        if 'method' in finding:
            cleaned['method'] = finding['method']
        
        if 'priority_factors' in finding:
            cleaned['factors'] = finding['priority_factors']
        
        if 'evidence' in finding:
            cleaned['evidence'] = finding['evidence']
        
        return cleaned
    
    def export_ffuf_config(self, scan_results: Dict[str, Any], output_file: str) -> bool:
        """Export ffuf-compatible configuration."""
        try:
            endpoints = scan_results.get('endpoints', [])
            
            # Extract base URLs and create ffuf targets
            base_urls = set()
            for endpoint in endpoints:
                if isinstance(endpoint, str):
                    parsed = urlparse(endpoint)
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    base_urls.add(base_url)
            
            # Create ffuf configuration
            config = {
                "targets": list(base_urls),
                "wordlist_paths": [],
                "wordlist_params": [],
                "extensions": [".js", ".json", ".xml", ".txt", ".php", ".asp", ".aspx"],
                "status_codes": "200,204,301,302,307,401,403,405,500",
                "threads": 40,
                "delay": "100ms"
            }
            
            # Extract paths for wordlist
            paths = set()
            parameters = set()
            
            for endpoint in endpoints:
                if isinstance(endpoint, str):
                    parsed = urlparse(endpoint)
                    path_parts = [p for p in parsed.path.split('/') if p and len(p) > 2]
                    paths.update(path_parts)
                    
                    if parsed.query:
                        query_params = parse_qs(parsed.query)
                        parameters.update(query_params.keys())
            
            config["wordlist_paths"] = sorted(list(paths))
            config["wordlist_params"] = sorted(list(parameters))
            
            # Write JSON config
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            
            # Also create a simple ffuf command file
            cmd_file = output_file.replace('.json', '_commands.sh')
            with open(cmd_file, 'w', encoding='utf-8') as f:
                f.write("#!/bin/bash\n")
                f.write("# JSEye Generated ffuf Commands\n\n")
                
                for base_url in base_urls:
                    f.write(f"# Fuzzing {base_url}\n")
                    f.write(f"ffuf -u {base_url}/FUZZ -w /path/to/wordlist.txt -mc 200,204,301,302,307,401,403,405 -t 40\n")
                    f.write(f"ffuf -u {base_url}/FUZZ -w /path/to/wordlist.txt -e .js,.json,.xml,.txt,.php -mc 200,204,301,302,307,401,403,405 -t 40\n\n")
            
            logger.info(f"ffuf configuration exported to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export ffuf config: {e}")
            return False
    
    def export_burp_config(self, scan_results: Dict[str, Any], output_file: str) -> bool:
        """Export Burp Suite compatible configuration."""
        try:
            endpoints = scan_results.get('endpoints', [])
            
            # Create Burp Suite site map XML
            root = ET.Element("items")
            root.set("burpVersion", "2023.10.3.4")
            root.set("exportTime", "JSEye Export")
            
            for endpoint in endpoints:
                if isinstance(endpoint, str):
                    item = ET.SubElement(root, "item")
                    
                    # Parse URL
                    parsed = urlparse(endpoint)
                    
                    # Add URL components
                    ET.SubElement(item, "url").text = endpoint
                    ET.SubElement(item, "host").text = parsed.netloc
                    ET.SubElement(item, "port").text = str(parsed.port or (443 if parsed.scheme == 'https' else 80))
                    ET.SubElement(item, "protocol").text = parsed.scheme
                    ET.SubElement(item, "path").text = parsed.path
                    ET.SubElement(item, "extension").text = self._get_file_extension(parsed.path)
                    
                    # Add request
                    request = ET.SubElement(item, "request")
                    request.set("base64", "false")
                    request.text = f"GET {parsed.path} HTTP/1.1\nHost: {parsed.netloc}\nUser-Agent: JSEye/2.0.2\n\n"
                    
                    # Add response placeholder
                    response = ET.SubElement(item, "response")
                    response.set("base64", "false")
                    response.text = "HTTP/1.1 200 OK\nContent-Type: application/javascript\n\n"
            
            # Write XML
            tree = ET.ElementTree(root)
            tree.write(output_file, encoding='utf-8', xml_declaration=True)
            
            logger.info(f"Burp Suite configuration exported to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export Burp config: {e}")
            return False
    
    def export_csv(self, scan_results: Dict[str, Any], output_file: str) -> bool:
        """Export comprehensive CSV report."""
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                # Endpoints CSV
                endpoints_file = output_file.replace('.csv', '_endpoints.csv')
                self._export_endpoints_csv(scan_results, endpoints_file)
                
                # Secrets CSV
                secrets_file = output_file.replace('.csv', '_secrets.csv')
                self._export_secrets_csv(scan_results, secrets_file)
                
                # Vulnerabilities CSV
                vulns_file = output_file.replace('.csv', '_vulnerabilities.csv')
                self._export_vulnerabilities_csv(scan_results, vulns_file)
                
                # Summary CSV
                writer = csv.writer(csvfile)
                writer.writerow(['Metric', 'Value'])
                
                stats = scan_results.get('statistics', {})
                writer.writerow(['Target', scan_results.get('target', 'Unknown')])
                writer.writerow(['Total JS Files', stats.get('total_js_files', 0)])
                writer.writerow(['Total Secrets', stats.get('total_secrets', 0)])
                writer.writerow(['Total Endpoints', stats.get('total_endpoints', 0)])
                writer.writerow(['Total Vulnerabilities', len(scan_results.get('vulnerabilities', []))])
                
                risk_dist = stats.get('risk_distribution', {})
                writer.writerow(['Critical Risks', risk_dist.get('Critical', 0)])
                writer.writerow(['High Risks', risk_dist.get('High', 0)])
                writer.writerow(['Medium Risks', risk_dist.get('Medium', 0)])
                writer.writerow(['Low Risks', risk_dist.get('Low', 0)])
            
            logger.info(f"CSV reports exported to {output_file} and related files")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export CSV: {e}")
            return False
    
    def _export_endpoints_csv(self, scan_results: Dict[str, Any], output_file: str) -> None:
        """Export endpoints to CSV."""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['URL', 'Method', 'Status', 'Content-Type', 'Auth Required', 'CORS Enabled'])
            
            api_analysis = scan_results.get('api_analysis', [])
            for api in api_analysis:
                if isinstance(api, dict):
                    url = api.get('url', '')
                    methods = api.get('methods_supported', ['GET'])
                    auth_required = api.get('authentication_required', False)
                    cors_enabled = api.get('cors_enabled', False)
                    
                    for method in methods:
                        writer.writerow([url, method, 'Unknown', 'Unknown', auth_required, cors_enabled])
    
    def _export_secrets_csv(self, scan_results: Dict[str, Any], output_file: str) -> None:
        """Export secrets to CSV."""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Type', 'Description', 'Severity', 'Risk Level', 'Confidence', 'Source File', 'Masked Value'])
            
            secrets = scan_results.get('secrets', [])
            for secret in secrets:
                writer.writerow([
                    secret.get('type', ''),
                    secret.get('description', ''),
                    secret.get('severity', ''),
                    secret.get('risk_level', ''),
                    secret.get('confidence', 0),
                    secret.get('source_file', ''),
                    secret.get('value_masked', '')
                ])
    
    def _export_vulnerabilities_csv(self, scan_results: Dict[str, Any], output_file: str) -> None:
        """Export vulnerabilities to CSV."""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Type', 'Severity', 'Count', 'Description', 'Recommendation'])
            
            vulnerabilities = scan_results.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.get('type', ''),
                    vuln.get('severity', ''),
                    vuln.get('count', 1),
                    vuln.get('description', ''),
                    vuln.get('recommendation', '')
                ])
    
    def _generate_curl_command(self, url: str, method: str = 'GET') -> str:
        """Generate a cURL command for an endpoint."""
        cmd = f"curl -X {method}"
        cmd += " -H 'User-Agent: JSEye/2.0.2'"
        cmd += " -H 'Accept: application/json, text/javascript, */*'"
        
        if method in ['POST', 'PUT', 'PATCH']:
            cmd += " -H 'Content-Type: application/json'"
            cmd += " -d '{}'"
        
        cmd += f" '{url}'"
        
        return cmd
    
    def _get_file_extension(self, path: str) -> str:
        """Get file extension from path."""
        if '.' in path:
            return path.split('.')[-1]
        return ""
    
    def export_parameter_wordlist(self, scan_results: Dict[str, Any], output_file: str) -> bool:
        """Export parameter names as wordlist."""
        try:
            parameters = set()
            
            # Extract from API analysis
            api_analysis = scan_results.get('api_analysis', [])
            for api in api_analysis:
                if isinstance(api, dict):
                    api_params = api.get('parameters', [])
                    for param in api_params:
                        if isinstance(param, dict):
                            param_name = param.get('name', '')
                            if param_name and len(param_name) > 1:
                                parameters.add(param_name)
            
            # Extract from endpoints
            endpoints = scan_results.get('endpoints', [])
            for endpoint in endpoints:
                if isinstance(endpoint, str):
                    parsed = urlparse(endpoint)
                    if parsed.query:
                        query_params = parse_qs(parsed.query)
                        parameters.update(query_params.keys())
            
            # Write parameter wordlist
            with open(output_file, 'w', encoding='utf-8') as f:
                for param in sorted(parameters):
                    f.write(f"{param}\n")
            
            logger.info(f"Parameter wordlist exported to {output_file}", count=len(parameters))
            return True
            
        except Exception as e:
            logger.error(f"Failed to export parameter wordlist: {e}")
            return False