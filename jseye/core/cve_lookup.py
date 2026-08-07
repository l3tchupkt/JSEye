"""
CVE Lookup System using Free APIs
Queries multiple CVE databases for vulnerability information
"""

import asyncio
import aiohttp
import json
from typing import List, Dict, Any, Optional
from urllib.parse import quote


class CVELookup:
    """Lookup CVEs for libraries using free APIs."""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        
        # Free CVE APIs
        self.apis = {
            'osv': 'https://api.osv.dev/v1/query',
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'cvedetails': 'https://www.cvedetails.com/json-feed.php',
        }
    
    async def lookup_cves(self, library: str, version: str) -> Dict[str, Any]:
        """Lookup CVEs for a specific library and version."""
        results = {
            'library': library,
            'version': version,
            'cves': [],
            'total_cves': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'sources': []
        }
        
        # Try multiple sources
        tasks = [
            self._query_osv(library, version),
            self._query_nvd(library, version),
        ]
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for response in responses:
            if isinstance(response, dict) and response.get('cves'):
                results['cves'].extend(response['cves'])
                results['sources'].append(response.get('source', 'unknown'))
        
        # Deduplicate CVEs
        seen_cves = set()
        unique_cves = []
        for cve in results['cves']:
            cve_id = cve.get('id', '')
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                unique_cves.append(cve)
                
                # Count by severity
                severity = cve.get('severity', 'unknown').lower()
                if severity == 'critical':
                    results['critical'] += 1
                elif severity == 'high':
                    results['high'] += 1
                elif severity == 'medium':
                    results['medium'] += 1
                elif severity == 'low':
                    results['low'] += 1
        
        results['cves'] = unique_cves
        results['total_cves'] = len(unique_cves)
        
        return results
    
    async def _query_osv(self, library: str, version: str) -> Dict[str, Any]:
        """Query OSV (Open Source Vulnerabilities) API."""
        try:
            # OSV uses ecosystem-specific package names
            ecosystems = ['npm', 'PyPI', 'Maven', 'Go', 'RubyGems', 'NuGet']
            
            # Try npm first (most common for JS)
            package_name = library
            
            # Prepare query
            query = {
                "package": {
                    "name": package_name,
                    "ecosystem": "npm"
                },
                "version": version
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.apis['osv'],
                    json=query,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        cves = []
                        if 'vulns' in data:
                            for vuln in data['vulns']:
                                cve = {
                                    'id': vuln.get('id', 'N/A'),
                                    'summary': vuln.get('summary', 'No summary available'),
                                    'severity': self._extract_severity_osv(vuln),
                                    'cvss_score': self._extract_cvss_osv(vuln),
                                    'published': vuln.get('published', 'N/A'),
                                    'modified': vuln.get('modified', 'N/A'),
                                    'references': [ref.get('url') for ref in vuln.get('references', [])],
                                    'source': 'OSV',
                                    'affected_versions': self._extract_affected_versions(vuln)
                                }
                                cves.append(cve)
                        
                        return {
                            'source': 'OSV',
                            'cves': cves
                        }
        except Exception:
            pass
        
        return {'source': 'OSV', 'cves': []}
    
    async def _query_nvd(self, library: str, version: str) -> Dict[str, Any]:
        """Query NVD (National Vulnerability Database) API."""
        try:
            # NVD search by keyword
            keyword = f"{library} {version}"
            url = f"{self.apis['nvd']}?keywordSearch={quote(keyword)}&resultsPerPage=20"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={'User-Agent': 'JSEye/3.0.1'}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        cves = []
                        if 'vulnerabilities' in data:
                            for item in data['vulnerabilities'][:10]:  # Limit to 10
                                vuln = item.get('cve', {})
                                
                                cve = {
                                    'id': vuln.get('id', 'N/A'),
                                    'summary': self._extract_description_nvd(vuln),
                                    'severity': self._extract_severity_nvd(vuln),
                                    'cvss_score': self._extract_cvss_nvd(vuln),
                                    'published': vuln.get('published', 'N/A'),
                                    'modified': vuln.get('lastModified', 'N/A'),
                                    'references': self._extract_references_nvd(vuln),
                                    'source': 'NVD',
                                    'cwe': self._extract_cwe_nvd(vuln)
                                }
                                cves.append(cve)
                        
                        return {
                            'source': 'NVD',
                            'cves': cves
                        }
        except Exception:
            pass
        
        return {'source': 'NVD', 'cves': []}
    
    def _extract_severity_osv(self, vuln: Dict) -> str:
        """Extract severity from OSV vulnerability."""
        if 'severity' in vuln:
            severity_list = vuln['severity']
            if severity_list and len(severity_list) > 0:
                return severity_list[0].get('type', 'UNKNOWN')
        
        # Try to infer from CVSS score
        if 'database_specific' in vuln:
            cvss = vuln['database_specific'].get('cvss', {})
            score = cvss.get('score', 0)
            if score >= 9.0:
                return 'CRITICAL'
            elif score >= 7.0:
                return 'HIGH'
            elif score >= 4.0:
                return 'MEDIUM'
            elif score > 0:
                return 'LOW'
        
        return 'UNKNOWN'
    
    def _extract_cvss_osv(self, vuln: Dict) -> float:
        """Extract CVSS score from OSV vulnerability."""
        if 'database_specific' in vuln:
            cvss = vuln['database_specific'].get('cvss', {})
            return cvss.get('score', 0.0)
        
        if 'severity' in vuln and vuln['severity']:
            for sev in vuln['severity']:
                if 'score' in sev:
                    return float(sev['score'])
        
        return 0.0
    
    def _extract_affected_versions(self, vuln: Dict) -> List[str]:
        """Extract affected versions from OSV vulnerability."""
        versions = []
        if 'affected' in vuln:
            for affected in vuln['affected']:
                if 'versions' in affected:
                    versions.extend(affected['versions'])
        return versions
    
    def _extract_description_nvd(self, vuln: Dict) -> str:
        """Extract description from NVD vulnerability."""
        if 'descriptions' in vuln:
            for desc in vuln['descriptions']:
                if desc.get('lang') == 'en':
                    return desc.get('value', 'No description available')
        return 'No description available'
    
    def _extract_severity_nvd(self, vuln: Dict) -> str:
        """Extract severity from NVD vulnerability."""
        if 'metrics' in vuln:
            metrics = vuln['metrics']
            
            # Try CVSS v3.1
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss = metrics['cvssMetricV31'][0].get('cvssData', {})
                return cvss.get('baseSeverity', 'UNKNOWN')
            
            # Try CVSS v3.0
            if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss = metrics['cvssMetricV30'][0].get('cvssData', {})
                return cvss.get('baseSeverity', 'UNKNOWN')
            
            # Try CVSS v2
            if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss = metrics['cvssMetricV2'][0]
                score = cvss.get('cvssData', {}).get('baseScore', 0)
                if score >= 7.0:
                    return 'HIGH'
                elif score >= 4.0:
                    return 'MEDIUM'
                elif score > 0:
                    return 'LOW'
        
        return 'UNKNOWN'
    
    def _extract_cvss_nvd(self, vuln: Dict) -> float:
        """Extract CVSS score from NVD vulnerability."""
        if 'metrics' in vuln:
            metrics = vuln['metrics']
            
            # Try CVSS v3.1
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss = metrics['cvssMetricV31'][0].get('cvssData', {})
                return cvss.get('baseScore', 0.0)
            
            # Try CVSS v3.0
            if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss = metrics['cvssMetricV30'][0].get('cvssData', {})
                return cvss.get('baseScore', 0.0)
            
            # Try CVSS v2
            if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss = metrics['cvssMetricV2'][0].get('cvssData', {})
                return cvss.get('baseScore', 0.0)
        
        return 0.0
    
    def _extract_references_nvd(self, vuln: Dict) -> List[str]:
        """Extract references from NVD vulnerability."""
        refs = []
        if 'references' in vuln:
            for ref in vuln['references'][:5]:  # Limit to 5
                if 'url' in ref:
                    refs.append(ref['url'])
        return refs
    
    def _extract_cwe_nvd(self, vuln: Dict) -> List[str]:
        """Extract CWE IDs from NVD vulnerability."""
        cwes = []
        if 'weaknesses' in vuln:
            for weakness in vuln['weaknesses']:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwes.append(desc.get('value', ''))
        return cwes
    
    async def batch_lookup(self, libraries: List[Dict[str, str]]) -> Dict[str, Any]:
        """Lookup CVEs for multiple libraries."""
        results = {
            'total_libraries': len(libraries),
            'libraries_with_cves': 0,
            'total_cves': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'vulnerabilities': []
        }
        
        # Lookup CVEs for each library
        tasks = []
        for lib in libraries:
            library_name = lib.get('library', '')
            version = lib.get('version', '')
            if library_name and version:
                tasks.append(self.lookup_cves(library_name, version))
        
        # Execute all lookups concurrently
        cve_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in cve_results:
            if isinstance(result, dict) and result.get('total_cves', 0) > 0:
                results['libraries_with_cves'] += 1
                results['total_cves'] += result['total_cves']
                results['critical'] += result.get('critical', 0)
                results['high'] += result.get('high', 0)
                results['medium'] += result.get('medium', 0)
                results['low'] += result.get('low', 0)
                results['vulnerabilities'].append(result)
        
        return results
