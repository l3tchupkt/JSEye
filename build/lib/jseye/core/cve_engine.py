"""CVE intelligence engine using free APIs for library vulnerability detection."""

import asyncio
import aiohttp
import re
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from .logging import get_logger
from .exceptions import JSEyeNetworkError

logger = get_logger(__name__)


@dataclass
class LibraryInfo:
    """Information about a detected JavaScript library."""
    name: str
    version: str
    confidence: float
    detection_method: str
    file_url: str
    line_number: Optional[int] = None


@dataclass
class CVEInfo:
    """Information about a CVE vulnerability."""
    id: str
    severity: str
    summary: str
    references: List[str]
    published_date: str
    modified_date: str
    cvss_score: Optional[float] = None


@dataclass
class LibraryVulnerability:
    """Represents a vulnerable library with its CVEs."""
    library: LibraryInfo
    cves: List[CVEInfo]
    risk_boost: int
    total_cvss_score: float


class CVEIntelligenceEngine:
    """CVE intelligence engine using free APIs."""
    
    def __init__(self, timeout: int = 30):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session = None
        self.cve_cache = {}  # In-memory cache for scan duration
        
        # Library detection patterns
        self.library_patterns = {
            'jquery': [
                (r'jQuery\s+v?(\d+\.\d+\.\d+)', 'version_comment'),
                (r'jquery[/-](\d+\.\d+\.\d+)', 'filename'),
                (r'jQuery\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)["\']', 'property'),
                (r'/\*!\s*jQuery\s+v(\d+\.\d+\.\d+)', 'header_comment'),
            ],
            'lodash': [
                (r'lodash\s+(\d+\.\d+\.\d+)', 'version_comment'),
                (r'lodash[/-](\d+\.\d+\.\d+)', 'filename'),
                (r'VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']', 'property'),
            ],
            'react': [
                (r'React\s+(\d+\.\d+\.\d+)', 'version_comment'),
                (r'react[/-](\d+\.\d+\.\d+)', 'filename'),
                (r'React\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']', 'property'),
            ],
            'angular': [
                (r'AngularJS\s+v(\d+\.\d+\.\d+)', 'version_comment'),
                (r'angular[/-](\d+\.\d+\.\d+)', 'filename'),
                (r'angular\.version\s*=\s*\{\s*full:\s*["\'](\d+\.\d+\.\d+)["\']', 'property'),
            ],
            'vue': [
                (r'Vue\.js\s+v(\d+\.\d+\.\d+)', 'version_comment'),
                (r'vue[/-](\d+\.\d+\.\d+)', 'filename'),
                (r'Vue\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']', 'property'),
            ],
            'bootstrap': [
                (r'Bootstrap\s+v(\d+\.\d+\.\d+)', 'version_comment'),
                (r'bootstrap[/-](\d+\.\d+\.\d+)', 'filename'),
            ],
            'moment': [
                (r'Moment\.js\s+(\d+\.\d+\.\d+)', 'version_comment'),
                (r'moment[/-](\d+\.\d+\.\d+)', 'filename'),
                (r'moment\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']', 'property'),
            ],
            'axios': [
                (r'axios\s+(\d+\.\d+\.\d+)', 'version_comment'),
                (r'axios[/-](\d+\.\d+\.\d+)', 'filename'),
            ],
            'd3': [
                (r'D3\.js\s+(\d+\.\d+\.\d+)', 'version_comment'),
                (r'd3[/-](\d+\.\d+\.\d+)', 'filename'),
                (r'd3\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']', 'property'),
            ],
            'underscore': [
                (r'Underscore\.js\s+(\d+\.\d+\.\d+)', 'version_comment'),
                (r'underscore[/-](\d+\.\d+\.\d+)', 'filename'),
                (r'_\.VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']', 'property'),
            ]
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(limit=10)
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers={
                'User-Agent': 'JSEye/2.0.2 Security Scanner'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def analyze_libraries_and_cves(self, js_files: List[Dict[str, Any]]) -> List[LibraryVulnerability]:
        """Analyze JavaScript files for libraries and their CVEs."""
        try:
            # Detect libraries
            detected_libraries = await self._detect_libraries(js_files)
            
            if not detected_libraries:
                return []
            
            # Get CVEs for detected libraries
            vulnerabilities = []
            
            # Process libraries in batches to avoid overwhelming APIs
            batch_size = 5
            for i in range(0, len(detected_libraries), batch_size):
                batch = detected_libraries[i:i + batch_size]
                
                batch_tasks = []
                for library in batch:
                    task = self._get_library_cves(library)
                    batch_tasks.append(task)
                
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, LibraryVulnerability):
                        vulnerabilities.append(result)
                    elif isinstance(result, Exception):
                        logger.warning(f"CVE lookup failed: {result}")
                
                # Small delay between batches
                await asyncio.sleep(1)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Library and CVE analysis failed: {e}")
            return []
    
    async def _detect_libraries(self, js_files: List[Dict[str, Any]]) -> List[LibraryInfo]:
        """Detect JavaScript libraries in the provided files."""
        detected_libraries = []
        
        for js_file in js_files:
            content = js_file.get('content', '')
            file_url = js_file.get('url', '')
            
            if not content:
                continue
            
            # Check filename patterns first
            filename_libraries = self._detect_from_filename(file_url)
            detected_libraries.extend(filename_libraries)
            
            # Check content patterns
            content_libraries = self._detect_from_content(content, file_url)
            detected_libraries.extend(content_libraries)
        
        # Deduplicate libraries
        unique_libraries = self._deduplicate_libraries(detected_libraries)
        
        return unique_libraries
    
    def _detect_from_filename(self, file_url: str) -> List[LibraryInfo]:
        """Detect libraries from filename patterns."""
        libraries = []
        
        for lib_name, patterns in self.library_patterns.items():
            for pattern, method in patterns:
                if method == 'filename':
                    match = re.search(pattern, file_url, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        libraries.append(LibraryInfo(
                            name=lib_name,
                            version=version,
                            confidence=0.9,
                            detection_method='filename',
                            file_url=file_url
                        ))
        
        return libraries
    
    def _detect_from_content(self, content: str, file_url: str) -> List[LibraryInfo]:
        """Detect libraries from content analysis."""
        libraries = []
        lines = content.split('\n')
        
        for lib_name, patterns in self.library_patterns.items():
            for pattern, method in patterns:
                if method in ['version_comment', 'property', 'header_comment']:
                    for line_num, line in enumerate(lines, 1):
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                            confidence = 0.95 if method == 'header_comment' else 0.8
                            
                            libraries.append(LibraryInfo(
                                name=lib_name,
                                version=version,
                                confidence=confidence,
                                detection_method=method,
                                file_url=file_url,
                                line_number=line_num
                            ))
                            break  # Only first match per library per file
        
        return libraries
    
    def _deduplicate_libraries(self, libraries: List[LibraryInfo]) -> List[LibraryInfo]:
        """Remove duplicate library detections."""
        seen = {}
        unique_libraries = []
        
        for lib in libraries:
            key = f"{lib.name}:{lib.version}"
            
            if key not in seen or lib.confidence > seen[key].confidence:
                seen[key] = lib
        
        return list(seen.values())
    
    async def _get_library_cves(self, library: LibraryInfo) -> Optional[LibraryVulnerability]:
        """Get CVEs for a specific library using free APIs."""
        try:
            # Try OSV.dev API first (primary)
            cves = await self._query_osv_api(library)
            
            if not cves:
                # Fallback to MITRE CVE API
                cves = await self._query_mitre_api(library)
            
            if cves:
                # Calculate risk boost and total CVSS score
                risk_boost = self._calculate_risk_boost(cves)
                total_cvss = sum(cve.cvss_score or 0 for cve in cves)
                
                return LibraryVulnerability(
                    library=library,
                    cves=cves,
                    risk_boost=risk_boost,
                    total_cvss_score=total_cvss
                )
            
            return None
            
        except Exception as e:
            logger.warning(f"CVE lookup failed for {library.name} {library.version}: {e}")
            return None
    
    async def _query_osv_api(self, library: LibraryInfo) -> List[CVEInfo]:
        """Query OSV.dev API for vulnerabilities."""
        cache_key = f"osv:{library.name}:{library.version}"
        
        if cache_key in self.cve_cache:
            return self.cve_cache[cache_key]
        
        try:
            # OSV.dev query format
            query_data = {
                "package": {
                    "name": library.name,
                    "ecosystem": "npm"  # Most JS libraries are on npm
                },
                "version": library.version
            }
            
            url = "https://api.osv.dev/v1/query"
            
            async with self.session.post(url, json=query_data) as response:
                if response.status == 200:
                    data = await response.json()
                    cves = self._parse_osv_response(data)
                    self.cve_cache[cache_key] = cves
                    return cves
                else:
                    logger.debug(f"OSV API returned status {response.status} for {library.name}")
                    return []
                    
        except Exception as e:
            logger.debug(f"OSV API query failed for {library.name}: {e}")
            return []
    
    def _parse_osv_response(self, data: Dict[str, Any]) -> List[CVEInfo]:
        """Parse OSV.dev API response."""
        cves = []
        
        vulnerabilities = data.get('vulns', [])
        
        for vuln in vulnerabilities:
            # Extract CVE ID
            cve_id = None
            aliases = vuln.get('aliases', [])
            for alias in aliases:
                if alias.startswith('CVE-'):
                    cve_id = alias
                    break
            
            if not cve_id:
                cve_id = vuln.get('id', 'Unknown')
            
            # Extract severity and CVSS score
            severity = 'medium'  # default
            cvss_score = None
            
            severity_info = vuln.get('severity', [])
            if severity_info:
                for sev in severity_info:
                    if sev.get('type') == 'CVSS_V3':
                        cvss_score = float(sev.get('score', 0))
                        if cvss_score >= 9.0:
                            severity = 'critical'
                        elif cvss_score >= 7.0:
                            severity = 'high'
                        elif cvss_score >= 4.0:
                            severity = 'medium'
                        else:
                            severity = 'low'
                        break
            
            # Extract summary
            summary = vuln.get('summary', 'No summary available')
            
            # Extract references
            references = []
            refs = vuln.get('references', [])
            for ref in refs:
                if isinstance(ref, dict):
                    url = ref.get('url')
                    if url:
                        references.append(url)
                elif isinstance(ref, str):
                    references.append(ref)
            
            # Extract dates
            published = vuln.get('published', '')
            modified = vuln.get('modified', '')
            
            cves.append(CVEInfo(
                id=cve_id,
                severity=severity,
                summary=summary,
                references=references,
                published_date=published,
                modified_date=modified,
                cvss_score=cvss_score
            ))
        
        return cves
    
    async def _query_mitre_api(self, library: LibraryInfo) -> List[CVEInfo]:
        """Query MITRE CVE API as fallback."""
        cache_key = f"mitre:{library.name}:{library.version}"
        
        if cache_key in self.cve_cache:
            return self.cve_cache[cache_key]
        
        try:
            # Search for CVEs mentioning the library
            search_terms = [library.name, f"{library.name} {library.version}"]
            all_cves = []
            
            for term in search_terms:
                url = f"https://cveawg.mitre.org/api/cve?keyword={term}"
                
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        cves = self._parse_mitre_response(data, library)
                        all_cves.extend(cves)
                    
                # Small delay between requests
                await asyncio.sleep(0.5)
            
            # Deduplicate CVEs
            unique_cves = self._deduplicate_cves(all_cves)
            self.cve_cache[cache_key] = unique_cves
            return unique_cves
            
        except Exception as e:
            logger.debug(f"MITRE API query failed for {library.name}: {e}")
            return []
    
    def _parse_mitre_response(self, data: Dict[str, Any], library: LibraryInfo) -> List[CVEInfo]:
        """Parse MITRE CVE API response."""
        cves = []
        
        cve_items = data.get('cveItems', [])
        
        for item in cve_items:
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('CVE_data_meta', {}).get('ID', 'Unknown')
            
            # Check if CVE is relevant to the library
            description = cve_data.get('description', {}).get('description_data', [])
            desc_text = ''
            if description:
                desc_text = description[0].get('value', '')
            
            if library.name.lower() not in desc_text.lower():
                continue  # Skip irrelevant CVEs
            
            # Extract severity (simplified)
            severity = 'medium'  # default
            cvss_score = None
            
            impact = item.get('impact', {})
            if 'baseMetricV3' in impact:
                cvss_v3 = impact['baseMetricV3'].get('cvssV3', {})
                cvss_score = cvss_v3.get('baseScore')
                if cvss_score:
                    if cvss_score >= 9.0:
                        severity = 'critical'
                    elif cvss_score >= 7.0:
                        severity = 'high'
                    elif cvss_score >= 4.0:
                        severity = 'medium'
                    else:
                        severity = 'low'
            
            # Extract dates
            published = item.get('publishedDate', '')
            modified = item.get('lastModifiedDate', '')
            
            # Extract references
            references = []
            ref_data = cve_data.get('references', {}).get('reference_data', [])
            for ref in ref_data:
                url = ref.get('url')
                if url:
                    references.append(url)
            
            cves.append(CVEInfo(
                id=cve_id,
                severity=severity,
                summary=desc_text[:200] + '...' if len(desc_text) > 200 else desc_text,
                references=references,
                published_date=published,
                modified_date=modified,
                cvss_score=cvss_score
            ))
        
        return cves
    
    def _deduplicate_cves(self, cves: List[CVEInfo]) -> List[CVEInfo]:
        """Remove duplicate CVEs."""
        seen = set()
        unique_cves = []
        
        for cve in cves:
            if cve.id not in seen:
                seen.add(cve.id)
                unique_cves.append(cve)
        
        return unique_cves
    
    def _calculate_risk_boost(self, cves: List[CVEInfo]) -> int:
        """Calculate risk boost based on CVE severity."""
        if not cves:
            return 0
        
        risk_boost = 0
        
        for cve in cves:
            if cve.severity == 'critical':
                risk_boost += 25
            elif cve.severity == 'high':
                risk_boost += 15
            elif cve.severity == 'medium':
                risk_boost += 8
            elif cve.severity == 'low':
                risk_boost += 3
        
        return min(risk_boost, 50)  # Cap at 50 points