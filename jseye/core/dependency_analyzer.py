"""
Dependency Confusion/Takeover Analyzer
"""

import asyncio
import json
import re
from difflib import SequenceMatcher
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import aiohttp

from .logging import get_logger

logger = get_logger(__name__)

class DependencyAnalyzer:
    PRIVATE_PATTERNS = [r'^@[a-z0-9-]+/', r'-internal$', r'-private$']
    SUSPICIOUS_VERSIONS = [r'^\d+\.\d+\.\d+-dev', r'^0\.0\.']
    
    def __init__(self, timeout=10, max_concurrent=20):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.session = None
        self.npm_cache = {}
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=self.max_concurrent, ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def is_likely_private(self, package_name):
        for pattern in self.PRIVATE_PATTERNS:
            if re.search(pattern, package_name):
                return True, f"Matches pattern: {pattern}"
        return False, ""
    
    def check_version_suspicion(self, version):
        for pattern in self.SUSPICIOUS_VERSIONS:
            if re.search(pattern, version):
                return True, f"Matches pattern: {pattern}"
        return False, ""
    
    def find_typosquatting_candidates(self, package_name, all_packages):
        candidates = []
        for other_package in all_packages:
            if other_package == package_name:
                continue
            similarity = SequenceMatcher(None, package_name.lower(), other_package.lower()).ratio()
            if similarity > 0.8:
                candidates.append({'package': other_package, 'similarity': similarity})
        return candidates
    
    def extract_dependencies(self, package_data):
        deps = {'dependencies': {}, 'devDependencies': {}, 'peerDependencies': {}, 'optionalDependencies': {}}
        data = package_data.get('data', package_data)
        for dep_type in deps:
            if dep_type in data:
                deps[dep_type] = data[dep_type]
        return deps
    
    async def check_npm_registry(self, package_name, retries=3):
        if package_name in self.npm_cache:
            return self.npm_cache[package_name]
        
        delay = 1
        for attempt in range(retries):
            try:
                url = f"https://registry.npmjs.org/{package_name}"
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = {'exists': True, 'name': data.get('name'), 'version': data.get('dist-tags', {}).get('latest')}
                        self.npm_cache[package_name] = result
                        return result
                    elif response.status == 404:
                        result = {'exists': False}
                        self.npm_cache[package_name] = result
                        return result
                    elif response.status == 429:
                        await asyncio.sleep(delay)
                        delay *= 2
                        continue
                    else:
                        result = {'exists': None}
                        self.npm_cache[package_name] = result
                        return result
            except Exception as e:
                if attempt == retries - 1:
                    return {'exists': None, 'error': str(e)}
                await asyncio.sleep(delay)
                delay *= 2
                
        return {'exists': None, 'error': 'Max retries exceeded due to rate limiting'}
    
    async def analyze_dependency(self, name, version, dep_type):
        result = {'name': name, 'version': version, 'type': dep_type, 'vulnerabilities': [], 'risk_score': 0, 'severity': 'INFO'}
        is_private, private_reason = self.is_likely_private(name)
        npm_info = await self.check_npm_registry(name)
        if is_private and npm_info.get('exists'):
            result['vulnerabilities'].append({'type': 'DEPENDENCY_CONFUSION', 'severity': 'CRITICAL', 'description': f"Private package '{name}' exists in public NPM registry"})
            result['risk_score'] += 50
        if not npm_info.get('exists'):
            result['vulnerabilities'].append({'type': 'TAKEOVER_OPPORTUNITY', 'severity': 'HIGH', 'description': f"Package '{name}' not found in NPM registry"})
            result['risk_score'] += 30
        is_suspicious, suspicious_reason = self.check_version_suspicion(version)
        if is_suspicious:
            result['vulnerabilities'].append({'type': 'SUSPICIOUS_VERSION', 'severity': 'MEDIUM', 'description': f"Suspicious version: {version}"})
            result['risk_score'] += 15
        if result['risk_score'] >= 50:
            result['severity'] = 'CRITICAL'
        elif result['risk_score'] >= 30:
            result['severity'] = 'HIGH'
        elif result['risk_score'] >= 15:
            result['severity'] = 'MEDIUM'
        return result
    
    async def analyze_package_json(self, package_data):
        logger.info("Analyzing dependencies...")
        deps = self.extract_dependencies(package_data)
        tasks = []
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def bounded_analyze(name, version, dep_type):
            async with semaphore:
                return await self.analyze_dependency(name, version, dep_type)
        
        for dep_type, packages in deps.items():
            for name, version in packages.items():
                tasks.append(bounded_analyze(name, version, dep_type))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        vulnerable = [r for r in results if isinstance(r, dict) and r.get('vulnerabilities')]
        total_deps = sum(len(packages) for packages in deps.values())
        confusion_risk = sum(1 for v in vulnerable if any(vuln['type'] == 'DEPENDENCY_CONFUSION' for vuln in v['vulnerabilities']))
        takeover_risk = sum(1 for v in vulnerable if any(vuln['type'] == 'TAKEOVER_OPPORTUNITY' for vuln in v['vulnerabilities']))
        critical_count = sum(1 for v in vulnerable if v['severity'] == 'CRITICAL')
        high_count = sum(1 for v in vulnerable if v['severity'] == 'HIGH')
        return {'total_dependencies': total_deps, 'vulnerable_count': len(vulnerable), 'critical_count': critical_count, 'high_count': high_count, 'confusion_risk': confusion_risk, 'takeover_risk': takeover_risk, 'vulnerable_packages': sorted(vulnerable, key=lambda x: x['risk_score'], reverse=True)}
    
    async def discover_package_files(self, base_url, js_files):
        logger.info("Discovering package.json files...")
        package_files = []
        common_paths = ['/package.json', '/package-lock.json', '/yarn.lock']
        tasks = [self._fetch_package_file(urljoin(base_url, path), path) for path in common_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        package_files = [r for r in results if isinstance(r, dict) and r.get('data')]
        logger.info(f"Found {len(package_files)} package files")
        return package_files
    
    async def _fetch_package_file(self, url, source):
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    try:
                        data = json.loads(content)
                        return {'url': url, 'source': source, 'data': data, 'type': 'package.json'}
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass
        return None

    async def discover_and_analyze(self, js_files: List[Any], urls: Any) -> Dict[str, Any]:
        """Discover package manifests and analyze dependencies for risks."""
        close_session = False
        if not self.session:
            connector = aiohttp.TCPConnector(limit=self.max_concurrent, ssl=False)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
            close_session = True

        try:
            base_urls = set()
            if isinstance(urls, (list, set)):
                for u in urls:
                    if isinstance(u, str) and u.startswith(("http://", "https://")):
                        p = urlparse(u)
                        base_urls.add(f"{p.scheme}://{p.netloc}")
            elif isinstance(urls, str) and urls.startswith(("http://", "https://")):
                p = urlparse(urls)
                base_urls.add(f"{p.scheme}://{p.netloc}")

            for js in js_files:
                js_url = js.get("url") if isinstance(js, dict) else (js if isinstance(js, str) else "")
                if js_url and js_url.startswith(("http://", "https://")):
                    p = urlparse(js_url)
                    base_urls.add(f"{p.scheme}://{p.netloc}")

            discovered_manifests = []
            for base in list(base_urls)[:5]:
                pkg_files = await self.discover_package_files(base, js_files)
                discovered_manifests.extend(pkg_files)

            if not discovered_manifests:
                return {
                    "success": False,
                    "message": "No package files found",
                    "statistics": {"total_dependencies": 0, "vulnerable_count": 0},
                    "vulnerable_dependencies": [],
                }

            all_vulnerable_deps = []
            total_dependencies = 0
            critical_count = 0
            high_count = 0
            confusion_risk = 0
            missing_packages = 0

            for manifest in discovered_manifests:
                analysis = await self.analyze_package_json(manifest)
                total_dependencies += analysis.get("total_dependencies", 0)
                critical_count += analysis.get("critical_count", 0)
                high_count += analysis.get("high_count", 0)
                confusion_risk += analysis.get("confusion_risk", 0)
                missing_packages += analysis.get("takeover_risk", 0)

                for pkg in analysis.get("vulnerable_packages", []):
                    risk_factors = [v.get("description", "") for v in pkg.get("vulnerabilities", [])]
                    all_vulnerable_deps.append({
                        "name": pkg.get("name"),
                        "version": pkg.get("version"),
                        "severity": pkg.get("severity", "MEDIUM"),
                        "risk_score": pkg.get("risk_score", 0),
                        "risk_factors": risk_factors,
                        "vulnerabilities": pkg.get("vulnerabilities", []),
                        "source_file": manifest.get("url", ""),
                    })

            return {
                "success": True,
                "manifests_analyzed": len(discovered_manifests),
                "statistics": {
                    "total_dependencies": total_dependencies,
                    "vulnerable_count": len(all_vulnerable_deps),
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "confusion_risk": confusion_risk,
                    "missing_packages": missing_packages,
                },
                "vulnerable_dependencies": all_vulnerable_deps,
            }
        finally:
            if close_session and self.session:
                await self.session.close()
                self.session = None
