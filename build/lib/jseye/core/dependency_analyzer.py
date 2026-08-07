"""
Dependency Confusion/Takeover Analyzer
"""

import re
import json
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin
from difflib import SequenceMatcher
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
        for dep_type in deps.keys():
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
        if npm_info.get('exists') == False:
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
