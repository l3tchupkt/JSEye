"""
Dynamic Version Detection for JavaScript Libraries and Frameworks
Detects versions from multiple sources using dynamic patterns
"""

import re
import json
from typing import List, Dict, Any, Set


class VersionDetector:
    """Dynamically detect versions of JavaScript libraries and frameworks."""
    
    def __init__(self):
        # Dynamic patterns that work for ANY library
        self.generic_version_patterns = [
            # Library.VERSION or Library.version
            r'([a-zA-Z0-9_$]+)\.(?:VERSION|version)\s*=\s*["\']([0-9.]+)["\']',
            
            # Library v1.2.3 in comments
            r'/\*!?\s*([a-zA-Z0-9._-]+)\s+v?([0-9.]+)',
            r'//\s*([a-zA-Z0-9._-]+)\s+v?([0-9.]+)',
            
            # @version tag
            r'@version\s+([0-9.]+)',
            
            # npm package pattern: library@version
            r'([a-zA-Z0-9@/_-]+)@([0-9.]+)',
            
            # File names: library-1.2.3.js
            r'([a-zA-Z0-9._-]+)-([0-9.]+)\.(?:min\.)?js',
            
            # CDN patterns (dynamic)
            r'cdn\.jsdelivr\.net/npm/([^@/]+)@([0-9.]+)',
            r'unpkg\.com/([^@/]+)@([0-9.]+)',
            r'cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([0-9.]+)',
            r'code\.jquery\.com/([^-]+)-([0-9.]+)',
            r'ajax\.googleapis\.com/ajax/libs/([^/]+)/([0-9.]+)',
            
            # Package path patterns
            r'node_modules/([^/]+)/([0-9.]+)',
            r'/([a-zA-Z0-9._-]+)/([0-9.]+)/',
        ]
        
        # Package.json dependency patterns
        self.package_json_pattern = r'"([^"]+)":\s*"[\^~>=<]*([0-9.]+[^"]*)"'
    
    def detect_versions(self, content: str, url: str = '') -> List[Dict[str, Any]]:
        """Dynamically detect all library versions in content."""
        detected = []
        seen = set()
        
        # Detect using generic patterns
        for pattern in self.generic_version_patterns:
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    if len(match.groups()) >= 2:
                        library = match.group(1).strip()
                        version = match.group(2).strip()
                    else:
                        library = 'unknown'
                        version = match.group(1).strip()
                    
                    # Clean library name
                    library = self._clean_library_name(library)
                    
                    # Validate version
                    if self._is_valid_version(version) and self._is_valid_library_name(library):
                        key = f"{library}:{version}"
                        if key not in seen:
                            seen.add(key)
                            detected.append({
                                'library': library,
                                'version': version,
                                'source': url,
                                'detection_method': 'pattern',
                                'confidence': 'high'
                            })
            except Exception:
                continue
        
        # Detect from package.json
        if 'package.json' in url.lower() or '"dependencies"' in content or '"devDependencies"' in content:
            package_versions = self._extract_from_package_json(content, url)
            for pv in package_versions:
                key = f"{pv['library']}:{pv['version']}"
                if key not in seen:
                    seen.add(key)
                    detected.append(pv)
        
        # Detect from webpack/bundle metadata
        webpack_versions = self._extract_from_webpack(content, url)
        for wv in webpack_versions:
            key = f"{wv['library']}:{wv['version']}"
            if key not in seen:
                seen.add(key)
                detected.append(wv)
        
        return detected
    
    def _clean_library_name(self, name: str) -> str:
        """Clean and normalize library name."""
        # Remove common prefixes/suffixes
        name = re.sub(r'\.min$', '', name)
        name = re.sub(r'\.js$', '', name)
        name = re.sub(r'^@', '', name)
        
        # Remove path separators
        if '/' in name:
            name = name.split('/')[-1]
        
        return name.strip()
    
    def _is_valid_library_name(self, name: str) -> bool:
        """Validate library name."""
        if not name or len(name) < 2 or len(name) > 100:
            return False
        
        # Skip common false positives
        false_positives = [
            'var', 'let', 'const', 'function', 'return', 'this', 'self',
            'window', 'document', 'console', 'undefined', 'null', 'true', 'false',
            'http', 'https', 'www', 'com', 'org', 'net', 'io',
            'profile_background_images', 'background', 'images', 'image',
            'data', 'id', 'name', 'value', 'type', 'class', 'style',
            'width', 'height', 'src', 'href', 'alt', 'title'
        ]
        
        if name.lower() in false_positives:
            return False
        
        # Skip if it's just numbers
        if name.isdigit():
            return False
        
        # Skip if it looks like an ID or hash
        if len(name) > 20 and name.isalnum():
            return False
        
        # Must contain letters
        if not re.search(r'[a-zA-Z]', name):
            return False
        
        # Skip if it contains spaces
        if ' ' in name:
            return False
        
        return True
    
    def _is_valid_version(self, version: str) -> bool:
        """Validate version format."""
        if not version or len(version) > 30:
            return False
        
        # Must contain at least one digit
        if not re.search(r'\d', version):
            return False
        
        # Common version patterns
        valid_patterns = [
            r'^\d+\.\d+\.\d+',  # 1.2.3
            r'^\d+\.\d+',        # 1.2
            r'^\d+',             # 1
        ]
        
        for pattern in valid_patterns:
            if re.match(pattern, version):
                return True
        
        return False
    
    def _extract_from_package_json(self, content: str, url: str) -> List[Dict[str, Any]]:
        """Extract versions from package.json content."""
        versions = []
        
        try:
            # Try to parse as JSON
            data = json.loads(content)
            
            # Check dependencies
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
                if dep_type in data and isinstance(data[dep_type], dict):
                    for lib, ver in data[dep_type].items():
                        # Clean version (remove ^, ~, >=, etc.)
                        clean_ver = re.sub(r'[\^~>=<]', '', str(ver))
                        clean_ver = clean_ver.split()[0]  # Take first part
                        
                        if self._is_valid_version(clean_ver):
                            versions.append({
                                'library': lib,
                                'version': clean_ver,
                                'source': url,
                                'detection_method': 'package.json',
                                'confidence': 'high',
                                'dependency_type': dep_type
                            })
        except Exception:
            # Fallback to regex
            matches = re.finditer(self.package_json_pattern, content)
            for match in matches:
                lib = match.group(1)
                ver = match.group(2)
                
                # Clean version
                clean_ver = re.sub(r'[\^~>=<]', '', ver)
                clean_ver = clean_ver.split()[0]
                
                if self._is_valid_version(clean_ver) and self._is_valid_library_name(lib):
                    versions.append({
                        'library': lib,
                        'version': clean_ver,
                        'source': url,
                        'detection_method': 'package.json',
                        'confidence': 'medium'
                    })
        
        return versions
    
    def _extract_from_webpack(self, content: str, url: str) -> List[Dict[str, Any]]:
        """Extract versions from webpack bundle metadata."""
        versions = []
        
        # Webpack module IDs with versions
        webpack_patterns = [
            r'\/\*\*\*\/ "([^"]+)":\s*\/\*\*\*\/.*?version.*?["\']([0-9.]+)["\']',
            r'module\.exports\s*=\s*{[^}]*name:\s*["\']([^"\']+)["\'][^}]*version:\s*["\']([0-9.]+)["\']',
        ]
        
        for pattern in webpack_patterns:
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    lib = match.group(1)
                    ver = match.group(2)
                    
                    if self._is_valid_version(ver) and self._is_valid_library_name(lib):
                        versions.append({
                            'library': lib,
                            'version': ver,
                            'source': url,
                            'detection_method': 'webpack',
                            'confidence': 'medium'
                        })
            except Exception:
                continue
        
        return versions
    
    def analyze_versions(self, detected_versions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze detected versions."""
        analysis = {
            'total_libraries': 0,
            'total_detections': len(detected_versions),
            'by_library': {},
            'by_confidence': {'high': 0, 'medium': 0, 'low': 0},
            'by_method': {},
            'unique_libraries': set(),
            'library_list': []
        }
        
        for version in detected_versions:
            lib = version['library']
            ver = version['version']
            confidence = version.get('confidence', 'medium')
            method = version.get('detection_method', 'unknown')
            
            # Count by library
            if lib not in analysis['by_library']:
                analysis['by_library'][lib] = []
            analysis['by_library'][lib].append(ver)
            
            # Count by confidence
            analysis['by_confidence'][confidence] = analysis['by_confidence'].get(confidence, 0) + 1
            
            # Count by method
            analysis['by_method'][method] = analysis['by_method'].get(method, 0) + 1
            
            # Track unique
            analysis['unique_libraries'].add(lib)
            
            # Add to list
            analysis['library_list'].append({
                'library': lib,
                'version': ver,
                'confidence': confidence
            })
        
        analysis['total_libraries'] = len(analysis['unique_libraries'])
        analysis['unique_libraries'] = sorted(list(analysis['unique_libraries']))
        
        return analysis
