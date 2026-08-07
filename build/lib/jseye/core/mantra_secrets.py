"""
Mantra Integration for Secret Detection
Specialized tool for finding secrets in JavaScript files
"""

import asyncio
import subprocess
import json
import tempfile
import os
from typing import List, Dict, Any


class MantraSecretScanner:
    """Integration with Mantra for secret detection in JavaScript."""
    
    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        self.mantra_available = self._check_mantra_availability()
    
    def _check_mantra_availability(self) -> bool:
        """Check if mantra is installed."""
        try:
            result = subprocess.run(
                ['mantra', '-h'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    async def scan_js_file(self, js_content: str, url: str) -> Dict[str, Any]:
        """Scan a single JS file for secrets using Mantra."""
        if not self.mantra_available:
            return {'success': False, 'secrets': []}
        
        try:
            # Write JS content to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(js_content)
                temp_file = f.name
            
            try:
                # Run mantra on the file
                cmd = ['mantra', '-f', temp_file, '-o', 'json']
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
                
                if process.returncode == 0:
                    try:
                        results = json.loads(stdout.decode('utf-8', errors='ignore'))
                        secrets = []
                        
                        for finding in results.get('findings', []):
                            secrets.append({
                                'type': finding.get('type', 'unknown'),
                                'value': finding.get('value', ''),
                                'line': finding.get('line', 0),
                                'confidence': finding.get('confidence', 'medium'),
                                'source_url': url,
                                'tool': 'mantra'
                            })
                        
                        return {
                            'success': True,
                            'secrets': secrets,
                            'count': len(secrets)
                        }
                    except json.JSONDecodeError:
                        return {'success': False, 'secrets': []}
                
                return {'success': False, 'secrets': []}
                
            finally:
                # Clean up temp file
                try:
                    os.unlink(temp_file)
                except Exception:
                    pass
                    
        except asyncio.TimeoutError:
            return {'success': False, 'secrets': [], 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'secrets': [], 'error': str(e)}
    
    async def scan_multiple_files(self, js_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan multiple JS files for secrets."""
        if not self.mantra_available:
            return {
                'success': False,
                'total_secrets': 0,
                'secrets_by_file': {},
                'error': 'Mantra not available'
            }
        
        all_secrets = []
        secrets_by_file = {}
        
        for js_file in js_files:
            url = js_file.get('url', 'unknown')
            content = js_file.get('content', '')
            
            if content:
                result = await self.scan_js_file(content, url)
                if result.get('success') and result.get('secrets'):
                    secrets = result['secrets']
                    all_secrets.extend(secrets)
                    secrets_by_file[url] = secrets
        
        return {
            'success': True,
            'total_secrets': len(all_secrets),
            'secrets': all_secrets,
            'secrets_by_file': secrets_by_file,
            'files_scanned': len(js_files)
        }
    
    def is_available(self) -> bool:
        """Check if mantra is available."""
        return self.mantra_available
