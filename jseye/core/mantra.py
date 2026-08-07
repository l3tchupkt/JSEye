"""Mantra integration for JSEye - JavaScript file discovery and analysis."""

import asyncio
import subprocess
import json
from typing import List, Dict, Any, Optional
from .logging import get_logger

logger = get_logger(__name__)


class MantraIntegration:
    """Integration with Mantra tool for JavaScript discovery."""
    
    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        self.tool_name = 'mantra'
    
    def is_available(self) -> bool:
        """Check if mantra is installed and available."""
        try:
            result = subprocess.run([self.tool_name, '-h'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    async def discover_js_urls(self, domain: str, depth: int = 3) -> List[Dict[str, Any]]:
        """
        Discover JavaScript URLs using mantra.
        
        Args:
            domain: Target domain to scan
            depth: Crawl depth (default: 3)
            
        Returns:
            List of discovered JavaScript URLs with metadata
        """
        if not self.is_available():
            logger.warning("Mantra tool not available")
            return []
        
        try:
            logger.info(f"Discovering JS URLs with mantra for {domain}")
            
            # Mantra reads from stdin, so we pipe the domain
            cmd = [
                self.tool_name,
                '-s',  # Silent mode
                '-t', '50'  # Thread count
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                # Send domain to stdin
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=f"{domain}\n".encode()),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                logger.warning(f"Mantra timed out after {self.timeout}s for {domain}")
                return []
            
            if process.returncode != 0:
                error_msg = stderr.decode().strip()
                if error_msg:
                    logger.warning(f"Mantra failed for {domain}: {error_msg}")
                return []
            
            # Parse output
            js_urls = []
            output = stdout.decode('utf-8', errors='ignore')
            
            for line in output.strip().split('\n'):
                line = line.strip()
                if line and (line.endswith('.js') or '/js/' in line or 'javascript' in line.lower()):
                    js_urls.append({
                        'url': line,
                        'source': 'mantra',
                        'type': 'discovered',
                        'depth': depth
                    })
            
            logger.info(f"Mantra discovered {len(js_urls)} JS URLs for {domain}")
            return js_urls
            
        except Exception as e:
            logger.error(f"Mantra discovery failed for {domain}: {e}")
            return []
    
    async def crawl_with_mantra(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Crawl target with mantra and extract JavaScript files.
        
        Args:
            target: Target URL or domain
            options: Additional options for mantra
            
        Returns:
            Dictionary with crawl results
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'Mantra tool not available',
                'js_urls': []
            }
        
        options = options or {}
        
        try:
            logger.info(f"Crawling {target} with mantra")
            
            # Build command - mantra reads from stdin
            cmd = [self.tool_name, '-s', '-t', '50']  # Silent mode, 50 threads
            
            # Execute mantra
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                # Send target to stdin
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=f"{target}\n".encode()),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                return {
                    'success': False,
                    'error': f'Timeout after {self.timeout}s',
                    'js_urls': []
                }
            
            if process.returncode != 0:
                error_msg = stderr.decode().strip()
                return {
                    'success': False,
                    'error': error_msg if error_msg else 'Unknown error',
                    'js_urls': []
                }
            
            # Parse results
            output = stdout.decode('utf-8', errors='ignore')
            all_urls = []
            js_urls = []
            
            for line in output.strip().split('\n'):
                line = line.strip()
                if line:
                    all_urls.append(line)
                    if line.endswith('.js') or '/js/' in line or 'javascript' in line.lower():
                        js_urls.append({
                            'url': line,
                            'source': 'mantra',
                            'type': 'crawled'
                        })
            
            return {
                'success': True,
                'target': target,
                'total_urls': len(all_urls),
                'js_urls': js_urls,
                'tool': 'mantra'
            }
            
        except Exception as e:
            logger.error(f"Mantra crawl failed for {target}: {e}")
            return {
                'success': False,
                'error': str(e),
                'js_urls': []
            }
    
    async def extract_endpoints(self, js_content: str) -> List[str]:
        """
        Extract API endpoints from JavaScript content.
        
        Args:
            js_content: JavaScript file content
            
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        
        try:
            # Common endpoint patterns
            patterns = [
                r'["\']/(api|v\d+)/[^"\']+["\']',
                r'["\']https?://[^"\']+/api/[^"\']+["\']',
                r'endpoint\s*[:=]\s*["\'][^"\']+["\']',
                r'url\s*[:=]\s*["\'][^"\']+["\']',
            ]
            
            import re
            for pattern in patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                endpoints.extend(matches)
            
            # Remove duplicates
            endpoints = list(set(endpoints))
            
        except Exception as e:
            logger.error(f"Endpoint extraction failed: {e}")
        
        return endpoints
