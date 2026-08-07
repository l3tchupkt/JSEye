"""Headless browser integration for dynamic JavaScript analysis."""

import asyncio
from typing import List, Dict, Any, Optional
import json


class HeadlessBrowser:
    """Headless browser for dynamic JavaScript analysis using Playwright."""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.browser = None
        self.context = None
        self.playwright_available = self._check_playwright()
        
    def _check_playwright(self) -> bool:
        """Check if Playwright is available."""
        try:
            import playwright
            return True
        except ImportError:
            return False
    
    async def __aenter__(self):
        """Async context manager entry."""
        if not self.playwright_available:
            return self
            
        try:
            from playwright.async_api import async_playwright
            
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--disable-gpu'
                ]
            )
            
            self.context = await self.browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                viewport={'width': 1920, 'height': 1080}
            )
            
        except Exception as e:
            self.playwright_available = False
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright') and self.playwright:
            await self.playwright.stop()
    
    async def analyze_page(self, url: str) -> Dict[str, Any]:
        """Analyze a page with headless browser."""
        if not self.playwright_available or not self.context:
            return {
                'url': url,
                'status': 'error',
                'error': 'Playwright not available',
                'network_requests': [],
                'console_logs': [],
                'javascript_errors': [],
                'intercepted_data': {}
            }
        
        try:
            page = await self.context.new_page()
            
            # Set up interceptors
            network_requests = []
            console_logs = []
            javascript_errors = []
            intercepted_data = {
                'fetch_calls': [],
                'xhr_requests': [],
                'websocket_connections': [],
                'local_storage': {},
                'session_storage': {},
                'cookies': []
            }
            
            # Network request interceptor
            async def handle_request(request):
                network_requests.append({
                    'url': request.url,
                    'method': request.method,
                    'headers': dict(request.headers),
                    'post_data': request.post_data,
                    'resource_type': request.resource_type
                })
            
            # Response interceptor
            async def handle_response(response):
                # Only capture interesting responses
                if response.request.resource_type in ['xhr', 'fetch']:
                    try:
                        content = await response.text()
                        network_requests.append({
                            'url': response.url,
                            'status': response.status,
                            'headers': dict(response.headers),
                            'content_preview': content[:1000] if content else '',
                            'type': 'response'
                        })
                    except Exception:
                        pass
            
            # Console log interceptor
            async def handle_console(msg):
                console_logs.append({
                    'type': msg.type,
                    'text': msg.text,
                    'location': msg.location
                })
            
            # JavaScript error interceptor
            async def handle_page_error(error):
                javascript_errors.append({
                    'message': str(error),
                    'name': error.__class__.__name__
                })
            
            # Set up event listeners
            page.on('request', handle_request)
            page.on('response', handle_response)
            page.on('console', handle_console)
            page.on('pageerror', handle_page_error)
            
            # Inject JavaScript to intercept API calls
            await page.add_init_script("""
                // Intercept fetch calls
                const originalFetch = window.fetch;
                window.fetch = function(...args) {
                    window.jseyeIntercepted = window.jseyeIntercepted || {};
                    window.jseyeIntercepted.fetchCalls = window.jseyeIntercepted.fetchCalls || [];
                    
                    const url = args[0];
                    const options = args[1] || {};
                    
                    window.jseyeIntercepted.fetchCalls.push({
                        url: url,
                        method: options.method || 'GET',
                        headers: options.headers || {},
                        body: options.body,
                        timestamp: Date.now()
                    });
                    
                    return originalFetch.apply(this, args);
                };
                
                // Intercept XMLHttpRequest
                const originalXHROpen = XMLHttpRequest.prototype.open;
                const originalXHRSend = XMLHttpRequest.prototype.send;
                
                XMLHttpRequest.prototype.open = function(method, url, ...args) {
                    this._jseyeMethod = method;
                    this._jseyeUrl = url;
                    return originalXHROpen.apply(this, [method, url, ...args]);
                };
                
                XMLHttpRequest.prototype.send = function(data) {
                    window.jseyeIntercepted = window.jseyeIntercepted || {};
                    window.jseyeIntercepted.xhrRequests = window.jseyeIntercepted.xhrRequests || [];
                    
                    window.jseyeIntercepted.xhrRequests.push({
                        method: this._jseyeMethod,
                        url: this._jseyeUrl,
                        data: data,
                        timestamp: Date.now()
                    });
                    
                    return originalXHRSend.apply(this, [data]);
                };
                
                // Intercept WebSocket
                const originalWebSocket = window.WebSocket;
                window.WebSocket = function(url, protocols) {
                    window.jseyeIntercepted = window.jseyeIntercepted || {};
                    window.jseyeIntercepted.websocketConnections = window.jseyeIntercepted.websocketConnections || [];
                    
                    window.jseyeIntercepted.websocketConnections.push({
                        url: url,
                        protocols: protocols,
                        timestamp: Date.now()
                    });
                    
                    return new originalWebSocket(url, protocols);
                };
            """)
            
            # Navigate to the page
            try:
                await page.goto(url, timeout=self.timeout * 1000, wait_until='networkidle')
            except Exception as e:
                # Try with a shorter timeout and different wait condition
                try:
                    await page.goto(url, timeout=15000, wait_until='domcontentloaded')
                except Exception:
                    pass
            
            # Wait a bit for dynamic content to load
            await asyncio.sleep(2)
            
            # Extract intercepted data
            try:
                intercepted_js_data = await page.evaluate('window.jseyeIntercepted || {}')
                intercepted_data.update(intercepted_js_data)
            except Exception:
                pass
            
            # Extract storage data
            try:
                local_storage = await page.evaluate('JSON.stringify(localStorage)')
                intercepted_data['local_storage'] = json.loads(local_storage) if local_storage else {}
            except Exception:
                pass
            
            try:
                session_storage = await page.evaluate('JSON.stringify(sessionStorage)')
                intercepted_data['session_storage'] = json.loads(session_storage) if session_storage else {}
            except Exception:
                pass
            
            # Extract cookies
            try:
                cookies = await page.context.cookies()
                intercepted_data['cookies'] = [
                    {
                        'name': cookie['name'],
                        'value': cookie['value'],
                        'domain': cookie['domain'],
                        'path': cookie['path'],
                        'secure': cookie.get('secure', False),
                        'httpOnly': cookie.get('httpOnly', False)
                    }
                    for cookie in cookies
                ]
            except Exception:
                pass
            
            await page.close()
            
            return {
                'url': url,
                'status': 'success',
                'network_requests': network_requests,
                'console_logs': console_logs,
                'javascript_errors': javascript_errors,
                'intercepted_data': intercepted_data
            }
            
        except Exception as e:
            return {
                'url': url,
                'status': 'error',
                'error': str(e),
                'network_requests': [],
                'console_logs': [],
                'javascript_errors': [],
                'intercepted_data': {}
            }
    
    async def analyze_multiple_pages(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple pages with headless browser."""
        if not self.playwright_available:
            return [{
                'url': url,
                'status': 'error',
                'error': 'Playwright not available'
            } for url in urls]
        
        results = []
        
        # Process pages sequentially to avoid overwhelming the browser
        for url in urls:
            result = await self.analyze_page(url)
            results.append(result)
            
            # Small delay between pages
            await asyncio.sleep(1)
        
        return results
    
    def is_available(self) -> bool:
        """Check if headless browser is available."""
        return self.playwright_available
    
    async def extract_dynamic_content(self, url: str, wait_time: int = 5) -> Dict[str, Any]:
        """Extract content that loads dynamically."""
        if not self.playwright_available or not self.context:
            return {
                'url': url,
                'status': 'error',
                'error': 'Playwright not available'
            }
        
        try:
            page = await self.context.new_page()
            
            # Navigate and wait for dynamic content
            await page.goto(url, timeout=self.timeout * 1000)
            await asyncio.sleep(wait_time)
            
            # Extract all script tags (including dynamically added ones)
            scripts = await page.evaluate("""
                Array.from(document.querySelectorAll('script')).map(script => ({
                    src: script.src,
                    content: script.innerHTML,
                    type: script.type,
                    async: script.async,
                    defer: script.defer
                }))
            """)
            
            # Extract dynamically loaded content
            dynamic_content = await page.evaluate("""
                {
                    title: document.title,
                    scripts: Array.from(document.querySelectorAll('script[src]')).map(s => s.src),
                    links: Array.from(document.querySelectorAll('link[href]')).map(l => ({href: l.href, rel: l.rel})),
                    meta: Array.from(document.querySelectorAll('meta')).map(m => ({name: m.name, content: m.content})),
                    forms: Array.from(document.querySelectorAll('form')).map(f => ({action: f.action, method: f.method}))
                }
            """)
            
            await page.close()
            
            return {
                'url': url,
                'status': 'success',
                'scripts': scripts,
                'dynamic_content': dynamic_content
            }
            
        except Exception as e:
            return {
                'url': url,
                'status': 'error',
                'error': str(e)
            }
    
    async def test_javascript_execution(self, url: str, js_code: str) -> Dict[str, Any]:
        """Test custom JavaScript code execution on a page."""
        if not self.playwright_available or not self.context:
            return {
                'url': url,
                'status': 'error',
                'error': 'Playwright not available'
            }
        
        try:
            page = await self.context.new_page()
            
            await page.goto(url, timeout=self.timeout * 1000)
            
            # Execute custom JavaScript
            result = await page.evaluate(js_code)
            
            await page.close()
            
            return {
                'url': url,
                'status': 'success',
                'result': result
            }
            
        except Exception as e:
            return {
                'url': url,
                'status': 'error',
                'error': str(e)
            }