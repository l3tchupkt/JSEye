import asyncio
from typing import Dict, Any, List

from .base import (
    BasePlugin, PluginContext, PluginResult, PluginMetadata,
    PluginCategory, ExploitationLikelihood, ExposureLevel
)
from ..core.ast_engine import JSASTAnalyzer
from ..core.logging import get_logger

logger = get_logger(__name__)

class ASTAnalysisPlugin(BasePlugin):
    """Plugin for deep JavaScript AST analysis."""
    
    def __init__(self):
        super().__init__()
        self._metadata = PluginMetadata(
            name="ASTAnalysisPlugin",
            version="1.0.0",
            category=PluginCategory.ANALYSIS,
            risk_weight=0.8,
            description="Performs deep Abstract Syntax Tree analysis of JavaScript files to find endpoints and variables.",
            author="JSEye Team",
            execution_order=150
        )
    
    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata
        
    async def run(self, context: PluginContext) -> PluginResult:
        result = self.create_result()
        js_files = context.js_files
        
        loop = asyncio.get_running_loop()
        ast_analyzer = JSASTAnalyzer()
        
        for js_file in js_files:
            content = js_file.get('content', '')
            url = js_file.get('url', '')
            if not content:
                continue
                
            try:
                # Run in executor to avoid blocking event loop
                analysis = await loop.run_in_executor(None, ast_analyzer.analyze, content, url)
                
                # Add endpoints found via AST
                if analysis.get('endpoints'):
                    for ep in analysis['endpoints']:
                        url_val = ep.get('normalized', ep.get('original', ''))
                        if url_val:
                            result.add_finding({
                                'type': 'ast_endpoint',
                                'url': url_val,
                                'source_file': url,
                                'confidence_score': 85.0
                            })
                            
            except Exception as e:
                logger.error(f"AST Analysis failed for {url}: {e}")
                result.errors.append(f"AST Analysis failed for {url}: {e}")
                
        return result
