"""Plugin manager for JSEye v2.0 - Dynamic plugin loading and execution."""

import os
import sys
import importlib
import inspect
import asyncio
import traceback
from typing import Dict, List, Any, Optional, Type
from pathlib import Path

from jseye.plugins.base import BasePlugin, PluginContext, PluginResult, PluginCategory, PluginMetadata
from jseye.core.logging import get_logger
from jseye.core.exceptions import JSEyeException

logger = get_logger(__name__)


class PluginLoadError(JSEyeException):
    """Raised when plugin loading fails."""
    pass


class PluginExecutionError(JSEyeException):
    """Raised when plugin execution fails."""
    pass


class PluginManager:
    """Manages plugin loading, execution, and lifecycle."""
    
    def __init__(self, plugin_dirs: List[str] = None):
        self.plugins: Dict[str, BasePlugin] = {}
        self.plugin_metadata: Dict[str, PluginMetadata] = {}
        self.execution_order: List[str] = []
        self.disabled_plugins: set = set()
        
        # Default plugin directories
        self.plugin_dirs = plugin_dirs or [
            os.path.join(os.path.dirname(__file__)),  # Built-in plugins
            os.path.expanduser("~/.jseye/plugins"),   # User plugins
            os.path.join(os.getcwd(), ".jseye/plugins")  # Project plugins
        ]
        
        self.profiling_enabled = False
        self.execution_stats: Dict[str, Dict[str, Any]] = {}
    
    def enable_profiling(self) -> None:
        """Enable plugin execution profiling."""
        self.profiling_enabled = True
        self.execution_stats.clear()
    
    def disable_profiling(self) -> None:
        """Disable plugin execution profiling."""
        self.profiling_enabled = False
    
    def get_profiling_report(self) -> Dict[str, Any]:
        """Get detailed profiling report."""
        if not self.profiling_enabled:
            return {}
        
        total_time = sum(stats.get('execution_time', 0) for stats in self.execution_stats.values())
        total_memory = sum(stats.get('memory_usage', 0) for stats in self.execution_stats.values())
        total_network_calls = sum(stats.get('network_calls', 0) for stats in self.execution_stats.values())
        
        return {
            'total_execution_time': total_time,
            'total_memory_usage': total_memory,
            'total_network_calls': total_network_calls,
            'plugin_stats': self.execution_stats,
            'plugin_count': len(self.plugins),
            'enabled_plugins': len([p for p in self.plugins.values() if p.is_enabled()]),
            'performance_breakdown': {
                name: {
                    'time_percentage': (stats.get('execution_time', 0) / total_time * 100) if total_time > 0 else 0,
                    'memory_percentage': (stats.get('memory_usage', 0) / total_memory * 100) if total_memory > 0 else 0
                }
                for name, stats in self.execution_stats.items()
            }
        }
    
    async def load_plugins(self) -> None:
        """Load all plugins from plugin directories."""
        logger.info("Loading plugins from directories", dirs=self.plugin_dirs)
        
        for plugin_dir in self.plugin_dirs:
            if os.path.exists(plugin_dir):
                await self._load_plugins_from_directory(plugin_dir)
        
        # Sort plugins by execution order
        self._sort_plugins_by_execution_order()
        
        logger.info(f"Loaded {len(self.plugins)} plugins", 
                   enabled=len([p for p in self.plugins.values() if p.is_enabled()]))
    
    async def _load_plugins_from_directory(self, plugin_dir: str) -> None:
        """Load plugins from a specific directory."""
        try:
            plugin_path = Path(plugin_dir)
            
            # Add plugin directory to Python path
            if str(plugin_path) not in sys.path:
                sys.path.insert(0, str(plugin_path))
            
            # Find Python files
            for py_file in plugin_path.glob("*.py"):
                if py_file.name.startswith("__"):
                    continue
                
                try:
                    await self._load_plugin_from_file(py_file)
                except Exception as e:
                    logger.warning(f"Failed to load plugin from {py_file}: {e}")
        
        except Exception as e:
            logger.error(f"Failed to load plugins from directory {plugin_dir}: {e}")
    
    async def _load_plugin_from_file(self, plugin_file: Path) -> None:
        """Load a plugin from a Python file."""
        try:
            module_name = plugin_file.stem
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            
            if spec is None or spec.loader is None:
                return
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, BasePlugin) and 
                    obj != BasePlugin and 
                    not inspect.isabstract(obj)):
                    
                    plugin_instance = obj()
                    metadata = plugin_instance.metadata
                    
                    if metadata.name in self.plugins:
                        logger.warning(f"Plugin {metadata.name} already loaded, skipping")
                        continue
                    
                    self.plugins[metadata.name] = plugin_instance
                    self.plugin_metadata[metadata.name] = metadata
                    
                    logger.debug(f"Loaded plugin: {metadata.name} v{metadata.version}")
        
        except Exception as e:
            logger.error(f"Error loading plugin from {plugin_file}: {e}")
            raise PluginLoadError(f"Failed to load plugin from {plugin_file}: {e}")
    
    def _sort_plugins_by_execution_order(self) -> None:
        """Sort plugins by category and execution order."""
        # Group by category first, then by execution order
        category_order = [
            PluginCategory.COLLECTION,
            PluginCategory.ANALYSIS,
            PluginCategory.DETECTION,
            PluginCategory.INTELLIGENCE,
            PluginCategory.EXPORT
        ]
        
        sorted_plugins = []
        
        for category in category_order:
            category_plugins = [
                (name, metadata) for name, metadata in self.plugin_metadata.items()
                if metadata.category == category
            ]
            
            # Sort by execution order within category
            category_plugins.sort(key=lambda x: x[1].execution_order)
            sorted_plugins.extend([name for name, _ in category_plugins])
        
        self.execution_order = sorted_plugins
    
    async def execute_plugins(self, context: PluginContext) -> Dict[str, PluginResult]:
        """Execute all enabled plugins in order."""
        from rich.progress import Progress, SpinnerColumn, TextColumn
        from rich.console import Console
        
        results = {}
        console = Console()
        
        enabled_plugins = [name for name in self.execution_order 
                          if name in self.plugins and 
                          self.plugins[name].is_enabled() and 
                          name not in self.disabled_plugins]
        
        logger.info("Executing plugins", 
                   total=len(self.execution_order),
                   enabled=len(enabled_plugins))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            for i, plugin_name in enumerate(self.execution_order):
                if plugin_name not in self.plugins:
                    continue
                
                plugin = self.plugins[plugin_name]
                
                if not plugin.is_enabled() or plugin_name in self.disabled_plugins:
                    logger.debug(f"Skipping disabled plugin: {plugin_name}")
                    continue
                
                task = progress.add_task(f"Running {plugin_name}...", total=None)
                
                # Add small delay for better visibility
                await asyncio.sleep(1.0)  # Increased delay
                
                try:
                    result = await self._execute_single_plugin(plugin, context)
                    results[plugin_name] = result
                    
                    # Add plugin results to shared context
                    context.add_shared_data(f"{plugin_name}_results", result)
                    
                    progress.update(task, description=f"Completed {plugin_name} ({len(result.findings)} findings)")
                    
                    # Add delay to show completion status
                    await asyncio.sleep(0.8)  # Increased delay
                    
                except Exception as e:
                    logger.error(f"Plugin {plugin_name} execution failed: {e}")
                    
                    # Create error result
                    error_result = PluginResult(plugin_name=plugin_name, findings=[])
                    error_result.errors.append(str(e))
                    results[plugin_name] = error_result
                    
                    progress.update(task, description=f"Failed {plugin_name}: {str(e)}")
                    await asyncio.sleep(0.8)  # Increased delay
                
                progress.remove_task(task)
        
        return results
    
    async def _execute_single_plugin(self, plugin: BasePlugin, context: PluginContext) -> PluginResult:
        """Execute a single plugin with profiling and error handling."""
        plugin_name = plugin.metadata.name
        
        # Validate context
        if not await plugin.validate_context(context):
            raise PluginExecutionError(f"Context validation failed for plugin {plugin_name}")
        
        # Start profiling
        start_time = asyncio.get_event_loop().time()
        start_memory = self._get_memory_usage()
        
        try:
            logger.debug(f"Executing plugin: {plugin_name}")
            
            # Execute plugin
            result = await plugin.run(context)
            
            # Record execution stats
            end_time = asyncio.get_event_loop().time()
            end_memory = self._get_memory_usage()
            
            execution_time = end_time - start_time
            memory_usage = max(0, end_memory - start_memory)
            
            result.execution_time = execution_time
            result.memory_usage = memory_usage
            
            if self.profiling_enabled:
                self.execution_stats[plugin_name] = {
                    'execution_time': execution_time,
                    'memory_usage': memory_usage,
                    'network_calls': result.network_calls,
                    'findings_count': len(result.findings),
                    'errors_count': len(result.errors),
                    'category': plugin.metadata.category.value,
                    'risk_weight': plugin.metadata.risk_weight
                }
            
            logger.debug(f"Plugin {plugin_name} completed", 
                        execution_time=execution_time,
                        findings=len(result.findings),
                        errors=len(result.errors))
            
            return result
            
        except Exception as e:
            logger.error(f"Plugin {plugin_name} execution error: {e}")
            
            # Create error result
            error_result = PluginResult(plugin_name=plugin_name)
            error_result.errors.append(f"Execution error: {str(e)}")
            error_result.execution_time = asyncio.get_event_loop().time() - start_time
            
            return error_result
    
    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss
        except ImportError:
            return 0
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all loaded plugins with metadata."""
        plugins_info = []
        
        for name, metadata in self.plugin_metadata.items():
            plugin = self.plugins.get(name)
            
            plugins_info.append({
                'name': name,
                'version': metadata.version,
                'category': metadata.category.value,
                'description': metadata.description,
                'author': metadata.author,
                'risk_weight': metadata.risk_weight,
                'execution_order': metadata.execution_order,
                'enabled': plugin.is_enabled() if plugin else False,
                'requires': metadata.requires
            })
        
        return plugins_info
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a specific plugin."""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enable()
            self.disabled_plugins.discard(plugin_name)
            logger.info(f"Enabled plugin: {plugin_name}")
            return True
        return False
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a specific plugin."""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].disable()
            self.disabled_plugins.add(plugin_name)
            logger.info(f"Disabled plugin: {plugin_name}")
            return True
        return False
    
    def get_plugin_by_name(self, plugin_name: str) -> Optional[BasePlugin]:
        """Get a plugin by name."""
        return self.plugins.get(plugin_name)
    
    def get_plugins_by_category(self, category: PluginCategory) -> List[BasePlugin]:
        """Get all plugins in a specific category."""
        return [
            plugin for plugin in self.plugins.values()
            if plugin.metadata.category == category and plugin.is_enabled()
        ]