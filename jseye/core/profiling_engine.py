"""Scan Profiling Engine for JSEye v2.1."""

import time
import asyncio
import psutil
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from .logging import get_logger

logger = get_logger(__name__)


@dataclass
class ProfileMetrics:
    """Profiling metrics for a single operation."""
    operation_name: str
    start_time: float
    end_time: float
    execution_time: float
    memory_start: int
    memory_end: int
    memory_delta: int
    network_calls: int = 0
    cpu_percent: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginProfile:
    """Profiling data for a plugin execution."""
    plugin_name: str
    category: str
    execution_time: float
    memory_usage: int
    network_calls: int
    findings_count: int
    errors_count: int
    cpu_percent: float
    success: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanProfile:
    """Complete scan profiling data."""
    target: str
    total_execution_time: float
    total_memory_usage: int
    total_network_calls: int
    plugin_profiles: List[PluginProfile]
    phase_metrics: Dict[str, ProfileMetrics]
    system_metrics: Dict[str, Any]
    performance_summary: Dict[str, Any]
    bottlenecks: List[str]
    recommendations: List[str]


class ProfilingEngine:
    """Engine for profiling scan performance and resource usage."""
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.scan_start_time = 0.0
        self.scan_start_memory = 0
        self.current_metrics: Dict[str, ProfileMetrics] = {}
        self.plugin_profiles: List[PluginProfile] = []
        self.phase_metrics: Dict[str, ProfileMetrics] = {}
        self.system_metrics: Dict[str, Any] = {}
        
        # Performance thresholds
        self.slow_plugin_threshold = 30.0  # seconds
        self.high_memory_threshold = 500 * 1024 * 1024  # 500MB
        self.high_network_threshold = 100  # network calls
    
    def start_scan_profiling(self, target: str) -> None:
        """Start profiling for the entire scan."""
        if not self.enabled:
            return
        
        self.scan_start_time = time.time()
        self.scan_start_memory = self._get_memory_usage()
        self.system_metrics = self._capture_system_metrics()
        
        logger.debug("Started scan profiling", target=target)
    
    def start_operation(self, operation_name: str, metadata: Dict[str, Any] = None) -> None:
        """Start profiling an operation."""
        if not self.enabled:
            return
        
        start_time = time.time()
        start_memory = self._get_memory_usage()
        
        self.current_metrics[operation_name] = ProfileMetrics(
            operation_name=operation_name,
            start_time=start_time,
            end_time=0.0,
            execution_time=0.0,
            memory_start=start_memory,
            memory_end=0,
            memory_delta=0,
            metadata=metadata or {}
        )
        
        logger.debug(f"Started profiling operation: {operation_name}")
    
    def end_operation(self, operation_name: str, network_calls: int = 0) -> Optional[ProfileMetrics]:
        """End profiling an operation."""
        if not self.enabled or operation_name not in self.current_metrics:
            return None
        
        end_time = time.time()
        end_memory = self._get_memory_usage()
        
        metrics = self.current_metrics[operation_name]
        metrics.end_time = end_time
        metrics.execution_time = end_time - metrics.start_time
        metrics.memory_end = end_memory
        metrics.memory_delta = end_memory - metrics.memory_start
        metrics.network_calls = network_calls
        
        # Store in phase metrics
        self.phase_metrics[operation_name] = metrics
        
        # Remove from current metrics
        del self.current_metrics[operation_name]
        
        logger.debug(f"Completed profiling operation: {operation_name}", 
                    execution_time=metrics.execution_time,
                    memory_delta=metrics.memory_delta)
        
        return metrics
    
    def profile_plugin_execution(self, plugin_name: str, category: str, 
                                execution_time: float, memory_usage: int,
                                network_calls: int, findings_count: int,
                                errors_count: int, success: bool,
                                metadata: Dict[str, Any] = None) -> None:
        """Record plugin execution profile."""
        if not self.enabled:
            return
        
        # Get CPU usage (approximate)
        cpu_percent = 0.0
        try:
            cpu_percent = psutil.cpu_percent()
        except Exception:
            pass
        
        profile = PluginProfile(
            plugin_name=plugin_name,
            category=category,
            execution_time=execution_time,
            memory_usage=memory_usage,
            network_calls=network_calls,
            findings_count=findings_count,
            errors_count=errors_count,
            cpu_percent=cpu_percent,
            success=success,
            metadata=metadata or {}
        )
        
        self.plugin_profiles.append(profile)
        
        logger.debug(f"Recorded plugin profile: {plugin_name}",
                    execution_time=execution_time,
                    memory_usage=memory_usage,
                    findings=findings_count)
    
    def generate_scan_profile(self, target: str) -> ScanProfile:
        """Generate complete scan profile."""
        if not self.enabled:
            return ScanProfile(
                target=target,
                total_execution_time=0.0,
                total_memory_usage=0,
                total_network_calls=0,
                plugin_profiles=[],
                phase_metrics={},
                system_metrics={},
                performance_summary={},
                bottlenecks=[],
                recommendations=[]
            )
        
        total_execution_time = time.time() - self.scan_start_time
        total_memory_usage = self._get_memory_usage() - self.scan_start_memory
        total_network_calls = sum(p.network_calls for p in self.plugin_profiles)
        
        # Generate performance summary
        performance_summary = self._generate_performance_summary()
        
        # Identify bottlenecks
        bottlenecks = self._identify_bottlenecks()
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        profile = ScanProfile(
            target=target,
            total_execution_time=total_execution_time,
            total_memory_usage=total_memory_usage,
            total_network_calls=total_network_calls,
            plugin_profiles=self.plugin_profiles,
            phase_metrics=self.phase_metrics,
            system_metrics=self.system_metrics,
            performance_summary=performance_summary,
            bottlenecks=bottlenecks,
            recommendations=recommendations
        )
        
        logger.info("Generated scan profile",
                   target=target,
                   total_time=total_execution_time,
                   plugins_executed=len(self.plugin_profiles))
        
        return profile
    
    def get_profiling_report(self) -> Dict[str, Any]:
        """Get profiling report in dictionary format."""
        if not self.enabled:
            return {'profiling_enabled': False}
        
        total_time = sum(p.execution_time for p in self.plugin_profiles)
        total_memory = sum(p.memory_usage for p in self.plugin_profiles)
        total_network = sum(p.network_calls for p in self.plugin_profiles)
        
        return {
            'profiling_enabled': True,
            'total_execution_time': total_time,
            'total_memory_usage': total_memory,
            'total_network_calls': total_network,
            'plugin_count': len(self.plugin_profiles),
            'successful_plugins': len([p for p in self.plugin_profiles if p.success]),
            'failed_plugins': len([p for p in self.plugin_profiles if not p.success]),
            'plugin_breakdown': [
                {
                    'name': p.plugin_name,
                    'category': p.category,
                    'execution_time': p.execution_time,
                    'memory_usage': p.memory_usage,
                    'network_calls': p.network_calls,
                    'findings': p.findings_count,
                    'errors': p.errors_count,
                    'success': p.success,
                    'time_percentage': (p.execution_time / total_time * 100) if total_time > 0 else 0,
                    'memory_percentage': (p.memory_usage / total_memory * 100) if total_memory > 0 else 0
                }
                for p in self.plugin_profiles
            ],
            'phase_breakdown': {
                name: {
                    'execution_time': metrics.execution_time,
                    'memory_delta': metrics.memory_delta,
                    'network_calls': metrics.network_calls
                }
                for name, metrics in self.phase_metrics.items()
            },
            'performance_summary': self._generate_performance_summary(),
            'bottlenecks': self._identify_bottlenecks(),
            'recommendations': self._generate_recommendations()
        }
    
    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes."""
        try:
            process = psutil.Process()
            return process.memory_info().rss
        except Exception:
            return 0
    
    def _capture_system_metrics(self) -> Dict[str, Any]:
        """Capture system metrics at scan start."""
        try:
            return {
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'memory_available': psutil.virtual_memory().available,
                'cpu_percent': psutil.cpu_percent(),
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            }
        except Exception as e:
            logger.warning(f"Failed to capture system metrics: {e}")
            return {}
    
    def _generate_performance_summary(self) -> Dict[str, Any]:
        """Generate performance summary statistics."""
        if not self.plugin_profiles:
            return {}
        
        execution_times = [p.execution_time for p in self.plugin_profiles]
        memory_usages = [p.memory_usage for p in self.plugin_profiles]
        network_calls = [p.network_calls for p in self.plugin_profiles]
        
        return {
            'fastest_plugin': min(self.plugin_profiles, key=lambda p: p.execution_time).plugin_name,
            'slowest_plugin': max(self.plugin_profiles, key=lambda p: p.execution_time).plugin_name,
            'most_memory_intensive': max(self.plugin_profiles, key=lambda p: p.memory_usage).plugin_name,
            'most_network_intensive': max(self.plugin_profiles, key=lambda p: p.network_calls).plugin_name,
            'average_execution_time': sum(execution_times) / len(execution_times),
            'average_memory_usage': sum(memory_usages) / len(memory_usages),
            'average_network_calls': sum(network_calls) / len(network_calls),
            'total_findings': sum(p.findings_count for p in self.plugin_profiles),
            'total_errors': sum(p.errors_count for p in self.plugin_profiles)
        }
    
    def _identify_bottlenecks(self) -> List[str]:
        """Identify performance bottlenecks."""
        bottlenecks = []
        
        # Check for slow plugins
        slow_plugins = [p for p in self.plugin_profiles if p.execution_time > self.slow_plugin_threshold]
        for plugin in slow_plugins:
            bottlenecks.append(f"Slow plugin: {plugin.plugin_name} took {plugin.execution_time:.2f}s")
        
        # Check for high memory usage
        memory_intensive = [p for p in self.plugin_profiles if p.memory_usage > self.high_memory_threshold]
        for plugin in memory_intensive:
            mb_usage = plugin.memory_usage / (1024 * 1024)
            bottlenecks.append(f"High memory usage: {plugin.plugin_name} used {mb_usage:.1f}MB")
        
        # Check for high network usage
        network_intensive = [p for p in self.plugin_profiles if p.network_calls > self.high_network_threshold]
        for plugin in network_intensive:
            bottlenecks.append(f"High network usage: {plugin.plugin_name} made {plugin.network_calls} calls")
        
        # Check for failed plugins
        failed_plugins = [p for p in self.plugin_profiles if not p.success]
        for plugin in failed_plugins:
            bottlenecks.append(f"Failed plugin: {plugin.plugin_name} had {plugin.errors_count} errors")
        
        return bottlenecks
    
    def _generate_recommendations(self) -> List[str]:
        """Generate performance recommendations."""
        recommendations = []
        
        if not self.plugin_profiles:
            return recommendations
        
        # Analyze execution times
        total_time = sum(p.execution_time for p in self.plugin_profiles)
        if total_time > 120:  # 2 minutes
            recommendations.append("Consider reducing the number of concurrent operations to improve performance")
        
        # Analyze memory usage
        total_memory = sum(p.memory_usage for p in self.plugin_profiles)
        if total_memory > 1024 * 1024 * 1024:  # 1GB
            recommendations.append("High memory usage detected. Consider processing files in smaller batches")
        
        # Analyze network calls
        total_network = sum(p.network_calls for p in self.plugin_profiles)
        if total_network > 500:
            recommendations.append("High number of network calls. Consider implementing request caching or rate limiting")
        
        # Check for plugin failures
        failed_count = len([p for p in self.plugin_profiles if not p.success])
        if failed_count > 0:
            recommendations.append(f"{failed_count} plugins failed. Check network connectivity and API availability")
        
        # Check for unbalanced plugin performance
        execution_times = [p.execution_time for p in self.plugin_profiles]
        if len(execution_times) > 1:
            max_time = max(execution_times)
            min_time = min(execution_times)
            if max_time > min_time * 10:  # 10x difference
                recommendations.append("Significant performance imbalance between plugins. Consider optimizing slower plugins")
        
        return recommendations
    
    def export_profile_json(self, filepath: str) -> bool:
        """Export profiling data to JSON file."""
        if not self.enabled:
            return False
        
        try:
            import json
            
            profile_data = self.get_profiling_report()
            
            with open(filepath, 'w') as f:
                json.dump(profile_data, f, indent=2, default=str)
            
            logger.info(f"Profiling data exported to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export profiling data: {e}")
            return False
    
    def reset(self) -> None:
        """Reset profiling data for new scan."""
        self.current_metrics.clear()
        self.plugin_profiles.clear()
        self.phase_metrics.clear()
        self.system_metrics.clear()
        self.scan_start_time = 0.0
        self.scan_start_memory = 0