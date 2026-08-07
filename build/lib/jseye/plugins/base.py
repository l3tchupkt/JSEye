"""Base plugin architecture for JSEye v2.1."""

import abc
import time
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum


class PluginCategory(Enum):
    """Plugin categories for organization and execution order."""
    COLLECTION = "collection"
    ANALYSIS = "analysis"
    DETECTION = "detection"
    INTELLIGENCE = "intelligence"
    EXPORT = "export"


class ExploitationLikelihood(Enum):
    """Exploitation likelihood levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ExposureLevel(Enum):
    """Exposure level classification."""
    INTERNAL = "internal"
    EXTERNAL = "external"
    PUBLIC = "public"


@dataclass
class PluginMetadata:
    """Plugin metadata for registration and management."""
    name: str
    version: str
    category: PluginCategory
    risk_weight: float  # 0.0 to 1.0
    description: str
    author: str = "JSEye Team"
    requires: List[str] = field(default_factory=list)
    enabled: bool = True
    execution_order: int = 100  # Lower numbers execute first


@dataclass
class ConfidenceFactors:
    """Detailed confidence scoring factors."""
    base_confidence: float
    contributing_factors: List[str]
    penalty_factors: List[str] = field(default_factory=list)
    final_confidence: float = 0.0
    
    def __post_init__(self):
        """Calculate final confidence after initialization."""
        if self.final_confidence == 0.0:
            self.final_confidence = max(0.0, min(100.0, self.base_confidence))


@dataclass
class RiskMetrics:
    """Enhanced risk metrics for findings."""
    confidence_score: float  # 0-100
    exploitation_likelihood: ExploitationLikelihood
    stability_score: float  # 0-100, how stable/reliable the finding is
    exposure_level: ExposureLevel
    contributing_factors: List[str]
    risk_weight: float = 1.0


@dataclass
class PluginResult:
    """Standardized plugin result structure."""
    plugin_name: str
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0
    memory_usage: int = 0  # bytes
    network_calls: int = 0
    errors: List[str] = field(default_factory=list)
    
    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding with validation."""
        # Ensure required fields
        if 'type' not in finding:
            finding['type'] = 'unknown'
        if 'confidence_score' not in finding:
            finding['confidence_score'] = 50.0
        
        self.findings.append(finding)
    
    def get_high_confidence_findings(self, threshold: float = 70.0) -> List[Dict[str, Any]]:
        """Get findings above confidence threshold."""
        return [f for f in self.findings if f.get('confidence_score', 0) >= threshold]


@dataclass
class PluginContext:
    """Context object passed to plugins containing scan data and configuration."""
    target: str
    js_files: List[Dict[str, Any]]
    config: Dict[str, Any]
    shared_data: Dict[str, Any] = field(default_factory=dict)
    scan_metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Performance tracking
    start_time: float = field(default_factory=time.time)
    profiling_enabled: bool = False
    
    def get_js_content(self) -> List[str]:
        """Get all JavaScript content as list."""
        return [js_file.get('content', '') for js_file in self.js_files if js_file.get('content')]
    
    def get_js_urls(self) -> List[str]:
        """Get all JavaScript URLs."""
        return [js_file.get('url', '') for js_file in self.js_files if js_file.get('url')]
    
    def add_shared_data(self, key: str, value: Any) -> None:
        """Add data to be shared between plugins."""
        self.shared_data[key] = value
    
    def get_shared_data(self, key: str, default: Any = None) -> Any:
        """Get shared data from other plugins."""
        return self.shared_data.get(key, default)


class BasePlugin(abc.ABC):
    """Abstract base class for all JSEye plugins."""
    
    def __init__(self):
        self._metadata: Optional[PluginMetadata] = None
        self._enabled = True
    
    @property
    @abc.abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        pass
    
    @abc.abstractmethod
    async def run(self, context: PluginContext) -> PluginResult:
        """Execute the plugin analysis."""
        pass
    
    def is_enabled(self) -> bool:
        """Check if plugin is enabled."""
        return self._enabled and self.metadata.enabled
    
    def enable(self) -> None:
        """Enable the plugin."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable the plugin."""
        self._enabled = False
    
    async def validate_context(self, context: PluginContext) -> bool:
        """Validate that context meets plugin requirements."""
        return True
    
    def create_result(self, plugin_name: str = None) -> PluginResult:
        """Create a new plugin result."""
        name = plugin_name or self.metadata.name
        return PluginResult(plugin_name=name, findings=[])
    
    def calculate_confidence(self, base_confidence: float, 
                           contributing_factors: List[str],
                           penalty_factors: List[str] = None) -> ConfidenceFactors:
        """Calculate confidence with detailed factors."""
        penalty_factors = penalty_factors or []
        
        # Apply penalties
        final_confidence = base_confidence
        for penalty in penalty_factors:
            final_confidence -= 5.0  # Each penalty reduces confidence by 5%
        
        # Apply bonuses for contributing factors
        bonus = min(len(contributing_factors) * 2.0, 20.0)  # Max 20% bonus
        final_confidence += bonus
        
        # Clamp to valid range
        final_confidence = max(0.0, min(100.0, final_confidence))
        
        return ConfidenceFactors(
            base_confidence=base_confidence,
            contributing_factors=contributing_factors,
            penalty_factors=penalty_factors,
            final_confidence=final_confidence
        )
    
    def create_risk_metrics(self, confidence_score: float,
                          exploitation_likelihood: Union[str, ExploitationLikelihood],
                          stability_score: float,
                          exposure_level: Union[str, ExposureLevel],
                          contributing_factors: List[str]) -> RiskMetrics:
        """Create standardized risk metrics."""
        if isinstance(exploitation_likelihood, str):
            exploitation_likelihood = ExploitationLikelihood(exploitation_likelihood.lower())
        
        if isinstance(exposure_level, str):
            exposure_level = ExposureLevel(exposure_level.lower())
        
        return RiskMetrics(
            confidence_score=confidence_score,
            exploitation_likelihood=exploitation_likelihood,
            stability_score=stability_score,
            exposure_level=exposure_level,
            contributing_factors=contributing_factors,
            risk_weight=self.metadata.risk_weight
        )