"""Plugin system for JSEye v2.1 - Extensible Intelligence Framework."""

from .base import BasePlugin, PluginContext, PluginMetadata, PluginResult
from .manager import PluginManager

__all__ = ['BasePlugin', 'PluginContext', 'PluginManager', 'PluginMetadata', 'PluginResult']
