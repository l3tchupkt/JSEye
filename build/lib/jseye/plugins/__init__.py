"""Plugin system for JSEye v2.1 - Extensible Intelligence Framework."""

from .base import BasePlugin, PluginMetadata, PluginContext, PluginResult
from .manager import PluginManager

__all__ = ['BasePlugin', 'PluginMetadata', 'PluginContext', 'PluginResult', 'PluginManager']