"""Regression tests verifying real-world UAT fixes.

Covers:
- ast_analysis_plugin loading and execution
- JSEyeLogger *args format handling
- HTMLReportGenerator rendering with complete & partial statistics
- CLI argument parsing including --install-tools and -v
"""

import pytest

from jseye.cli import create_parser
from jseye.core.logging import get_logger
from jseye.plugins.ast_analysis_plugin import ASTAnalysisPlugin
from jseye.plugins.manager import PluginManager
from jseye.report.html_report import HTMLReportGenerator


def test_ast_analysis_plugin_metadata():
    """Verify ASTAnalysisPlugin initializes cleanly with absolute imports."""
    plugin = ASTAnalysisPlugin()
    meta = plugin.metadata
    assert meta.name == "ast_analysis"
    assert meta.version == "1.0.0"
    assert meta.category.value == "analysis"


@pytest.mark.asyncio
async def test_plugin_manager_loads_all_plugins():
    """Verify PluginManager loads all 6 built-in plugins without import errors."""
    pm = PluginManager()
    await pm.load_plugins()
    assert len(pm.plugins) >= 6
    assert "ast_analysis" in pm.plugins
    assert "api_intelligence" in pm.plugins
    assert "secret_detection" in pm.plugins
    assert "dom_flow_analysis" in pm.plugins
    assert "cve_intelligence" in pm.plugins
    assert "google_api_key_validator" in pm.plugins


def test_jseye_logger_format_args():
    """Verify JSEyeLogger handles *args safely like standard logging."""
    logger = get_logger("test_uat_logger")
    # Should not raise TypeError when called with format arguments
    logger.info("Found %d items in %s", 5, "http://example.com")
    logger.warning("Warning %d code on %s", 404, "http://example.com")
    logger.error("Error %s occurred: %d", "timeout", 504)
    logger.debug("Debug value: %s", "details")


def test_html_report_generator_handles_missing_keys():
    """Verify HTMLReportGenerator renders successfully even when statistics are minimal."""
    gen = HTMLReportGenerator()
    minimal_results = {
        "target": "https://example.com",
        "statistics": {},
        "secrets": [],
        "endpoints": [],
        "vulnerabilities": [],
        "errors": []
    }
    html = gen.generate_report(minimal_results)
    assert "<!DOCTYPE html>" in html
    assert "example.com" in html

    exec_summary = gen.generate_executive_summary(minimal_results)
    assert "<!DOCTYPE html>" in exec_summary
    assert "example.com" in exec_summary


def test_html_report_generator_with_full_data():
    """Verify HTMLReportGenerator renders complete report with secrets and findings."""
    gen = HTMLReportGenerator()
    results = {
        "target": "https://target.local",
        "statistics": {
            "total_js_files": 2,
            "total_findings": 4,
            "total_secrets": 2,
            "total_endpoints": 3,
            "total_errors": 0,
            "total_js_size": 2048,
            "average_file_size": 1024,
            "risk_distribution": {"Critical": 1, "High": 1, "Medium": 0, "Low": 0},
            "file_sources": {"crawler": 2},
            "secret_types": {"google_api_key": 1, "stripe_key": 1}
        },
        "secrets": [
            {
                "rule_id": "google_api_key",
                "risk_level": "Critical",
                "description": "Google API Key",
                "source_file": "app.js",
                "value_masked": "AIzaSy***"
            }
        ],
        "endpoints": ["/api/v1/users", "/api/v1/auth"],
        "vulnerabilities": [],
        "errors": []
    }
    html = gen.generate_report(results)
    assert "<!DOCTYPE html>" in html
    assert "target.local" in html
    assert "Google API Key" in html

    exec_summary = gen.generate_executive_summary(results)
    assert "Critical Secret Exposure" in exec_summary


def test_cli_flags():
    """Verify CLI parser supports all required flags."""
    parser = create_parser()
    args = parser.parse_args(["https://target.com", "-v", "--install-tools", "--no-subs", "--active"])
    assert args.target == "https://target.com"
    assert args.verbose is True
    assert args.install_tools is True
    assert args.no_subs is True
    assert args.active is True
