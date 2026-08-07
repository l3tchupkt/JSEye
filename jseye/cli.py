"""Command-line interface for JSEye v2.1 - Plugin Architecture."""

import argparse
import asyncio
import os
import sys
from datetime import datetime
from typing import List, Dict, Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel

from .version import __version__
from .installer import ToolInstaller
from .core.banner import print_banner_async
from .core.plugin_crawler import PluginBasedCrawler
from .plugins.manager import PluginManager
from .core.profiling_engine import ProfilingEngine
from .core.graph_engine import GraphEngine
from .report.json_report import JSONReportGenerator
from .report.html_report import HTMLReportGenerator


console = Console()


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=f'JSEye v{__version__} - JavaScript Intelligence & Attack Surface Discovery Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Bug Hunter Examples:
  jseye https://target.com                              # Full auto-scoped recursive scan
  jseye https://target.com --no-subs                    # Skip subdomain enum, target host only
  jseye https://target.com --active                     # Enable active parameter mutation probing
  jseye https://target.com --max-depth 5                # Limit recursion to 5 levels
  jseye https://target.com --max-requests 500           # Cap total requests at 500
  jseye https://target.com --all                        # Complete scan with ALL features
  jseye https://target.com --actionable                 # Show only exploitable findings
  jseye https://target.com --export-ffuf ffuf.sh        # Generate ffuf-ready wordlists
  jseye https://target.com --compare baseline.json      # Compare against previous scan
  jseye https://target.com --show-all                   # Disable noise filtering
  jseye https://target.com --verbose                    # Show low-confidence findings
        """
    )

    # Positional argument
    parser.add_argument(
        'target',
        nargs='?',
        help='Target domain/URL or file containing domains'
    )

    # Hunter-focused modes
    parser.add_argument(
        '--all',
        action='store_true',
        help='Complete scan with all features enabled and all exports generated (ultimate hunter mode)'
    )
    
    parser.add_argument(
        '--actionable',
        action='store_true',
        help='Show only exploitable findings (recommended for hunters)'
    )

    parser.add_argument(
        '--aggressive-filter',
        action='store_true',
        default=True,
        help='Enable aggressive noise filtering (default: enabled)'
    )

    parser.add_argument(
        '--show-all',
        action='store_true',
        help='Disable noise filtering - show all findings'
    )

    # Export options for hunters
    parser.add_argument(
        '--export-wordlist',
        help='Export endpoint wordlist to file'
    )

    parser.add_argument(
        '--export-params',
        help='Export parameter wordlist to file'
    )

    parser.add_argument(
        '--export-ffuf',
        help='Export ffuf-ready commands to file'
    )

    parser.add_argument(
        '--export-curl',
        help='Export cURL commands to file'
    )

    parser.add_argument(
        '--export-burp',
        help='Export Burp-compatible site map XML to file'
    )

    parser.add_argument(
        '--export-nuclei',
        help='Export Nuclei templates to file'
    )

    # Output options
    parser.add_argument(
        '-o', '--output',
        help='Output directory (default: jseye_output_<timestamp>)',
        default=None
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Generate JSON report (default: enabled)'
    )

    parser.add_argument(
        '--html',
        action='store_true',
        help='Generate HTML report (default: enabled)'
    )

    parser.add_argument(
        '--no-json',
        action='store_true',
        help='Disable JSON report generation'
    )

    parser.add_argument(
        '--no-html',
        action='store_true',
        help='Disable HTML report generation'
    )

    # Scan configuration
    parser.add_argument(
        '--threads',
        type=int,
        default=20,
        help='Number of concurrent threads (default: 20)'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )

    parser.add_argument(
        '--headless',
        action='store_true',
        help='Enable headless browser analysis (slower but more thorough)'
    )

    # Plugin management
    parser.add_argument(
        '--list-plugins',
        action='store_true',
        help='List all available plugins and exit'
    )

    parser.add_argument(
        '--disable-plugin',
        action='append',
        help='Disable specific plugin (can be used multiple times)'
    )

    parser.add_argument(
        '--enable-plugin',
        action='append',
        help='Enable specific plugin (can be used multiple times)'
    )

    # Performance profiling
    parser.add_argument(
        '--profile-scan',
        action='store_true',
        help='Enable detailed performance profiling'
    )

    # Attack surface graph
    parser.add_argument(
        '--generate-graph',
        action='store_true',
        help='Generate attack surface relationship graph'
    )

    # Target comparison
    parser.add_argument(
        '--compare',
        help='Compare with another target (requires two targets)'
    )

    # Feature toggles (all enabled by default)
    parser.add_argument(
        '--no-subs',
        action='store_true',
        help='Skip subdomain enumeration (skip subfinder entirely)'
    )

    parser.add_argument(
        '--no-wayback',
        action='store_true',
        help='Disable Wayback Machine integration'
    )

    parser.add_argument(
        '--no-gau',
        action='store_true',
        help='Disable GAU integration'
    )

    parser.add_argument(
        '--no-secrets',
        action='store_true',
        help='Disable secret detection'
    )

    parser.add_argument(
        '--no-api',
        action='store_true',
        help='Disable API analysis'
    )

    # Active probing modes (default: passive)
    parser.add_argument(
        '--active',
        action='store_true',
        help='Enable active probing: baseline + parameter mutation, reflection/CORS/auth detection'
    )

    parser.add_argument(
        '--intruder-lite',
        action='store_true',
        dest='active',
        help='Alias for --active'
    )

    parser.add_argument(
        '--aggressive',
        action='store_true',
        help='Enable aggressive active probing with extended fuzz payload set (implies --active)'
    )

    # Recursion control (unlimited by default)
    parser.add_argument(
        '--max-depth',
        type=int,
        default=None,
        help='Maximum crawl recursion depth (default: unlimited)'
    )

    parser.add_argument(
        '--max-requests',
        type=int,
        default=None,
        help='Maximum total HTTP requests (default: unlimited)'
    )

    # Output control
    parser.add_argument(
        '--silent',
        action='store_true',
        help='Silent mode - minimal output'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output - show low-confidence findings'
    )

    # Version
    parser.add_argument(
        '--version',
        action='version',
        version=f'JSEye {__version__}'
    )

    return parser



def setup_output_directory(output_dir: str = None) -> str:
    """Set up output directory in current working directory."""
    if not output_dir:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"jseye_output_{timestamp}"
    
    # Ensure output directory is relative to current working directory
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(os.getcwd(), output_dir)
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    except Exception as e:
        console.print(f"[red]Failed to create output directory: {e}")
        sys.exit(1)


def is_file(target: str) -> bool:
    """Check if target is a file."""
    return os.path.isfile(target)


def read_targets_from_file(file_path: str) -> List[str]:
    """Read targets from file."""
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        return targets
    except Exception as e:
        console.print(f"[red]Failed to read targets from file: {e}")
        sys.exit(1)


def create_scan_config(args) -> Dict[str, Any]:
    """Create scan configuration from arguments."""
    aggressive = getattr(args, 'aggressive', False)
    active = getattr(args, 'active', False) or aggressive
    return {
        'threads': args.threads,
        'timeout': args.timeout,
        'wayback': not getattr(args, 'no_wayback', False),
        'gau': not getattr(args, 'no_gau', False),
        'katana': True,
        # --no-subs disables subfinder completely
        'subfinder': not getattr(args, 'no_subs', False),
        'hakrawler': True,
        'linkfinder': True,
        'secrets': not getattr(args, 'no_secrets', False),
        'api_analysis': not getattr(args, 'no_api', False),
        'headless': getattr(args, 'headless', False),
        'verbose': getattr(args, 'verbose', False),
        'silent': getattr(args, 'silent', False),
        'profile_scan': getattr(args, 'profile_scan', False),
        'generate_graph': getattr(args, 'generate_graph', False),
        'disabled_plugins': getattr(args, 'disable_plugin', []) or [],
        'enabled_plugins': getattr(args, 'enable_plugin', []) or [],
        'actionable': getattr(args, 'actionable', False),
        'aggressive_filter': getattr(args, 'aggressive_filter', True),
        'show_all': getattr(args, 'show_all', False),
        # v3.0.1 recursive + active probing config
        'max_depth': getattr(args, 'max_depth', None),
        'max_requests': getattr(args, 'max_requests', None),
        'active_probing': active,
        'aggressive_probing': aggressive,
        'output_dir': None,  # Set later from output_dir arg
    }


async def list_plugins() -> None:
    """List all available plugins."""
    console.print("[cyan]Loading plugins...[/cyan]")
    
    plugin_manager = PluginManager()
    await plugin_manager.load_plugins()
    
    plugins_info = plugin_manager.list_plugins()
    
    if not plugins_info:
        console.print("[yellow]No plugins found.[/yellow]")
        return
    
    table = Table(title="Available Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Version", justify="center")
    table.add_column("Category", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Description")
    
    for plugin in plugins_info:
        status = "[green]Enabled[/green]" if plugin['enabled'] else "[red]Disabled[/red]"
        
        table.add_row(
            plugin['name'],
            plugin['version'],
            plugin['category'],
            status,
            plugin['description'][:60] + "..." if len(plugin['description']) > 60 else plugin['description']
        )
    
    console.print(table)
    console.print(f"\n[cyan]Total plugins: {len(plugins_info)}[/cyan]")
    console.print(f"[green]Enabled: {len([p for p in plugins_info if p['enabled']])}[/green]")
    console.print(f"[red]Disabled: {len([p for p in plugins_info if not p['enabled']])}[/red]")


async def scan_with_plugins(target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Scan using the new plugin architecture."""
    # Use the new plugin-based crawler
    crawler = PluginBasedCrawler(config)
    return await crawler.scan_target(target)


async def compare_targets(target1: str, target2: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two targets and generate diff report."""
    console.print(f"[cyan]Comparing {target1} vs {target2}...[/cyan]")
    
    # Scan both targets
    result1 = await scan_with_plugins(target1, config)
    result2 = await scan_with_plugins(target2, config)
    
    # Generate comparison
    comparison = {
        'target1': target1,
        'target2': target2,
        'scan1': result1,
        'scan2': result2,
        'differences': {
            'endpoints': {
                'target1_only': list(set(result1.get('endpoints', [])) - set(result2.get('endpoints', []))),
                'target2_only': list(set(result2.get('endpoints', [])) - set(result1.get('endpoints', []))),
                'common': list(set(result1.get('endpoints', [])) & set(result2.get('endpoints', [])))
            },
            'secrets': {
                'target1_count': len(result1.get('secrets', [])),
                'target2_count': len(result2.get('secrets', [])),
                'difference': len(result1.get('secrets', [])) - len(result2.get('secrets', []))
            },
            'vulnerabilities': {
                'target1_count': len(result1.get('vulnerabilities', [])),
                'target2_count': len(result2.get('vulnerabilities', [])),
                'difference': len(result1.get('vulnerabilities', [])) - len(result2.get('vulnerabilities', []))
            }
        },
        'risk_delta': _calculate_risk_delta(result1, result2)
    }
    
    return comparison


def _calculate_risk_delta(result1: Dict[str, Any], result2: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate risk difference between two scan results."""
    stats1 = result1.get('statistics', {})
    stats2 = result2.get('statistics', {})
    
    risk1 = stats1.get('risk_distribution', {})
    risk2 = stats2.get('risk_distribution', {})
    
    return {
        'critical_delta': risk1.get('Critical', 0) - risk2.get('Critical', 0),
        'high_delta': risk1.get('High', 0) - risk2.get('High', 0),
        'medium_delta': risk1.get('Medium', 0) - risk2.get('Medium', 0),
        'low_delta': risk1.get('Low', 0) - risk2.get('Low', 0),
        'overall_risk_change': 'increased' if sum(risk1.values()) > sum(risk2.values()) else 'decreased'
    }


async def scan_single_target(target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Scan a single target."""
    return await scan_with_plugins(target, config)


async def scan_multiple_targets(targets: List[str], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan multiple targets."""
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        for i, target in enumerate(targets, 1):
            task = progress.add_task(f"Scanning {target} ({i}/{len(targets)})", total=None)
            
            result = await scan_with_plugins(target, config)
            results.append(result)
            
            progress.remove_task(task)
    
    return results


def generate_reports(scan_results: List[Dict[str, Any]], output_dir: str, 
                    generate_json: bool = True, generate_html: bool = True):
    """Generate scan reports in the specified output directory."""
    json_generator = JSONReportGenerator()
    html_generator = HTMLReportGenerator()
    
    # Show relative path from current directory for better UX
    rel_output_dir = os.path.relpath(output_dir, os.getcwd())
    
    for i, result in enumerate(scan_results):
        target = result.get('target', f'target_{i}')
        safe_target = "".join(c for c in target if c.isalnum() or c in ('-', '_', '.'))
        
        # Generate JSON report
        if generate_json:
            json_file = os.path.join(output_dir, f"{safe_target}_report.json")
            rel_json_file = os.path.join(rel_output_dir, f"{safe_target}_report.json")
            try:
                json_generator.generate_report(result, json_file)
                console.print(f"[green][+] JSON report saved: {rel_json_file}")
            except Exception as e:
                console.print(f"[red][-] Failed to generate JSON report: {e}")
        
        # Generate HTML report
        if generate_html:
            html_file = os.path.join(output_dir, f"{safe_target}_report.html")
            rel_html_file = os.path.join(rel_output_dir, f"{safe_target}_report.html")
            try:
                html_generator.generate_report(result, html_file)
                console.print(f"[green][+] HTML report saved: {rel_html_file}")
            except Exception as e:
                console.print(f"[red][-] Failed to generate HTML report: {e}")
        
        # Generate executive summary
        if generate_html:
            exec_file = os.path.join(output_dir, f"{safe_target}_executive_summary.html")
            rel_exec_file = os.path.join(rel_output_dir, f"{safe_target}_executive_summary.html")
            try:
                exec_summary = html_generator.generate_executive_summary(result)
                with open(exec_file, 'w', encoding='utf-8') as f:
                    f.write(exec_summary)
                console.print(f"[green][+] Executive summary saved: {rel_exec_file}")
            except Exception as e:
                console.print(f"[red][-] Failed to generate executive summary: {e}")
        
        # Generate attack surface graph if available
        if result.get('attack_surface_graph'):
            graph_file = os.path.join(output_dir, f"{safe_target}_attack_surface_graph.json")
            rel_graph_file = os.path.join(rel_output_dir, f"{safe_target}_attack_surface_graph.json")
            try:
                import json
                with open(graph_file, 'w') as f:
                    json.dump(result['attack_surface_graph'], f, indent=2, default=str)
                console.print(f"[green][+] Attack surface graph saved: {rel_graph_file}")
            except Exception as e:
                console.print(f"[red][-] Failed to generate attack surface graph: {e}")
    
    # Show summary of generated reports
    if generate_json and generate_html:
        console.print(f"\n[cyan][*] Generated both JSON and HTML reports in: {rel_output_dir}")
    elif generate_json:
        console.print(f"\n[cyan][*] Generated JSON reports in: {rel_output_dir}")
    elif generate_html:
        console.print(f"\n[cyan][*] Generated HTML reports in: {rel_output_dir}")
    
    console.print(f"[dim]Full path: {output_dir}")


def print_scan_summary(scan_results: List[Dict[str, Any]]):
    """Print scan summary to console."""
    table = Table(title=f"JSEye v{__version__} - Bug Hunter Scan Summary")
    
    table.add_column("Target", style="cyan")
    table.add_column("JS Files", justify="right")
    table.add_column("Findings", justify="right", style="yellow")
    table.add_column("Secrets", justify="right", style="red")
    table.add_column("Endpoints", justify="right")
    table.add_column("Parameters", justify="right", style="green")
    table.add_column("High Priority", justify="right", style="bold red")
    table.add_column("Risk Level", justify="center")
    table.add_column("Status")
    
    for result in scan_results:
        stats = result.get('statistics', {})
        target = result.get('target', 'Unknown')
        
        # Calculate risk level
        risk_dist = stats.get('risk_distribution', {})
        if risk_dist.get('Critical', 0) > 0:
            risk_level = "[red]Critical[/red]"
        elif risk_dist.get('High', 0) > 0:
            risk_level = "[yellow]High[/yellow]"
        elif risk_dist.get('Medium', 0) > 0:
            risk_level = "[blue]Medium[/blue]"
        else:
            risk_level = "[green]Low[/green]"
        
        # Count high priority findings
        high_priority_count = 0
        prioritized_endpoints = result.get('prioritized_endpoints', {})
        prioritized_secrets = result.get('prioritized_secrets', {})
        prioritized_vulnerabilities = result.get('prioritized_vulnerabilities', {})
        
        high_priority_count += len(prioritized_endpoints.get('high', []))
        high_priority_count += len(prioritized_secrets.get('high', []))
        high_priority_count += len(prioritized_vulnerabilities.get('high', []))
        
        errors = result.get('errors', [])
        plugin_errors = []
        
        # Check for plugin-level errors
        plugin_results = result.get('plugin_results', {})
        for plugin_name, plugin_result in plugin_results.items():
            if isinstance(plugin_result, dict) and plugin_result.get('errors'):
                plugin_errors.extend(plugin_result.get('errors'))
            elif hasattr(plugin_result, 'errors') and plugin_result.errors:
                plugin_errors.extend(plugin_result.errors)
        
        # Combine all errors
        all_errors = errors + plugin_errors
        has_errors = all_errors and len(all_errors) > 0
        
        status = "[green][+] Success[/green]" if not has_errors else "[red][-] Errors[/red]"
        
        table.add_row(
            target,
            str(stats.get('total_js_files', 0)),
            str(stats.get('total_findings', 0)),
            str(stats.get('total_secrets', 0)),
            str(stats.get('total_endpoints', 0)),
            str(stats.get('total_parameters', 0)),
            str(high_priority_count),
            risk_level,
            status
        )
    
    console.print(table)
    
    # Print enhanced details
    for result in scan_results:
        print_enhanced_summary(result)


def print_enhanced_summary(result: Dict[str, Any]):
    """Print enhanced summary with additional details."""
    from rich.panel import Panel
    from rich.columns import Columns
    
    target = result.get('target', 'Unknown')
    
    # Google API Key Validation Results
    google_api_keys = result.get('statistics', {}).get('google_api_keys', {})
    if google_api_keys and google_api_keys.get('total_found', 0) > 0:
        valid = google_api_keys.get('valid', 0)
        restricted = google_api_keys.get('restricted', 0)
        invalid = google_api_keys.get('invalid', 0)
        total = google_api_keys.get('total_found', 0)
        color = "bold red" if valid > 0 else ("bold yellow" if restricted > 0 else "bold green")
        console.print(f"\n[{color}][KEY] Google API Keys Detected & Validated:[/{color}] {total} found")
        if valid:
            console.print(f"  [red][!] VALID (live): {valid}[/red]  <- Rotate immediately")
        if restricted:
            console.print(f"  [yellow][~] Restricted: {restricted}[/yellow]  <- Key exists, has restrictions")
        if invalid:
            console.print(f"  [green][+] Invalid/Dead: {invalid}[/green]")

    # API Keys found
    api_key_findings = result.get('api_key_findings', [])
    if api_key_findings:
        console.print(f"\n[bold red][!] API Keys Found in URLs:[/bold red]")
        for finding in api_key_findings[:5]:  # Show first 5
            console.print(f"  [*] Parameter: [yellow]{finding.get('parameter')}[/yellow]")
            console.print(f"    Value: [red]{finding.get('value', '')[:50]}...[/red]")
    
    # Libraries detected
    version_analysis = result.get('version_analysis', {})
    if version_analysis and version_analysis.get('total_libraries', 0) > 0:
        console.print(f"\n[bold cyan][*] Libraries Detected:[/bold cyan]")
        by_library = version_analysis.get('by_library', {})
        for lib in sorted(version_analysis.get('unique_libraries', []))[:10]:
            versions = by_library.get(lib, [])
            unique_versions = list(set(versions))[:2]
            console.print(f"  [+] {lib}: {', '.join(unique_versions)}")
    
    # CVE Results
    cve_results = result.get('cve_results', {})
    if cve_results and cve_results.get('total_cves', 0) > 0:
        console.print(f"\n[bold red]🔴 Vulnerabilities Found:[/bold red]")
        console.print(f"  Total CVEs: {cve_results['total_cves']}")
        console.print(f"  Critical: {cve_results.get('critical', 0)}")
        console.print(f"  High: {cve_results.get('high', 0)}")
        console.print(f"  Medium: {cve_results.get('medium', 0)}")
        console.print(f"  Low: {cve_results.get('low', 0)}")
        
        # Show vulnerable libraries
        vulnerabilities = cve_results.get('vulnerabilities', [])
        if vulnerabilities:
            console.print(f"\n  [yellow]Vulnerable Libraries:[/yellow]")
            for vuln in vulnerabilities[:5]:  # Show first 5
                lib = vuln.get('library', 'unknown')
                ver = vuln.get('version', 'unknown')
                cve_count = vuln.get('total_cves', 0)
                console.print(f"    • {lib} {ver}: {cve_count} CVE(s)")
    
    # Dependency Confusion Results
    dep_analysis = result.get('dependency_analysis', {})
    if dep_analysis and dep_analysis.get('success'):
        stats = dep_analysis.get('statistics', {})
        vulnerable_deps = dep_analysis.get('vulnerable_dependencies', [])
        
        if stats.get('vulnerable_count', 0) > 0:
            console.print(f"\n[bold red]⚠️  Dependency Confusion Risks:[/bold red]")
            console.print(f"  Total Dependencies: {stats.get('total_dependencies', 0)}")
            console.print(f"  Vulnerable: {stats['vulnerable_count']}")
            console.print(f"  Critical: {stats.get('critical_count', 0)}")
            console.print(f"  High: {stats.get('high_count', 0)}")
            console.print(f"  Confusion Risk: {stats.get('confusion_risk', 0)}")
            console.print(f"  Missing Packages: {stats.get('missing_packages', 0)}")
            
            # Show top vulnerable dependencies
            if vulnerable_deps:
                console.print(f"\n  [yellow]Top Vulnerable Dependencies:[/yellow]")
                for dep in vulnerable_deps[:5]:  # Show first 5
                    name = dep.get('name', 'unknown')
                    severity = dep.get('severity', 'UNKNOWN')
                    risk_factors = dep.get('risk_factors', [])
                    risk_desc = risk_factors[0] if risk_factors else 'Unknown risk'
                    console.print(f"    • {name} [{severity}]: {risk_desc}")
    
    # API Endpoints detected
    api_endpoints = result.get('api_endpoints', [])
    if api_endpoints:
        console.print(f"\n[bold green]🌐 API Endpoints:[/bold green] {len(api_endpoints)} detected")
        api_analysis = result.get('api_analysis', {})
        if api_analysis:
            by_classification = api_analysis.get('by_classification', {})
            if by_classification:
                console.print(f"  [cyan]By Type:[/cyan]")
                for api_type, count in sorted(by_classification.items(), key=lambda x: x[1], reverse=True)[:5]:
                    console.print(f"    • {api_type}: {count}")
    
    # Swagger/OpenAPI specs found
    swagger_specs = result.get('swagger_specs', [])
    if swagger_specs:
        console.print(f"\n[bold magenta]📋 Swagger/OpenAPI Specs:[/bold magenta] {len(swagger_specs)} found")
        swagger_endpoints = result.get('swagger_endpoints', [])
        if swagger_endpoints:
            console.print(f"  Total API endpoints from specs: {len(swagger_endpoints)}")
        
        # Show spec details
        for spec in swagger_specs[:3]:  # Show first 3
            version = spec.get('version', 'unknown')
            endpoint_count = spec.get('endpoint_count', 0)
            path = spec.get('path', '')
            console.print(f"  • {path} (v{version}): {endpoint_count} endpoints")
            if by_classification:
                console.print(f"  [cyan]By Type:[/cyan]")
                for api_type, count in sorted(by_classification.items(), key=lambda x: x[1], reverse=True)[:5]:
                    console.print(f"    [+] {api_type}: {count}")
    
    # Source maps found
    js_files = result.get('js_files', [])
    sourcemap_count = len([f for f in js_files if f.get('type') == 'sourcemap'])
    if sourcemap_count > 0:
        console.print(f"\n[bold blue][*] Source Maps:[/bold blue] {sourcemap_count} found (unminified code available)")
    
    # API Documentation
    api_docs = result.get('api_documentation', [])
    if api_docs:
        console.print(f"\n[bold magenta][*] API Documentation:[/bold magenta]")
        for doc in api_docs[:3]:
            console.print(f"  [+] {doc}")


async def handle_export_options(args, scan_results: List[Dict[str, Any]], output_dir: str):
    """Handle hunter-focused export options."""
    from .core.export_engine import ExportEngine
    
    # Check if we should export (either explicit flags or --all mode)
    all_mode = getattr(args, '_all_mode', False)
    
    if not all_mode and not any([args.export_wordlist, args.export_params, args.export_ffuf, 
                                  args.export_curl, args.export_burp, args.export_nuclei]):
        return
    
    export_engine = ExportEngine()
    
    # Combine all scan results for export - include ALL data
    combined_results = {
        'targets': [],
        'all_findings': [],
        'endpoints': [],
        'secrets': [],
        'vulnerabilities': [],
        'parameters': [],
        'linkfinder_endpoints': [],
        'api_endpoints': [],
        'api_key_findings': [],
        'version_analysis': {},
        'js_files': [],
        'api_analysis': {},
        'api_documentation': [],
        'cve_results': {}
    }
    
    # Merge data from all scan results
    for result in scan_results:
        combined_results['targets'].append(result.get('target', ''))
        combined_results['all_findings'].extend(result.get('all_findings', []))
        combined_results['endpoints'].extend(result.get('endpoints', []))
        combined_results['secrets'].extend(result.get('secrets', []))
        combined_results['vulnerabilities'].extend(result.get('vulnerabilities', []))
        combined_results['parameters'].extend(result.get('parameters', []))
        combined_results['linkfinder_endpoints'].extend(result.get('linkfinder_endpoints', []))
        combined_results['api_endpoints'].extend(result.get('api_endpoints', []))
        combined_results['api_key_findings'].extend(result.get('api_key_findings', []))
        combined_results['js_files'].extend(result.get('js_files', []))
        combined_results['api_documentation'].extend(result.get('api_documentation', []))
        
        # Merge version analysis
        version_analysis = result.get('version_analysis', {})
        if version_analysis:
            if not combined_results['version_analysis']:
                combined_results['version_analysis'] = version_analysis
            else:
                # Merge unique libraries
                existing_libs = set(combined_results['version_analysis'].get('unique_libraries', []))
                new_libs = set(version_analysis.get('unique_libraries', []))
                combined_results['version_analysis']['unique_libraries'] = list(existing_libs | new_libs)
                
                # Merge detections
                combined_results['version_analysis'].setdefault('detections', []).extend(
                    version_analysis.get('detections', [])
                )
        
        # Merge API analysis
        api_analysis = result.get('api_analysis', {})
        if api_analysis:
            if not combined_results['api_analysis']:
                combined_results['api_analysis'] = api_analysis
            else:
                # Merge by_classification
                by_class = combined_results['api_analysis'].setdefault('by_classification', {})
                for key, val in api_analysis.get('by_classification', {}).items():
                    by_class[key] = by_class.get(key, 0) + val
        
        # Merge CVE results
        cve_results = result.get('cve_results', {})
        if cve_results:
            if not combined_results['cve_results']:
                combined_results['cve_results'] = cve_results
            else:
                # Merge CVE counts
                combined_results['cve_results']['total_cves'] = (
                    combined_results['cve_results'].get('total_cves', 0) + 
                    cve_results.get('total_cves', 0)
                )
                for severity in ['critical', 'high', 'medium', 'low']:
                    combined_results['cve_results'][severity] = (
                        combined_results['cve_results'].get(severity, 0) + 
                        cve_results.get(severity, 0)
                    )
                combined_results['cve_results'].setdefault('vulnerabilities', []).extend(
                    cve_results.get('vulnerabilities', [])
                )
    
    # Set target for single-target scans
    if len(combined_results['targets']) == 1:
        combined_results['target'] = combined_results['targets'][0]
    else:
        combined_results['target'] = ', '.join(combined_results['targets'])
    
    # If --all mode, set default export paths
    if all_mode:
        if not args.export_wordlist:
            args.export_wordlist = 'wordlist_endpoints.txt'
        if not args.export_params:
            args.export_params = 'wordlist_parameters.txt'
        if not args.export_ffuf:
            args.export_ffuf = 'ffuf_commands.txt'
        if not args.export_curl:
            args.export_curl = 'curl_commands.sh'
        if not args.export_burp:
            args.export_burp = 'burp_sitemap.xml'
        if not args.export_nuclei:
            args.export_nuclei = 'nuclei_templates.yaml'
    
    # Apply prioritization and filtering if actionable mode
    if getattr(args, 'actionable', False):
        from .core.prioritization import PrioritizationEngine
        prioritizer = PrioritizationEngine()
        combined_results = prioritizer.prioritize_findings(combined_results)
        
        # Filter to only high priority findings
        combined_results['endpoints'] = combined_results.get('prioritized_endpoints', {}).get('high', [])
        combined_results['secrets'] = combined_results.get('prioritized_secrets', {}).get('high', [])
        combined_results['vulnerabilities'] = combined_results.get('prioritized_vulnerabilities', {}).get('high', [])
    
    # Apply noise filtering unless show-all is specified
    if not getattr(args, 'show_all', False):
        from .core.prioritization import PrioritizationEngine
        prioritizer = PrioritizationEngine()
        aggressive = getattr(args, 'aggressive_filter', True)
        
        if combined_results.get('endpoints'):
            combined_results['endpoints'] = prioritizer.filter_noise(combined_results['endpoints'], aggressive)
        if combined_results.get('all_findings'):
            combined_results['all_findings'] = prioritizer.filter_noise(combined_results['all_findings'], aggressive)
    
    # Export wordlist
    if args.export_wordlist:
        export_path = args.export_wordlist if os.path.isabs(args.export_wordlist) else os.path.join(output_dir, args.export_wordlist)
        if export_engine.export_wordlist(combined_results, export_path):
            console.print(f"[green][+] Endpoint wordlist exported: {os.path.relpath(export_path, os.getcwd())}")
    
    # Export parameters
    if args.export_params:
        export_path = args.export_params if os.path.isabs(args.export_params) else os.path.join(output_dir, args.export_params)
        if export_engine.export_parameters(combined_results, export_path):
            console.print(f"[green][+] Parameter wordlist exported: {os.path.relpath(export_path, os.getcwd())}")
    
    # Export ffuf commands
    if args.export_ffuf:
        export_path = args.export_ffuf if os.path.isabs(args.export_ffuf) else os.path.join(output_dir, args.export_ffuf)
        if export_engine.export_ffuf(combined_results, export_path):
            console.print(f"[green][+] ffuf commands exported: {os.path.relpath(export_path, os.getcwd())}")
    
    # Export cURL commands
    if args.export_curl:
        export_path = args.export_curl if os.path.isabs(args.export_curl) else os.path.join(output_dir, args.export_curl)
        if export_engine.export_curl_commands(combined_results, export_path):
            console.print(f"[green][+] cURL commands exported: {os.path.relpath(export_path, os.getcwd())}")
    
    # Export Burp site map
    if args.export_burp:
        export_path = args.export_burp if os.path.isabs(args.export_burp) else os.path.join(output_dir, args.export_burp)
        if export_engine.export_burp(combined_results, export_path):
            console.print(f"[green][+] Burp site map exported: {os.path.relpath(export_path, os.getcwd())}")
    
    # Export Nuclei templates
    if args.export_nuclei:
        export_path = args.export_nuclei if os.path.isabs(args.export_nuclei) else os.path.join(output_dir, args.export_nuclei)
        if export_engine.export_nuclei_template(combined_results, export_path):
            console.print(f"[green][+] Nuclei templates exported: {os.path.relpath(export_path, os.getcwd())}")


async def main():
    """Main CLI function."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle plugin listing
    if getattr(args, 'list_plugins', False):
        await list_plugins()
        return
    
    # Validate target argument for other operations
    if not args.target:
        console.print("[red]Error: target argument is required[/red]")
        parser.print_help()
        sys.exit(1)
    
    # Print banner unless silent
    if not args.silent:
        await print_banner_async()

    # ---------------------------------------------------------------------------
    # Pre-flight: auto-install Go tools and Python packages on every run.
    # Already-installed tools are detected in < 1ms via PATH check.
    # ---------------------------------------------------------------------------
    if not args.silent:
        console.print("[cyan][*] Pre-flight check: verifying tools and dependencies...[/cyan]")

    try:
        from .installer import ToolInstaller
        from .os_detect import OSDetector

        installer = ToolInstaller()
        os_det = OSDetector()

        # Check Python deps first (fast)
        await installer.check_and_install_python_dependencies()

        # Build tool status table
        all_tools = ['gau', 'waybackurls', 'hakrawler', 'mantra', 'subfinder', 'katana']
        tool_status = {t: os_det.is_tool_installed(t) for t in all_tools}
        missing_tools = [t for t, ok in tool_status.items() if not ok]

        if not args.silent:
            status_table = Table(title="Tool Status", show_header=True, header_style="bold cyan")
            status_table.add_column("Tool", style="white")
            status_table.add_column("Status", justify="center")
            status_table.add_column("Purpose")

            tool_purposes = {
                'gau': 'URL discovery from archive/wayback',
                'waybackurls': 'Wayback Machine historical URL fetch',
                'hakrawler': 'Deep web crawler with JS support',
                'mantra': 'Secret scanning in HTTP responses',
                'subfinder': 'Passive subdomain discovery',
                'katana': 'Fast crawler with JavaScript rendering',
            }

            for tool in all_tools:
                ok = tool_status[tool]
                status_str = "[green][READY][/green]" if ok else "[yellow][INSTALLING][/yellow]"
                status_table.add_row(tool, status_str, tool_purposes.get(tool, ''))

            console.print(status_table)

        if missing_tools:
            if not args.silent:
                console.print(f"[yellow][!] Installing missing tools: {', '.join(missing_tools)}[/yellow]")
            await installer.install_external_tools()

        if not args.silent:
            console.print("[green][+] Pre-flight check complete[/green]\n")

    except Exception as _pf_exc:
        if not args.silent:
            console.print(f"[yellow][!] Pre-flight installer error (continuing): {_pf_exc}[/yellow]")

    # Handle --all flag (ultimate hunter mode)
    if getattr(args, 'all', False):
        if not args.silent:
            console.print("[cyan]Running complete scan with all features and exports enabled...[/cyan]\n")
        
        # Enable all features
        args.actionable = True
        args.headless = True
        args.profile_scan = True
        args.generate_graph = True
        args.verbose = True
        
        # Enable all collection sources
        args.wayback = True
        args.gau = True
        args.katana = True
        args.subfinder = True
        args.hakrawler = True
        args.linkfinder = True
        
        # Set up all export paths with default names
        if not args.output:
            args.output = None  # Will be auto-generated
        
        # We'll set export paths after output_dir is created
        args._all_mode = True  # Internal flag to trigger all exports
    
    # Handle comparison mode
    if getattr(args, 'compare', None):
        target1 = args.target
        target2 = args.compare
        
        if not args.silent:
            console.print(f"[cyan]Comparison mode: {target1} vs {target2}[/cyan]")
        
        # Set up output directory
        output_dir = setup_output_directory(args.output)
        if not args.silent:
            console.print(f"[cyan]Output directory: {output_dir}[/cyan]")
        
        # Create scan configuration
        config = create_scan_config(args)
        config['output_dir'] = output_dir
        
        try:
            # Perform comparison
            comparison_result = await compare_targets(target1, target2, config)
            
            # Generate comparison report
            comparison_file = os.path.join(output_dir, "comparison_report.json")
            with open(comparison_file, 'w') as f:
                import json
                json.dump(comparison_result, f, indent=2, default=str)
            
            if not args.silent:
                rel_comparison_file = os.path.relpath(comparison_file, os.getcwd())
                console.print(f"[green][+] Comparison report saved to: {rel_comparison_file}[/green]")
                console.print(f"[dim]Full path: {comparison_file}")
                
                # Print comparison summary
                diff = comparison_result['differences']
                console.print(f"\n[cyan]Comparison Summary:[/cyan]")
                console.print(f"Target 1 ({target1}): {diff['secrets']['target1_count']} secrets, {diff['vulnerabilities']['target1_count']} vulnerabilities")
                console.print(f"Target 2 ({target2}): {diff['secrets']['target2_count']} secrets, {diff['vulnerabilities']['target2_count']} vulnerabilities")
                console.print(f"Risk trend: {comparison_result['risk_delta']['overall_risk_change']}")
            
            return
            
        except Exception as e:
            console.print(f"[red]Comparison failed: {e}[/red]")
            sys.exit(1)
    
    # Regular scan mode
    # Check if target is file or single target
    if is_file(args.target):
        targets = read_targets_from_file(args.target)
        if not args.silent:
            console.print(f"[cyan]Loaded {len(targets)} targets from file")
    else:
        targets = [args.target]
    
    # Set up output directory
    output_dir = setup_output_directory(args.output)
    if not args.silent:
        console.print(f"[cyan]Output directory: {output_dir}")
    
    # Check tool dependencies and auto-install
    installer = ToolInstaller()
    
    # Auto-install missing tools
    missing_tools = installer.get_missing_tools()
    if missing_tools and not args.silent:
        console.print(f"[cyan]Auto-installing {len(missing_tools)} missing tool(s)...[/cyan]")
        await installer.auto_install_missing_tools()
    
    setup_success = await installer.setup_environment(auto_install=True)
    
    if not setup_success:
        missing_tools = installer.get_missing_tools()
        if missing_tools and not args.silent:
            console.print(f"[yellow]! Some tools unavailable: {', '.join(missing_tools)}[/yellow]")
    
    # Create scan configuration
    config = create_scan_config(args)
    config['output_dir'] = output_dir
    
    # Determine report formats (default to both JSON and HTML)
    generate_json = not args.no_json if hasattr(args, 'no_json') else True
    generate_html = not args.no_html if hasattr(args, 'no_html') else True
    
    # If user explicitly specified formats, respect their choice
    if args.json and not args.html:
        generate_html = False
    elif args.html and not args.json:
        generate_json = False
    
    try:
        # Perform scans
        if not args.silent:
            console.print(f"[cyan]Starting scan of {len(targets)} target(s)...[/cyan]")
        
        scan_results = []
        
        if len(targets) == 1:
            if not args.silent:
                console.print(f"[cyan]Scanning {targets[0]}...[/cyan]")
            result = await scan_single_target(targets[0], config)
            scan_results = [result]
            if not args.silent:
                console.print(f"[green]Scan completed for {targets[0]}[/green]")
        else:
            for i, target in enumerate(targets, 1):
                if not args.silent:
                    console.print(f"[cyan]Scanning {target} ({i}/{len(targets)})...[/cyan]")
                result = await scan_with_plugins(target, config)
                scan_results.append(result)
                if not args.silent:
                    console.print(f"[green]Completed {target} ({i}/{len(targets)})[/green]")
        
        # Handle hunter-focused exports
        await handle_export_options(args, scan_results, output_dir)
        
        # Generate reports
        if not args.silent:
            console.print("[cyan]Generating reports...")
        
        generate_reports(scan_results, output_dir, generate_json, generate_html)
        
        # Generate profiling report if enabled
        if config.get('profile_scan', False):
            for i, result in enumerate(scan_results):
                if 'profiling' in result:
                    profile_file = os.path.join(output_dir, f"profile_report_{i}.json")
                    with open(profile_file, 'w') as f:
                        import json
                        json.dump(result['profiling'], f, indent=2, default=str)
                    
                    if not args.silent:
                        rel_profile_file = os.path.relpath(profile_file, os.getcwd())
                        console.print(f"[green][+] Profiling report saved: {rel_profile_file}")
                        console.print(f"[dim]Full path: {profile_file}")
        
        # Print summary
        if not args.silent:
            print_scan_summary(scan_results)
            
            # Print key findings
            total_findings = sum(len(r.get('all_findings', [])) for r in scan_results)
            critical_findings = sum(len([f for f in r.get('all_findings', []) if f.get('severity') == 'critical']) for r in scan_results)
            
            if critical_findings > 0:
                console.print(Panel(
                    f"[red][ ! ]  CRITICAL: Found {critical_findings} critical findings that require immediate attention!",
                    title="Security Alert",
                    border_style="red"
                ))
            elif total_findings > 0:
                console.print(Panel(
                    f"[yellow]Found {total_findings} security findings. Review the detailed report for analysis.",
                    title="Security Notice",
                    border_style="yellow"
                ))
            else:
                console.print(Panel(
                    "[green][ x ] No critical security issues detected in JavaScript files.",
                    title="Scan Complete",
                    border_style="green"
                ))
        
        console.print(f"\n[green][+] Scan completed successfully! Results saved to: {os.path.relpath(output_dir, os.getcwd())}")
        console.print(f"[dim]Full path: {output_dir}")
        
        # Print --all mode summary
        if getattr(args, '_all_mode', False):
            console.print("\n[bold cyan]================================================================[/bold cyan]")
            console.print("[bold cyan]ULTIMATE HUNTER MODE - COMPLETE SCAN SUMMARY[/bold cyan]")
            console.print("[bold cyan]================================================================[/bold cyan]\n")
            
            console.print("[green]All features enabled:[/green]")
            console.print("  - Actionable findings mode")
            console.print("  - Headless browser analysis")
            console.print("  - Performance profiling")
            console.print("  - Attack surface graph generation")
            console.print("  - Verbose output with all findings\n")
            
            console.print("[green]All exports generated:[/green]")
            export_files = []
            if os.path.exists(os.path.join(output_dir, 'wordlist_endpoints.txt')):
                export_files.append("  - wordlist_endpoints.txt - Endpoint wordlist for fuzzing")
            if os.path.exists(os.path.join(output_dir, 'wordlist_parameters.txt')):
                export_files.append("  - wordlist_parameters.txt - Parameter wordlist")
            if os.path.exists(os.path.join(output_dir, 'ffuf_commands.txt')):
                export_files.append("  - ffuf_commands.txt - ffuf-ready fuzzing commands")
            if os.path.exists(os.path.join(output_dir, 'curl_commands.sh')):
                export_files.append("  - curl_commands.sh - Manual testing commands")
            if os.path.exists(os.path.join(output_dir, 'burp_sitemap.xml')):
                export_files.append("  - burp_sitemap.xml - Burp Suite site map")
            if os.path.exists(os.path.join(output_dir, 'nuclei_templates.yaml')):
                export_files.append("  - nuclei_templates.yaml - Nuclei templates")
            
            for export_file in export_files:
                console.print(export_file)
            
            console.print("\n[green]Reports generated:[/green]")
            if generate_json:
                console.print("  - JSON report - Machine-readable findings")
            if generate_html:
                console.print("  - HTML report - Human-readable analysis")
            
            console.print("\n[bold yellow]Next Steps:[/bold yellow]")
            console.print(f"  1. Review actionable findings in the HTML report")
            console.print(f"  2. Run: ffuf -u FUZZ -w {output_dir}/wordlist_endpoints.txt")
            console.print(f"  3. Import {output_dir}/burp_sitemap.xml into Burp Suite")
            console.print(f"  4. Execute: nuclei -t {output_dir}/nuclei_templates.yaml")
            console.print(f"  5. Test manually: bash {output_dir}/curl_commands.sh\n")
            
            console.print("[bold cyan]================================================================[/bold cyan]\n")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Scan failed: {e}")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


def cli_main():
    """Entry point for CLI."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}")
        sys.exit(1)


# Backward-compat alias (test suite uses this name)
create_arg_parser = create_parser


if __name__ == '__main__':
    cli_main()