# JSEye 👁️
**JavaScript Intelligence & Attack Surface Discovery Engine**

<img width="1536" height="1024" alt="JSEye Banner" src="https://github.com/user-attachments/assets/70359cd0-ada8-4f44-a01f-81b9841d8556" />

JSEye is a production-grade Python framework for comprehensive JavaScript security analysis and attack surface discovery. Built for bug bounty hunters, penetration testers, and security researchers who need deep JavaScript intelligence with minimal noise.

## 🚀 Features

- **Plugin Architecture**: Modular design with extensible plugin system
- **Multi-Engine Analysis**: AST parsing, DOM flow analysis, secret detection, and CVE intelligence
- **Advanced Secret Detection**: Context-aware detection with risk scoring and confidence analysis
- **API Intelligence**: Automated endpoint discovery and security assessment
- **Attack Surface Mapping**: Visual graph generation of application attack surface
- **Professional Reports**: Beautiful HTML and structured JSON reports
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Zero Dependencies**: Pure Python implementation with optional external integrations

## 📦 Installation

### From PyPI (Recommended)
```bash
pip install jseye
```

### Verify Installation
```bash
jseye --version
```

## 🛠️ Requirements

- **Python 3.8+** (core functionality)
- **Optional**: Selenium WebDriver (for headless browser analysis)
- **Optional**: External APIs (for enhanced CVE intelligence)

JSEye works out of the box with zero configuration required.

## 🎯 Usage

### Basic Scanning
```bash
# Scan a single target
jseye example.com

# Scan with custom output
jseye example.com --output results.json

# Scan multiple targets
jseye target1.com target2.com target3.com
```

### Advanced Options
```bash
# Enable all analysis engines
jseye example.com --threads 20 --timeout 30

# Generate HTML report
jseye example.com --output report.html --format html

# Enable headless browser analysis
jseye example.com --headless

# Custom configuration
jseye example.com --config custom_config.json
```

### Plugin Management
```bash
# List available plugins
jseye --list-plugins

# Enable specific plugins
jseye example.com --enable-plugin secret_detection

# Disable plugins
jseye example.com --disable-plugin cve_intelligence
```

## 🔄 Analysis Pipeline

JSEye executes a comprehensive multi-stage analysis:

```
Target Domain
     ↓
🕷️ JavaScript Discovery & Collection
     ↓
🧠 AST Analysis & Code Parsing
     ↓
🔐 Secret Detection & Risk Assessment
     ↓
🌊 DOM Flow Analysis & XSS Detection
     ↓
🔍 API Endpoint Discovery
     ↓
🛡️ CVE Intelligence & Vulnerability Assessment
     ↓
📊 Attack Surface Graph Generation
     ↓
📋 Professional Report Generation
```

## 📁 Output Structure

```
output/
├── jseye_report.html              # Beautiful HTML report
├── jseye_report.json              # Structured JSON data
├── attack_surface_graph.png       # Visual attack surface map
├── secrets_detailed.json          # Detailed secret analysis
├── api_endpoints.json             # Discovered API endpoints
├── vulnerabilities.json           # CVE and security issues
├── dom_flows.json                 # XSS and DOM analysis
└── scan_metadata.json            # Scan statistics and metadata
```

## 🎨 Terminal Output

JSEye provides rich, informative terminal output:

```
     ____.  ____________________
    |    | /   _____/\_   _____/___.__.  ____
    |    | \_____  \  |    __)_<   |  |_/ __ \
/\__|    | /        \ |        \\___  |\  ___/
\________|/_______  //_______  // ____| \___  >
                  \/         \/ \/          \/

        JSEye v2.0 - JavaScript Intelligence Engine
        Author: Lakshmikanthan K (@letchupkt)

[+] Target: example.com
[+] Initializing plugin system...
[+] Loading 4 analysis plugins
[+] Discovering JavaScript files...
[+] Found 127 JavaScript files (2.3 MB)
[+] Running AST analysis...
[+] Detecting secrets and credentials...
[+] Analyzing DOM flows for XSS...
[+] Discovering API endpoints...
[+] Checking CVE intelligence...
[+] Generating attack surface graph...
[+] Creating professional reports...

──────── JSEye Analysis Summary ────────
JavaScript Files  : 127
Secrets Found     : 8 (3 high-risk)
API Endpoints     : 23
XSS Vectors       : 5
CVE Matches       : 2
Risk Score        : 75/100 (High)
Report Generated  : jseye_report.html
─────────────────────────────────────────
```

## 🧠 Smart Features

### Context-Aware Secret Detection
JSEye uses advanced algorithms to detect secrets with:
- **Risk Scoring**: 0-100 scale based on context and entropy
- **False Positive Reduction**: Smart filtering of test/dummy credentials
- **Context Analysis**: Understanding of code context and usage patterns

### DOM Flow Analysis
Comprehensive XSS detection through:
- **Source-to-Sink Mapping**: Tracks data flow from user input to dangerous sinks
- **Pattern Recognition**: Identifies common XSS patterns and bypasses
- **Confidence Scoring**: Rates findings based on exploitability

### API Intelligence
Automated API discovery and security assessment:
- **Endpoint Enumeration**: Discovers REST and GraphQL endpoints
- **Parameter Analysis**: Identifies required and optional parameters
- **Security Headers**: Checks for proper security configurations

### Attack Surface Visualization
Generates visual graphs showing:
- **Component Relationships**: How different parts of the application connect
- **Data Flow Paths**: Routes that user data takes through the application
- **Risk Hotspots**: Areas with the highest security risk concentration

## 🔧 Configuration

### Custom Configuration File
```json
{
  "threads": 10,
  "timeout": 30,
  "plugins": {
    "secret_detection": {
      "enabled": true,
      "min_confidence": 0.7
    },
    "dom_flow_analysis": {
      "enabled": true,
      "check_xss": true
    },
    "cve_intelligence": {
      "enabled": true,
      "api_timeout": 10
    }
  },
  "output": {
    "format": "html",
    "include_graphs": true,
    "verbose": true
  }
}
```

### Environment Variables
```bash
export JSEYE_THREADS=20
export JSEYE_TIMEOUT=60
export JSEYE_OUTPUT_DIR=/custom/output/path
```

## 📊 Report Features

### HTML Reports
- **Interactive Dashboard**: Click-to-expand findings with detailed context
- **Risk Visualization**: Color-coded risk levels and progress bars
- **Code Context**: Syntax-highlighted code snippets with line numbers
- **Export Options**: PDF generation and data export capabilities

### JSON Reports
- **Structured Data**: Machine-readable format for integration
- **Complete Metadata**: Timestamps, versions, and scan parameters
- **Nested Analysis**: Hierarchical organization of findings
- **API-Friendly**: Easy integration with other security tools

## 🔌 Plugin Development

JSEye supports custom plugin development:

```python
from jseye.plugins.base import BasePlugin

class CustomAnalysisPlugin(BasePlugin):
    name = "custom_analysis"
    version = "1.0.0"
    
    async def analyze(self, js_content, metadata):
        # Your custom analysis logic
        return findings
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Lakshmikanthan K** (@letchupkt)
- GitHub: [@letchupkt](https://github.com/letchupkt)
- Email: letchupkt.dev@gmail.com

## 🙏 Acknowledgments

- Thanks to the security research community for continuous feedback
- Inspired by the need for comprehensive JavaScript security analysis
- Built with modern Python async/await patterns for performance

## 🐛 Bug Reports & Feature Requests

- **Issues**: [GitHub Issues](https://github.com/letchupkt/jseye/issues)
- **Documentation**: [GitHub Wiki](https://github.com/letchupkt/jseye/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/letchupkt/jseye/discussions)

---

**JSEye v2.0** - See what JavaScript hides. 👁️
