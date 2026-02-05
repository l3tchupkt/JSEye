# JSEye 👁️

**See What JavaScript Hides**

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/70359cd0-ada8-4f44-a01f-81b9841d8556" />


JSEye is a production-grade Python reconnaissance framework for deep JavaScript intelligence and attack surface discovery. Built for bug bounty hunters and security researchers who need comprehensive JavaScript analysis with minimal noise.

## 🚀 Features

- **Fully Automatic**: Default mode runs complete pipeline with zero configuration
- **Modular Design**: Control execution with granular flags
- **Multi-Tool Integration**: Orchestrates gau, waybackurls, hakrawler, katana, subjs, linkfinder, and mantra
- **Smart Prioritization**: AI-powered JavaScript file ranking
- **Correlation Engine**: Connects findings across multiple sources
- **Clean Terminal UX**: Rich progress indicators and polished output
- **Linux-First**: Optimized for Linux environments

## 📦 Installation

### From PyPI 

```bash
pip install jseye
```

## 🛠️ Requirements

JSEye automatically installs required tools on first run:

- **Go** (for gau, waybackurls, hakrawler, katana, subjs, mantra)
- **Node.js** (for AST analysis)
- **Python 3.10+** (for linkfinder and core functionality)

## 🎯 Usage

### Default Mode (Full Pipeline)

```bash
# Run everything - this is the default behavior
jseye -i subdomains.txt -o output
```

### Module Control Flags

```bash
# Stop after JavaScript discovery
jseye -i subs.txt -o output --js-only

# Skip secrets detection
jseye -i subs.txt -o output --no-secrets

# Only regex analysis (skip AST)
jseye -i subs.txt -o output --regex-only

# Skip AST analysis
jseye -i subs.txt -o output --skip-ast

# Skip sink detection
jseye -i subs.txt -o output --no-sinks

# Skip correlation engine
jseye -i subs.txt -o output --no-correlate

# Don't auto-install tools
jseye -i subs.txt -o output --no-install
```

### Information Commands

```bash
# List available modules
jseye --list-modules
```

## 🔄 Pipeline

JSEye executes a comprehensive analysis pipeline:

```
subdomains.txt
    ↓
📡 URL Harvesting (gau, waybackurls, hakrawler, katana)
    ↓
🔍 JavaScript Filtering & Prioritization
    ↓
📥 JavaScript Download
    ↓
🧠 Regex Analysis
    ↓
🌳 AST Analysis
    ↓
🔗 LinkFinder Integration
    ↓
🔐 Secrets Detection (mantra)
    ↓
🎯 Sink Detection
    ↓
🔄 Intelligence Correlation
    ↓
📊 Final Report
```

## 📁 Output Structure

```
output/
├── harvested_urls.txt              # All discovered URLs
├── js_files_all.txt               # All JavaScript files
├── js_files_high_priority.txt     # High-value JS files
├── js_files_medium_priority.txt   # Medium-value JS files
├── js_files_low_priority.txt      # Low-value JS files
├── js_files_detailed.json         # Detailed JS analysis
├── endpoints.json                 # Discovered endpoints
├── secrets.json                   # Found secrets
├── sinks.json                     # Detected sinks
├── correlation_report.json        # Correlated intelligence
└── jseye_summary.json            # Final summary
```

## 🎨 Terminal Output

JSEye provides beautiful, informative terminal output:

```
   ▄▄▄▄▄▄  ▄▄▄▄▄     ▄▄▄▄▄▄▄            
  █▀ ██   ██▀▀▀▀█▄  █▀██▀▀▀             
     ██   ▀██▄  ▄▀    ██                
     ██     ▀██▄▄     ████   ██ ██ ▄█▀█▄
     ██   ▄   ▀██▄    ██     ██▄██ ██▄█▀
     ██   ▀██████▀    ▀█████▄▄▀██▀▄▀█▄▄▄
 ▄   ██                        ██       
 ▀████▀                      ▀▀▀        

        JSEye — See What JavaScript Hides
       Author: Lakshmikanthan K (letchupkt)

[+] Loading domains from subdomains.txt
[+] Harvesting URLs (gau, waybackurls, katana)
[+] Extracted 1,482 JavaScript files
[+] Prioritized 214 high-value JS files
[+] Analyzing JavaScript (regex + AST)
[+] Found 37 endpoints, 4 secrets, 9 sinks
[+] Correlating intelligence
[✓] Results saved to output/

──────── JSEye Summary ────────
JS Files Analyzed : 214
Endpoints Found   : 37
Secrets Found     : 4
Sinks Found       : 9
High Confidence   : 11
Output Directory  : output/
────────────────────────────────
```

## 🧠 Smart Features

### JavaScript Prioritization

JSEye intelligently prioritizes JavaScript files based on:

- **High-value indicators**: admin, api, auth, config, dashboard, login
- **File characteristics**: non-minified, shorter paths, custom code
- **Vendor detection**: deprioritizes common libraries and CDN files

### Correlation Engine

Connects findings across multiple sources to reduce false positives and highlight high-confidence discoveries.

### Auto-Installation

Automatically detects and installs missing tools on first run, with graceful fallbacks and clear error messages.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Lakshmikanthan K** (letchupkt)
- GitHub: [@letchupkt](https://github.com/letchupkt)

## 🙏 Acknowledgments

- Thanks to all the tool authors: gau, waybackurls, hakrawler, katana, subjs, linkfinder, mantra
- Inspired by the bug bounty and security research community

---

**JSEye** - See what JavaScript hides. 👁️
