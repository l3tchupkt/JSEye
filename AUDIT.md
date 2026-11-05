# JSEye Full Codebase Architecture & Security Audit

**Document Version:** 1.0.0  
**Target Project:** JSEye (JavaScript Intelligence & Attack Surface Discovery Engine)  
**Auditor:** Principal Security Tooling Engineer & Software Architect  
**Date:** 2026-11-05  

---

## 1. Executive Summary

A comprehensive architectural, code quality, security, and performance audit of the **JSEye** codebase was performed. The audit reviewed all 46 Python source modules, plugins, report generators, data files, CLI entry points, and test suites.

While JSEye has a rich concept and ambitious feature set for autonomous JavaScript reconnaissance, the audit revealed **several critical runtime crashes, logic flaws, architectural disconnects, and safety risks** that prevented core advertised features (including the Infinite Recursive Queue, Dependency Confusion Analyzer, GAU Discovery, Active Probing, and Secret Extraction) from functioning correctly in production.

This document details the architectural map, identified vulnerabilities, defects, and the systematic remediation plan implemented to make JSEye a reliable, enterprise-grade, evidence-driven security tool.

---

## 2. Architectural Overview & System Flow

### 2.1 Execution Flow
```
[CLI Entry: jseye.cli:cli_main / main()]
       │
       ▼
[CLI Arguments & Target Parsing]
       │
       ▼
[Environment & Tool Setup] (ToolInstaller / OSDetector)
       │
       ▼
[PluginBasedCrawler.scan_target(target)]
       │
       ├── 1. ScopeEngine Initialization (target root domain derivation, allowlists)
       ├── 2. JavaScript & URL Discovery Phase:
       │      ├── Subfinder (subdomain discovery)
       │      ├── GAU & Wayback Machine (historical archive endpoints)
       │      ├── Hakrawler & Katana (live web crawl)
       │      ├── AdditionalDiscovery (robots.txt, sitemaps, common files)
       │      ├── JSCollector (HTTP fetching & DOM script extraction)
       │      ├── RecursiveQueue (autonomous BFS crawl across discovered assets)
       │      ├── LinkFinder (static endpoint regex extraction)
       │      ├── APIDetector & SwaggerDetector (API routes & OpenAPI specs)
       │      ├── SourceMapDetector (.map retrieval)
       │      ├── VersionDetector (framework fingerprinting)
       │      ├── CVELookup / CVEIntelligence (known CVE mapping)
       │      └── DependencyAnalyzer (NPM package.json confusion / takeover)
       │
       ├── 3. Plugin Execution Phase:
       │      ├── SecretDetectionPlugin (entropy & pattern secret analysis)
       │      ├── GoogleAPIKeyPlugin (live non-destructive validation via Gemini API)
       │      ├── DOMFlowPlugin (source-to-sink DOM XSS flow tracing)
       │      ├── APIIntelligencePlugin (route & schema security analysis)
       │      ├── CVEIntelligencePlugin (vulnerable library classification)
       │      └── ASTAnalysisPlugin (abstract syntax tree variable & route analysis)
       │
       ├── 4. Parameter Discovery & Endpoint Normalization (ParameterDiscoveryEngine)
       ├── 5. Prioritization & Noise Filtering (PrioritizationEngine)
       ├── 6. Result Consolidation & Deduplication (DedupeEngine)
       ├── 7. Active Probing (Optional: ActiveProber, triggered only by --active)
       ├── 8. Graph Generation (Optional: GraphEngine)
       └── 9. Structured Output Persistence (OutputManager)
       │
       ▼
[Report Generation & Hunter Exports]
       ├── JSON Report (JSONReportGenerator)
       ├── HTML Report (HTMLReportGenerator)
       └── Weaponized Tool Exports (ExportEngine: ffuf, curl, burp, wordlists)
```

### 2.2 Component Responsibilities
- **`jseye/core/scope.py`**: Auto-derives root domain and subdomains using `tldextract`. Enforces allowlist boundary.
- **`jseye/core/dedupe.py`**: Canonicalizes URLs (sorting params, stripping cache-busters, detecting pagination shapes) and response hashes.
- **`jseye/core/recursive_queue.py`**: Asynchronous BFS queue exploring child links, script imports, and API paths.
- **`jseye/core/collector.py`**: Fetches HTML/JS and parses script tags, inline scripts, and dynamic imports.
- **`jseye/core/active_prober.py`**: Safe active mutation prober detecting reflection, CORS misconfigurations, and error leakage.
- **`jseye/core/secret_engine.py`**: Regex and Shannon entropy secret detection with contextual scoring.
- **`jseye/core/google_api_validator.py`**: Provider-specific non-destructive live key verification.
- **`jseye/core/dependency_analyzer.py`**: Identifies private packages in public NPM registry and package takeover vectors.
- **`jseye/core/prioritization.py`**: Scores findings by attack surface value, filters out framework noise.
- **`jseye/core/output_manager.py`**: Organizes artifacts into timestamped folders (`urls/`, `endpoints/`, `secrets/`, etc.).
- **`jseye/report/`**: Generates sanitized HTML and structured JSON reports.

---

## 3. Critical Findings & Bugs Discovered

### Finding 1: `RecursiveQueue` Constructor and Method Signature Mismatch (CRITICAL)
- **File:** `jseye/core/plugin_crawler.py` (lines 493–506) vs `jseye/core/recursive_queue.py`
- **Issue:** `plugin_crawler.py` instantiated `RecursiveQueue(scope_engine=..., dedupe_engine=..., threads=..., headless=...)` and invoked `await queue.start_crawl(...)`. However, `RecursiveQueue.__init__` accepted `(scope, dedupe, concurrency, timeout)` and defined `run(...)`, not `start_crawl(...)`.
- **Impact:** The core "Autonomous Recursive Queue" crashed on line 1 with `TypeError` on every scan. The generic `except Exception` caught and masked the crash, completely disabling recursive crawling.
- **Inside Worker Queue:** In `recursive_queue.py` line 161 & 167, `queue.task_done()` was called both in `finally:` and in `except Exception:`, triggering `ValueError: task_done() called too many times`.

### Finding 2: Missing `DependencyAnalyzer.discover_and_analyze` Method (CRITICAL)
- **File:** `jseye/core/plugin_crawler.py` (line 763) vs `jseye/core/dependency_analyzer.py`
- **Issue:** `plugin_crawler.py` called `await dep_analyzer.discover_and_analyze(all_js_files, all_urls_to_crawl)`, but this method did not exist in `DependencyAnalyzer`.
- **Impact:** Threw `AttributeError` on every scan. Dependency confusion and takeover detection never ran.

### Finding 3: Missing `GAUIntegration.is_available` Method (CRITICAL)
- **File:** `jseye/core/plugin_crawler.py` (line 347) vs `jseye/core/gau.py`
- **Issue:** `plugin_crawler.py` called `if gau.is_available():`, but `GAUIntegration` only had an instance attribute `self.gau_available`, with no `is_available()` method.
- **Impact:** Threw `AttributeError` and silently aborted GAU discovery on every execution.

### Finding 4: Critical Data Loss During Result Consolidation (CRITICAL)
- **File:** `jseye/core/plugin_crawler.py` (lines 157–172, 209, 948, 1008)
- **Issue:** Discovered endpoints from `ParameterDiscoveryEngine`, `LinkFinder`, `RecursiveQueue`, `APIDetector`, and `SwaggerDetector` were stored in `self.results['endpoints']`. However, during `_consolidate_plugin_results`, line 1008 unconditionally overwrote `self.results['endpoints'] = consolidated_endpoints`, which only held endpoints analyzed by the `api_intelligence` plugin.
- **Impact:** Discovered endpoints were discarded from final reports and outputs. Furthermore, `queued_endpoints` and `queued_parameters` were never merged.

### Finding 5: `SecretDetector` KeyError on `'metrics'` Aborting Secret Detection (CRITICAL)
- **File:** `jseye/core/secret_engine.py` (line 165) vs `jseye/core/entropy.py`
- **Issue:** In `_detect_entropy_secrets`, line 165 accessed `entropy_data['metrics']`. `EntropyAnalyzer.extract_high_entropy_strings` returned dicts with `'value'`, `'entropy'`, `'reason'`, `'length'`, but not `'metrics'`.
- **Impact:** Any file containing high-entropy strings crashed with `KeyError: 'metrics'`, triggering the outer exception handler and returning `[]`, wiping out all detected secrets for that file.

### Finding 6: Passive Reconnaissance Sending Invasive HTTP DELETE/PUT Requests (SAFETY VIOLATION)
- **File:** `jseye/core/api_engine.py` (lines 81–86) & `jseye/plugins/api_intelligence_plugin.py`
- **Issue:** `APIIntelligencePlugin` was enabled by default during passive scans. When scanning endpoints, it called `_analyze_endpoint`, which sent HTTP `DELETE`, `PUT`, `POST`, `PATCH` requests to all discovered API endpoints.
- **Impact:** A passive scanner must never send destructive or state-changing requests like HTTP `DELETE` to production targets without explicit active authorization.

### Finding 7: Scope Bypass & SSRF via Protocol-Relative URLs (`//evil.com/`) (SECURITY)
- **File:** `jseye/core/scope.py` (line 85) & `jseye/core/utils.py`
- **Issue:** `if not url.startswith(("http://", "https://")):` assumed the URL was a relative path and returned `True`. Protocol-relative URLs (e.g., `//attacker.com/payload.js`) were treated as in-scope and resolved via `urljoin` to external domains.
- **Impact:** Crawlers could be led out-of-scope to arbitrary third-party or malicious hosts. Additionally, private/internal IP ranges (127.0.0.1, 169.254.169.254, 10.0.0.0/8, etc.) lacked explicit validation.

### Finding 8: False Positive Credential Validation (TOOL INTEGRITY)
- **File:** `jseye/core/secret_engine.py` (lines 442–467)
- **Issue:** `_validate_secret` marked `secret['validated'] = True` purely if the secret string was longer than 4 characters and not in a 7-word blacklist (`test`, `example`, etc.).
- **Impact:** Unvalidated static regex matches were flagged to the user as confirmed live credentials. Only provider-validated secrets (e.g., Google API keys tested against Google's API) should be marked as validated.

### Finding 9: `normalize_url` Corrupting Relative Paths (LOGIC BUG)
- **File:** `jseye/core/utils.py` (lines 22–27)
- **Issue:** When called with a relative URL (e.g. `/api/v1/users`), `urlparse` produced empty scheme and netloc, resulting in `f"{parsed.scheme}://{parsed.netloc}{parsed.path}"` evaluating to `:///api/v1/users`.
- **Impact:** Broke all downstream relative URL handling.

### Finding 10: `extract_js_strings` Regex Capturing Group Bug (LOGIC BUG)
- **File:** `jseye/core/utils.py` (lines 88–108)
- **Issue:** `single_quote_pattern = r"'([^'\\]|\\.)*'"` used a capturing group on the repeated single-character pattern. In `re.findall`, Python returns only the capturing group (the last character of the string). Since length was 1, all strings failed `len(s) > 3` and were dropped.
- **Impact:** `extract_js_strings` returned an empty list for any JavaScript content.

### Finding 11: Artificial Sleep Delays in Plugin Manager (PERFORMANCE)
- **File:** `jseye/plugins/manager.py` (lines 213, 225, 236)
- **Issue:** Contained hardcoded `await asyncio.sleep(1.0)` and `await asyncio.sleep(0.8)` calls between every plugin execution.
- **Impact:** Injected 10–12 seconds of artificial latency into every scan.

### Finding 12: Broken Active Probing Pipeline (LOGIC BUG)
- **File:** `jseye/core/plugin_crawler.py` (lines 224–227) vs `jseye/core/prioritization.py`
- **Issue:** `plugin_crawler.py` looked for `self.results.get('prioritized_endpoints', [])` to feed `ActiveProber`. However, `PrioritizationEngine` merged all findings into generic priority buckets (`high_priority`, etc.) and never populated `'prioritized_endpoints'`.
- **Impact:** Active probing received 0 targets and probed nothing on every run.

### Finding 13: Subprocess and Shell Injection Risks (SECURITY)
- **File:** `jseye/os_detect.py` (lines 660, 669)
- **Issue:** Used `subprocess.run(..., shell=True)` with commands.
- **Impact:** Flagged by security audits (Bandit B602). Must be executed without `shell=True` using sanitized argument lists.

### Finding 14: Packaging, Metadata & Dead Code Issues
- **Files:** `pyproject.toml`, `setup.py`, `plugin_crawler.py`, `recursive_js_finder.py`, `agent.md`
- **Issues:**
  - `pyproject.toml` declared `selenium` for headless, but code imported `playwright`.
  - Repository URLs mismatched (`letchupkt` vs `l3tchupkt`).
  - Lines 800–864 in `plugin_crawler.py` were unreachable dead code following `return unique_js_files`.
  - `agent.md` was completely empty.
  - Deprecated `datetime.utcnow()` used throughout reporting modules.

---

## 4. Remediation Plan & Implementation Strategy

| Phase | Component | Action Item |
|---|---|---|
| **Phase 2** | `jseye/core/scope.py`, `dedupe.py`, `utils.py` | Fix protocol-relative URLs (`//evil.com/`), add SSRF/private IP protection, fix `normalize_url`, fix `extract_js_strings`. |
| **Phase 2** | `jseye/core/secret_engine.py` | Fix `metrics` KeyError, fix JWT base64url decoding, remove fake validation flag (keep static vs verified distinct). |
| **Phase 3** | `jseye/core/recursive_queue.py`, `plugin_crawler.py` | Align `RecursiveQueue` signature and methods (`run` and `start_crawl`), fix worker `task_done()` double-invocation. |
| **Phase 4** | `jseye/core/dependency_analyzer.py` | Implement `discover_and_analyze(js_files, urls)` to orchestrate package discovery and NPM registry analysis. |
| **Phase 4** | `jseye/core/gau.py` | Implement `is_available()` method on `GAUIntegration`. |
| **Phase 4** | `jseye/core/api_engine.py`, `api_intelligence_plugin.py` | Guard all mutation/state-changing HTTP requests behind `--active` check. In passive mode, analyze statically. |
| **Phase 4** | `jseye/core/prioritization.py`, `active_prober.py` | Ensure `prioritized_endpoints` is preserved and passed correctly to `ActiveProber`. Handle both dataclass and dict objects. Fix `active_prober.py` to actually send mutations with payloads. |
| **Phase 5** | `jseye/plugins/manager.py` | Remove fake `asyncio.sleep` delays. Enhance error isolation. |
| **Phase 5** | `jseye/core/plugin_crawler.py` | Remove dead code (lines 800-864), correctly consolidate all endpoints, parameters, vulnerabilities, and secrets into results. |
| **Phase 6** | `jseye/report/`, `export_engine.py` | Replace deprecated `utcnow()`, fix dict-in-dict endpoint serialization in `json_report.py` and `html_report.py`, ensure safe HTML escaping. |
| **Phase 7** | `setup.py`, `pyproject.toml`, `README.md`, `agent.md` | Align dependencies (replace selenium with playwright in extras), fix metadata, populate comprehensive `agent.md`. |
| **Phase 8** | `tests/` | Add comprehensive unit, integration, and security tests covering all bug fixes and regressions. |
| **Phase 9** | End-to-end Verification | Run full test suite, linting, bandit scan, and test package build. |

---

*End of AUDIT.md — Implementation proceeding immediately.*

