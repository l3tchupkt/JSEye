# JSEye — Agent & Contributor Operational Manual

## 1. System Overview & Design Philosophy

**JSEye** is a high-performance JavaScript intelligence, reconnaissance, and attack-surface mapping engine designed for application security engineers, penetration testers, and bug bounty researchers.

### Design Principles:
1. **Evidence-Driven Security**: Detections must be accompanied by contextual snippets, line numbers, and verifiable signals. A finding is never marked as verified unless live verification against an authorized endpoint occurred.
2. **Safe By Default (Passive Invariance)**: In passive reconnaissance mode, JSEye never issues state-changing HTTP requests (`POST`, `PUT`, `DELETE`, `PATCH`). Invasive mutations and fuzzing are strictly confined to `--active` / `--aggressive-probing` flags.
3. **SSRF & Scope Integrity**: Crawling and probing components must strictly validate target hosts. Private, loopback, link-local, and cloud metadata addresses (`127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`) are rejected unless the scan target itself was an explicit local host. Protocol-relative URLs (`//evil.com/payload.js`) are normalized and subject to scope checks.
4. **Resilient Concurrency**: Asynchronous queues use bounded worker pools, respect rate limits, and ensure each task completion lifecycle is guarded by exactly one `task_done()` call.

---

## 2. Complete Execution Architecture

```
CLI Entry (`jseye.cli:cli_main`)
  │
  ├── 1. Argument Parsing & Scope Derivation (`ScopeEngine`, `DedupeEngine`)
  ├── 2. Collection Phase (`PluginBasedCrawler.collect_all_js`)
  │     ├── Subdomain Enumeration (`SubfinderIntegration`)
  │     ├── Historical URL Mining (`WaybackIntegration`, `GAUIntegration`)
  │     ├── Active/Dynamic Crawling (`HakrawlerIntegration`, `RecursiveQueue`)
  │     └── Direct Script Ingestion (`JSCollector`)
  ├── 3. Analysis & Intelligence Plugins (`PluginManager`)
  │     ├── Secret Detection (`SecretDetector`, `EntropyAnalyzer`)
  │     ├── AST Analysis (`JSASTAnalyzer`)
  │     ├── DOM Flow & Source-Sink (`DOMFlowAnalyzer`)
  │     ├── API Intelligence (`APIIntelligence`)
  │     ├── CVE Lookup & Dependencies (`DependencyAnalyzer`, `CVEIntelligence`)
  │     └── Live Secret Validators (`GoogleAPIKeyPlugin`)
  ├── 4. Consolidation & Prioritization (`PrioritizationEngine`)
  │     ├── High-Signal Risk Scoring
  │     ├── Multi-Factor Confidence Weights
  │     └── Noise & Static Asset Filtering
  ├── 5. Optional Active Probing (`ActiveProber`)
  │     ├── Controlled Baseline Requests
  │     ├── Non-destructive Mutation & Reflection Checks
  │     └── Request Capturing (`captured_requests.json`)
  └── 6. Output & Serialization
        ├── Structured Workspace Folders (`OutputManager`)
        ├── JSON Reports (`JSONReportGenerator`)
        ├── HTML Reports (`HTMLReportGenerator`)
        └── Automation Exporters (`ExportEngine` -> FFUF, Burp, Curl, Nuclei)
```

---

## 3. Core Engine Interaction Map

| Engine | File | Role & Invariants |
|---|---|---|
| `ScopeEngine` | `jseye/core/scope.py` | Determines whether a URL or domain belongs to the target. Enforces host boundaries and blocks protocol-relative escapes. |
| `DedupeEngine` | `jseye/core/dedupe.py` | Canonicalizes URLs (strips volatile query params like `_`, `timestamp`, `utm_*`), hashes response bodies, and blocks pagination loops. |
| `RecursiveQueue` | `jseye/core/recursive_queue.py` | Asynchronous BFS crawler. Feeds seed URLs, discovers child URLs, scripts, API candidates, and query parameters. Bounded by concurrency semaphores. |
| `SecretDetector` | `jseye/core/secret_engine.py` | High-accuracy pattern matching and Shannon entropy scoring. Flags format validity while reserving `validated: True` only for live-probed credentials. |
| `DependencyAnalyzer` | `jseye/core/dependency_analyzer.py` | Probes for exposed `package.json` manifests, inspects internal namespace packages, and queries public NPM registries for dependency confusion or takeover opportunities. |
| `ActiveProber` | `jseye/core/active_prober.py` | Safe active parameter mutation engine. Sends actual fuzz payloads, captures timings/responses, and identifies reflections, error disclosures, and auth state changes. |
| `PrioritizationEngine` | `jseye/core/prioritization.py` | Aggregates discovered endpoints, secrets, and vulnerabilities. Emits high-priority lists for bug bounty triage. |
| `ExportEngine` | `jseye/core/export_engine.py` | Generates FFUF commands, Burp XML sitemaps, cURL reproduction scripts, and parameter wordlists. |

---

## 4. Coding Conventions & Safety Standards

1. **Type Annotations**:
   - Every new public function or method must have explicit type annotations for parameters and return values.
2. **Exception Handling**:
   - Catch specific exceptions (`asyncio.TimeoutError`, `aiohttp.ClientError`, `json.JSONDecodeError`).
   - Never use bare `except:` that silently suppresses program errors without debug logging.
3. **Async / Sync Boundaries**:
   - Compute-heavy tasks (such as large AST parsing or regex sweeps on megabyte-sized files) must be scheduled via `loop.run_in_executor()`.
   - Never call blocking synchronous I/O or `time.sleep()` inside an async coroutine.
4. **Time & Date Handling**:
   - Use `datetime.now(timezone.utc)` for all timestamps. Never use deprecated `datetime.utcnow()`.
5. **Report Escaping**:
   - In HTML and XML reports, untrusted inputs (target domains, matched strings, endpoints, reflection values) must be sanitized with `html.escape()` or `xml.sax.saxutils.escape()`.

---

## 5. Security Boundaries & SSRF Rules

- **SSRF Prevention**: Before dispatching any HTTP probe, verify the target URL's resolved host using `is_private_ip(host)`. By default, calls to `127.0.0.1`, `localhost`, `169.254.169.254`, and private RFC1918 subnets are forbidden.
- **Protocol-Relative Escapes**: Any URL starting with `//` must be interpreted as an absolute URL with scheme `https:` and checked against scope.
- **Subprocess Execution**: Never pass `shell=True` to `subprocess.run` or `subprocess.Popen`. Always pass an explicit list of command arguments.

---

## 6. Guidelines for Contributors & AI Agents

- **Running Tests**: Run `pytest` from the root directory. Ensure all unit and integration tests pass before opening a PR.
- **Adding Plugins**: Subclass `BasePlugin` in `jseye/plugins/`. Implement `metadata`, `validate_context`, and `run`. Register plugin dependencies cleanly.
- **Updating Dependencies**: If a feature requires external tools or libraries, declare optional dependencies in `pyproject.toml` and guard them with lazy imports and availability checks.

---

## 7. Release Engineering & PyPI Trusted Publishing

- **Version Authority**: Single source of truth is `jseye/version.py` (`__version__ = "0.1.0"`).
- **Validation**: Run `python scripts/validate_release.py` to ensure version matching and package integrity.
- **Release Trigger**: Tag pushes matching `v*.*.*` (e.g. `v0.1.0`) trigger `.github/workflows/release.yml`.
- **PyPI Trusted Publisher Configuration**:
  - Owner: `l3tchupkt`
  - Repository: `JSEye`
  - Workflow name: `release.yml`
  - Environment name: `release`


