"""
Active Probing Engine for JSEye v3.0.1.

Only activated when --active / --intruder-lite / --aggressive flags are set.
Default mode is PASSIVE.

Active mode:
  1. Send baseline request to each prioritised endpoint.
  2. Capture status, headers, body snippet, size, and timing.
  3. Mutate a limited set of parameters with a safe fuzz set.
  4. Detect: reflection, CORS misconfiguration, auth anomalies,
     access-control changes, error leakage, debug artifacts.

All captured requests are written to captured_requests.json.
"""

import asyncio
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from .logging import get_logger

logger = get_logger(__name__)

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False


# Safe fuzz payloads — limited, readable, and avoids destructive side-effects
_FUZZ_PAYLOADS = [
    "test",
    "1",
    "true",
    "admin",
    "'",
    '"',
    "../../etc/passwd",
    "<script>jseye</script>",
]

# Patterns that suggest error/debug leakage in responses
_ERROR_PATTERNS = re.compile(
    r"(traceback|stack\s+trace|exception|sql\s+syntax|mysql|psql|ora-\d+|"
    r"undefined\s+index|notice:|warning:|fatal\s+error|unhandled|debug\s+mode)",
    re.IGNORECASE,
)

_REFLECTION_MARKER = "jseye_reflect_"


class ActiveProber:
    """
    Sends controlled HTTP probes to prioritised endpoints.

    Parameters
    ----------
    concurrency : int   — parallel probing tasks
    timeout     : int   — per-request timeout (seconds)
    aggressive  : bool  — True = longer fuzz payload list
    max_mutations: int  — max mutations per endpoint (default 10)
    """

    def __init__(
        self,
        concurrency: int = 10,
        timeout: int = 10,
        aggressive: bool = False,
        max_mutations: int = 10,
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.aggressive = aggressive
        self.max_mutations = max_mutations

        self._payloads = _FUZZ_PAYLOADS
        if aggressive:
            self._payloads = _FUZZ_PAYLOADS + [
                "null",
                "undefined",
                "0",
                "-1",
                "999999",
                "${7*7}",
                "{{7*7}}",
                "' OR '1'='1",
                "%00",
            ]

        self.captured_requests: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def probe_endpoints(self, endpoints: List[str]) -> Dict[str, Any]:
        """
        Probe all supplied endpoints.
        Returns captured_requests and findings lists.
        """
        if not _HAS_AIOHTTP:
            logger.warning("aiohttp not installed — active probing disabled")
            return {"captured_requests": [], "findings": []}

        self._semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_cfg,
            headers={"User-Agent": "JSEye/3.0.1 (security-research)"},
        ) as session:
            tasks = [self._probe_one(session, ep) for ep in endpoints]
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(
            f"Active probing finished: {len(self.captured_requests)} requests, "
            f"{len(self.findings)} findings"
        )
        return {
            "captured_requests": self.captured_requests,
            "findings": self.findings,
        }

    # ------------------------------------------------------------------
    # Per-endpoint logic
    # ------------------------------------------------------------------

    async def _probe_one(self, session: "aiohttp.ClientSession", url: str) -> None:
        """Baseline + mutation probing for a single endpoint."""
        # Baseline
        baseline = await self._fetch(session, url)
        if not baseline:
            return

        self.captured_requests.append(baseline)

        # Detect issues on baseline response
        self._analyse_response(baseline, url, is_baseline=True)

        # Identify parameters to mutate (from URL query string)
        params = self._extract_params(url)
        if not params:
            # No query params — probe with a dummy param
            params = {"q": ""}

        mutations_done = 0
        for param_name in list(params.keys()):
            for payload in self._payloads:
                if mutations_done >= self.max_mutations:
                    break

                mutated_url = self._mutate_url(url, param_name, payload)
                reflection_marker = _REFLECTION_MARKER + payload[:6].replace("'", "x").replace('"', "x")
                mutated_url_marked = self._mutate_url(url, param_name, reflection_marker)

                result = await self._fetch(session, mutated_url_marked)
                if result:
                    self.captured_requests.append(result)
                    self._analyse_mutation(result, baseline, param_name, payload, url)

                mutations_done += 1

    # ------------------------------------------------------------------
    # HTTP fetch
    # ------------------------------------------------------------------

    async def _fetch(self, session: "aiohttp.ClientSession", url: str) -> Optional[Dict[str, Any]]:
        async with self._semaphore:
            t0 = time.time()
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    elapsed = time.time() - t0
                    try:
                        body = await resp.text(errors="replace")
                    except Exception:
                        body = ""

                    return {
                        "url": url,
                        "method": "GET",
                        "status": resp.status,
                        "response_size": len(body),
                        "response_time_ms": round(elapsed * 1000, 1),
                        "headers": dict(resp.headers),
                        "body_snippet": body[:500],
                        "full_body": body[:5000],
                    }
            except asyncio.TimeoutError:
                logger.debug(f"Timeout probing {url}")
            except Exception as exc:
                logger.debug(f"Probe error {url}: {exc}")
        return None

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def _analyse_response(self, result: Dict, url: str, is_baseline: bool = False) -> None:
        """Analyse a single response for interesting signals."""
        body = result.get("full_body", "")
        headers = result.get("headers", {})
        status = result.get("status", 0)

        # CORS misconfiguration
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or acao == "null":
            self._add_finding("cors_misconfiguration", url, "Medium",
                              f"Access-Control-Allow-Origin: {acao}")

        # Debug leakage
        if _ERROR_PATTERNS.search(body):
            self._add_finding("error_leakage", url, "High",
                              "Error/debug info in response body")

        # Interesting status on baseline
        if is_baseline and status in (403, 401):
            self._add_finding("access_control_candidate", url, "Low",
                              f"Baseline returned {status} — test with auth bypass params")

    def _analyse_mutation(
        self,
        result: Dict,
        baseline: Dict,
        param: str,
        payload: str,
        url: str,
    ) -> None:
        """Compare mutated response to baseline for interesting differences."""
        body = result.get("full_body", "")
        status = result.get("status", 0)
        size = result.get("response_size", 0)
        b_status = baseline.get("status", 0)
        b_size = baseline.get("response_size", 0)

        # Reflection
        if _REFLECTION_MARKER in body:
            self._add_finding("xss_reflection", url, "High",
                              f"Input reflected in response for param '{param}'",
                              param=param, payload=payload)

        # SQL / error leakage on mutation
        if _ERROR_PATTERNS.search(body) and not _ERROR_PATTERNS.search(baseline.get("full_body", "")):
            self._add_finding("error_leakage_on_mutation", url, "High",
                              f"Error triggered with payload '{payload}' on param '{param}'",
                              param=param, payload=payload)

        # Status code change (e.g., 403 -> 200 — auth bypass signal)
        if b_status in (401, 403) and status == 200:
            self._add_finding("auth_bypass_signal", url, "Critical",
                              f"Status changed {b_status} -> {status} with param '{param}'={payload}",
                              param=param, payload=payload)

        # Significant response size change (information disclosure signal)
        if b_size > 0 and abs(size - b_size) > 500:
            self._add_finding("response_size_change", url, "Low",
                              f"Size changed {b_size} -> {size} with param '{param}'={payload}",
                              param=param, payload=payload)

        # CORS on mutation
        headers = result.get("headers", {})
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao and acao not in ("", baseline.get("headers", {}).get("Access-Control-Allow-Origin", "")):
            self._add_finding("cors_misconfiguration_on_mutation", url, "Medium",
                              f"CORS header appeared after mutation: {acao}",
                              param=param, payload=payload)

    def _add_finding(
        self,
        finding_type: str,
        url: str,
        severity: str,
        detail: str,
        **kwargs: Any,
    ) -> None:
        f = {
            "type": finding_type,
            "url": url,
            "severity": severity,
            "detail": detail,
            "source": "active_prober",
        }
        f.update(kwargs)
        self.findings.append(f)
        logger.info(f"[ACTIVE] [{severity}] {finding_type}: {url}")

    # ------------------------------------------------------------------
    # URL mutation helpers
    # ------------------------------------------------------------------

    def _extract_params(self, url: str) -> Dict[str, str]:
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            return {k: (v[0] if v else "") for k, v in qs.items()}
        except Exception:
            return {}

    def _mutate_url(self, url: str, param: str, value: str) -> str:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [value]
            flat = {k: v[0] for k, v in params.items()}
            new_query = urlencode(flat)
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment,
            ))
        except Exception:
            return url
