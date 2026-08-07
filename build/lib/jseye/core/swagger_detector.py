"""
SwaggerDetector - Detects Swagger/OpenAPI specifications exposed by a target.

Loads 200+ detection paths from jseye/data/swagger.yaml (Nuclei template),
concurrently probes each path, and extracts endpoint/param data from found specs.
"""

import asyncio
import json
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from .logging import get_logger

logger = get_logger(__name__)

# Swagger/OpenAPI keywords used to confirm a spec response
SWAGGER_KEYWORDS = [
    "swagger:",
    "Swagger 2.0",
    '"swagger":',
    "Swagger UI",
    "loadSwaggerUI",
    "id=\"swagger-ui",
    "openapi:",
    '{"openapi":',
    '"openapi":',
]


class SwaggerDetector:
    """Detects and parses Swagger/OpenAPI specifications from a target host."""

    # ------------------------------------------------------------------ #
    # Class-level helpers                                                  #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _data_path() -> str:
        """Return absolute path to jseye/data/swagger.yaml."""
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, "data", "swagger.yaml")

    @classmethod
    def get_swagger_paths(cls) -> List[str]:
        """
        Load and return all detection paths from the bundled swagger.yaml.

        Falls back to a hardcoded set of 30+ common paths when the YAML
        file cannot be parsed (e.g., PyYAML not installed).

        Returns:
            List of URL paths (strings) to probe.
        """
        paths: List[str] = []

        yaml_file = cls._data_path()

        if YAML_AVAILABLE and os.path.exists(yaml_file):
            try:
                with open(yaml_file, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)

                # Navigate YAML structure: http[0].payloads.paths
                http_blocks = data.get("http", [])
                if http_blocks:
                    payloads = http_blocks[0].get("payloads", {})
                    raw_paths = payloads.get("paths", [])
                    for p in raw_paths:
                        if isinstance(p, str):
                            # Normalise: ensure leading slash
                            p = p.strip()
                            if not p.startswith("/"):
                                p = "/" + p
                            paths.append(p)
            except Exception as exc:
                logger.warning(f"Failed to parse swagger.yaml: {exc}")

        # Fallback / supplement with common paths not in the YAML
        fallback = [
            "/swagger.json",
            "/swagger.yaml",
            "/swagger-ui.html",
            "/openapi.json",
            "/openapi.yaml",
            "/api-docs",
            "/api-docs/swagger.json",
            "/api/swagger.json",
            "/api/swagger.yaml",
            "/api/swagger-ui.html",
            "/api/v1/swagger.json",
            "/api/v2/swagger.json",
            "/api/v3/swagger.json",
            "/v2/api-docs",
            "/v3/api-docs",
            "/swagger/v1/swagger.json",
            "/swagger/v2/swagger.json",
            "/docs/swagger.json",
            "/docs/openapi.json",
            "/redoc",
        ]

        existing = set(paths)
        for p in fallback:
            if p not in existing:
                paths.append(p)

        return paths

    # ------------------------------------------------------------------ #
    # Instance methods                                                     #
    # ------------------------------------------------------------------ #

    def __init__(
        self,
        timeout: int = 10,
        max_concurrent: int = 20,
        user_agent: str = "JSEye/2.1.0 SwaggerDetector",
    ) -> None:
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent
        self._session: Optional[Any] = None  # aiohttp.ClientSession

    async def __aenter__(self) -> "SwaggerDetector":
        if AIOHTTP_AVAILABLE:
            connector = aiohttp.TCPConnector(
                limit=self.max_concurrent,
                ssl=False,
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={"User-Agent": self.user_agent},
            )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------ #
    # Core detection                                                       #
    # ------------------------------------------------------------------ #

    async def detect_swagger_specs(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Probe all swagger paths on *base_url* concurrently.

        Args:
            base_url: Root URL of target, e.g. ``https://example.com``.

        Returns:
            List of spec dicts:
            ``{"path": str, "url": str, "version": str, "spec_type": str,
               "raw": dict|str, "endpoint_count": int}``
        """
        if not AIOHTTP_AVAILABLE:
            logger.warning("aiohttp not installed; SwaggerDetector requires it.")
            return []

        paths = self.get_swagger_paths()
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = [self._probe_path(base_url, path, semaphore) for path in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        found: List[Dict[str, Any]] = []
        for res in results:
            if isinstance(res, dict) and res.get("found"):
                found.append(res)

        logger.info("Swagger detection: %d spec(s) found on %s", len(found), base_url)
        return found

    async def discover_and_extract(self, base_url: str) -> Dict[str, Any]:
        """
        High-level helper used by the plugin crawler (Phase 6.4).

        Probes all swagger paths on *base_url*, then extracts all endpoints
        from every found spec.

        Returns:
            {
                'success': bool,
                'specs_found': int,
                'total_endpoints': int,
                'spec_details': List[dict],
                'endpoints': List[dict],  # each has 'full_path' key
            }
        """
        result: Dict[str, Any] = {
            'success': False,
            'specs_found': 0,
            'total_endpoints': 0,
            'spec_details': [],
            'endpoints': [],
        }

        try:
            specs = await self.detect_swagger_specs(base_url)
            if not specs:
                return result

            result['success'] = True
            result['specs_found'] = len(specs)
            result['spec_details'] = specs

            all_endpoints: List[Dict[str, Any]] = []
            for spec in specs:
                endpoints = self.extract_endpoints_from_spec(spec.get('raw'))
                for ep in endpoints:
                    ep_copy = dict(ep)
                    ep_copy['full_path'] = ep_copy.get('path', '/')
                    ep_copy['spec_url'] = spec.get('url', '')
                    ep_copy['spec_type'] = spec.get('spec_type', 'unknown')
                    all_endpoints.append(ep_copy)

            result['endpoints'] = all_endpoints
            result['total_endpoints'] = len(all_endpoints)

        except Exception as exc:
            logger.warning(f"discover_and_extract failed for {base_url}: {exc}")

        return result

    async def _probe_path(
        self,
        base_url: str,
        path: str,
        semaphore: asyncio.Semaphore,
    ) -> Dict[str, Any]:
        """Attempt to fetch *base_url + path* and detect swagger content."""
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

        async with semaphore:
            try:
                assert self._session is not None
                async with self._session.get(url, allow_redirects=True) as resp:
                    if resp.status != 200:
                        return {"found": False, "url": url}

                    content_type = resp.headers.get("Content-Type", "")
                    body_bytes = await resp.read()
                    body_text = body_bytes.decode("utf-8", errors="replace")

                    # Quick keyword check
                    is_swagger = any(kw in body_text for kw in SWAGGER_KEYWORDS)
                    if not is_swagger:
                        return {"found": False, "url": url}

                    # Try to parse as JSON or YAML
                    parsed = self._parse_spec(body_text, content_type)
                    spec_type, api_version = self._detect_spec_type(parsed, body_text)

                    endpoints = self.extract_endpoints_from_spec(parsed) if parsed else []

                    return {
                        "found": True,
                        "path": path,
                        "url": url,
                        "spec_type": spec_type,
                        "version": api_version,
                        "raw": parsed,
                        "endpoint_count": len(endpoints),
                        "endpoints": endpoints,
                    }

            except asyncio.TimeoutError:
                return {"found": False, "url": url, "error": "timeout"}
            except Exception as exc:
                return {"found": False, "url": url, "error": str(exc)}

    # ------------------------------------------------------------------ #
    # Spec parsing helpers                                                 #
    # ------------------------------------------------------------------ #

    def _parse_spec(
        self, body: str, content_type: str
    ) -> Optional[Dict[str, Any]]:
        """Try JSON then YAML parsing. Returns dict or None."""
        # JSON
        try:
            return json.loads(body)
        except (json.JSONDecodeError, ValueError):
            pass

        # YAML (only if library available)
        if YAML_AVAILABLE:
            try:
                result = yaml.safe_load(body)
                if isinstance(result, dict):
                    return result
            except Exception:
                pass

        return None

    def _detect_spec_type(
        self,
        parsed: Optional[Dict[str, Any]],
        body: str,
    ) -> tuple:
        """Return (spec_type, api_version) tuple."""
        if parsed:
            if "openapi" in parsed:
                return "OpenAPI", str(parsed.get("openapi", "unknown"))
            if "swagger" in parsed:
                return "Swagger", str(parsed.get("swagger", "unknown"))
            if "info" in parsed and "version" in parsed.get("info", {}):
                return "API Spec", parsed["info"]["version"]

        if "openapi:" in body or '"openapi":' in body:
            return "OpenAPI", "unknown"
        if "swagger:" in body or '"swagger":' in body:
            return "Swagger", "unknown"

        return "API Doc", "unknown"

    def extract_endpoints_from_spec(
        self, spec: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Extract API endpoints from a parsed OpenAPI/Swagger spec dict.

        Returns:
            List of endpoint dicts:
            ``{"path": str, "method": str, "summary": str, "parameters": list}``
        """
        endpoints: List[Dict[str, Any]] = []
        if not spec or not isinstance(spec, dict):
            return endpoints

        paths_obj = spec.get("paths", {})
        if not isinstance(paths_obj, dict):
            return endpoints

        for path, methods in paths_obj.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                method_upper = method.upper()
                if method_upper not in (
                    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
                ):
                    continue

                if not isinstance(operation, dict):
                    continue

                # Extract parameters
                params: List[str] = []
                for param in operation.get("parameters", []):
                    if isinstance(param, dict):
                        name = param.get("name", "")
                        if name:
                            params.append(name)

                endpoints.append(
                    {
                        "path": path,
                        "method": method_upper,
                        "summary": operation.get("summary", ""),
                        "description": operation.get("description", ""),
                        "parameters": params,
                        "tags": operation.get("tags", []),
                        "operation_id": operation.get("operationId", ""),
                    }
                )

        return endpoints

    # ------------------------------------------------------------------ #
    # Convenience helpers                                                  #
    # ------------------------------------------------------------------ #

    def build_endpoint_wordlist(self, specs: List[Dict[str, Any]]) -> List[str]:
        """Flatten all spec paths into a deduplicated wordlist."""
        seen: set = set()
        wordlist: List[str] = []
        for spec in specs:
            for ep in spec.get("endpoints", []):
                path = ep.get("path", "")
                if path and path not in seen:
                    seen.add(path)
                    wordlist.append(path)
        return wordlist
