"""
Recursive Crawl Queue for JSEye v3.0.1.

Async BFS queue with unlimited depth and requests by default.
Loop prevention is delegated to DedupeEngine.
In-scope enforcement is delegated to ScopeEngine.

Each processed URL yields:
  - Extracted links
  - JS file URLs
  - API endpoint candidates
  - Parameters (from URL query strings)
  - Any raw content for downstream analysers
"""

import asyncio
import re
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from .logging import get_logger
from .scope import ScopeEngine
from .dedupe import DedupeEngine

logger = get_logger(__name__)

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False


# Regex for extracting href / src / action attributes
_LINK_RE = re.compile(
    r'(?:href|src|action|data-src|data-href)\s*=\s*["\']([^"\'>\s]+)["\']',
    re.IGNORECASE,
)
_JS_IMPORT_RE = re.compile(
    r'(?:import\s+[^"\']*from|require\s*\()\s*["\']([^"\']+\.js)["\']',
    re.IGNORECASE,
)
_FETCH_RE = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class RecursiveQueue:
    """
    Async recursive URL processor.

    Parameters
    ----------
    scope       : ScopeEngine  — enforces in-scope filtering
    dedupe      : DedupeEngine — prevents re-processing seen URLs
    max_depth   : int | None   — None = unlimited
    max_requests: int | None   — None = unlimited
    concurrency : int          — parallel fetches at once
    timeout     : int          — per-request timeout (seconds)
    """

    def __init__(
        self,
        scope: ScopeEngine,
        dedupe: DedupeEngine,
        max_depth: Optional[int] = None,
        max_requests: Optional[int] = None,
        concurrency: int = 20,
        timeout: int = 10,
    ):
        self.scope = scope
        self.dedupe = dedupe
        self.max_depth = max_depth
        self.max_requests = max_requests
        self.concurrency = concurrency
        self.timeout = timeout

        self._requests_made: int = 0
        self._semaphore: Optional[asyncio.Semaphore] = None

        # Accumulated results
        self.all_urls: List[str] = []
        self.in_scope_urls: List[str] = []
        self.js_urls: List[str] = []
        self.api_candidates: List[str] = []
        self.page_contents: List[Dict[str, Any]] = []

    async def run(self, seed_urls: List[str]) -> Dict[str, Any]:
        """
        Start the recursive queue from a list of seed URLs.
        Returns a dict of all discovered resources.
        """
        if not _HAS_AIOHTTP:
            logger.warning("aiohttp not installed — recursive queue disabled")
            return self._empty_result()

        self._semaphore = asyncio.Semaphore(self.concurrency)

        # BFS queue: (url, depth)
        queue: asyncio.Queue = asyncio.Queue()

        # Seed
        for url in seed_urls:
            if self.scope.is_in_scope(url) and self.dedupe.should_crawl(url):
                self.dedupe.mark_url_seen(url)
                await queue.put((url, 0))
                self.all_urls.append(url)
                self.in_scope_urls.append(url)

        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_cfg,
            headers={"User-Agent": "JSEye/3.0.1 (security-research)"},
        ) as session:
            # Worker pool
            tasks = [
                asyncio.create_task(self._worker(session, queue))
                for _ in range(min(self.concurrency, len(seed_urls) + 1))
            ]

            # Wait until queue empty
            await queue.join()

            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(
            f"Recursive queue finished: {self._requests_made} requests, "
            f"{len(self.in_scope_urls)} in-scope URLs"
        )

        return {
            "all_urls": self.all_urls,
            "in_scope_urls": self.in_scope_urls,
            "js_urls": self.js_urls,
            "api_candidates": self.api_candidates,
            "page_contents": self.page_contents,
            "stats": {
                "requests_made": self._requests_made,
                "unique_in_scope": len(self.in_scope_urls),
                "js_files_found": len(self.js_urls),
                "api_candidates": len(self.api_candidates),
            },
        }

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    async def _worker(self, session: "aiohttp.ClientSession", queue: asyncio.Queue) -> None:
        while True:
            try:
                url, depth = await queue.get()
                try:
                    await self._process_url(session, queue, url, depth)
                finally:
                    queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug(f"Worker error: {exc}")
                queue.task_done()

    async def _process_url(
        self,
        session: "aiohttp.ClientSession",
        queue: asyncio.Queue,
        url: str,
        depth: int,
    ) -> None:
        """Fetch URL, extract new URLs, enqueue in-scope ones."""
        # Enforce request limit
        if self.max_requests is not None and self._requests_made >= self.max_requests:
            return

        # Enforce depth limit
        if self.max_depth is not None and depth > self.max_depth:
            return

        async with self._semaphore:
            try:
                self._requests_made += 1
                async with session.get(url, allow_redirects=True) as resp:
                    ct = resp.content_type or ""
                    body = ""

                    # Only decode text-based responses
                    if any(t in ct for t in ("html", "javascript", "json", "text")):
                        try:
                            body = await resp.text(errors="replace")
                        except Exception:
                            body = ""

                    # Skip duplicate bodies
                    if body and self.dedupe.is_body_seen(body):
                        return
                    if body:
                        self.dedupe.mark_body_seen(body)

                    # Record content
                    record = {
                        "url": url,
                        "status": resp.status,
                        "content_type": ct,
                        "content": body[:50000],  # cap at 50 KB
                        "headers": dict(resp.headers),
                    }
                    self.page_contents.append(record)

                    # Track as JS if appropriate
                    if "javascript" in ct or url.endswith(".js"):
                        if url not in self.js_urls:
                            self.js_urls.append(url)

                    # Extract and enqueue child URLs
                    if body:
                        new_urls = self._extract_urls(body, url)
                        for child in new_urls:
                            self.all_urls.append(child)

                            in_scope, external = self.scope.filter_urls([child])

                            for ext_url in external:
                                self.scope.record_external(ext_url)

                            for scoped in in_scope:
                                # Classify
                                if scoped.endswith(".js") or "javascript" in scoped:
                                    if scoped not in self.js_urls:
                                        self.js_urls.append(scoped)

                                if any(x in scoped for x in ("/api/", "/graphql", "/swagger", ".json")):
                                    if scoped not in self.api_candidates:
                                        self.api_candidates.append(scoped)

                                if self.dedupe.should_crawl(scoped):
                                    self.dedupe.mark_url_seen(scoped)
                                    self.in_scope_urls.append(scoped)
                                    await queue.put((scoped, depth + 1))

            except asyncio.TimeoutError:
                logger.debug(f"Timeout: {url}")
            except Exception as exc:
                logger.debug(f"Error fetching {url}: {exc}")

    # ------------------------------------------------------------------
    # URL extraction
    # ------------------------------------------------------------------

    def _extract_urls(self, body: str, base_url: str) -> List[str]:
        """Extract all URLs from an HTML / JS response body."""
        found: Set[str] = set()

        # HTML attributes
        for m in _LINK_RE.finditer(body):
            found.add(m.group(1))

        # JS imports / requires
        for m in _JS_IMPORT_RE.finditer(body):
            found.add(m.group(1))

        # fetch / axios calls
        for m in _FETCH_RE.finditer(body):
            found.add(m.group(1))

        # Resolve relative URLs
        resolved = []
        for raw in found:
            raw = raw.strip()
            if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#")):
                continue
            try:
                full = urljoin(base_url, raw)
                parsed = urlparse(full)
                if parsed.scheme in ("http", "https"):
                    resolved.append(full)
            except Exception:
                continue

        return resolved

    def _empty_result(self) -> Dict[str, Any]:
        return {
            "all_urls": [],
            "in_scope_urls": [],
            "js_urls": [],
            "api_candidates": [],
            "page_contents": [],
            "stats": {},
        }
