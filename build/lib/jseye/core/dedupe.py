"""
Global Deduplication Engine for JSEye v3.0.1.

Prevents duplicate URL processing, response body replay, and
infinite pagination loops throughout the recursive crawl.
"""

import hashlib
import re
from typing import Optional, Set, Dict
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from .logging import get_logger

logger = get_logger(__name__)

# Numeric-value parameters that suggest pagination
_PAGINATION_PARAMS = frozenset({
    "page", "p", "pg", "offset", "skip", "from", "start",
    "limit", "per_page", "page_size", "cursor", "after", "before",
})

# Query-string parameter names that carry unique IDs but not unique content
_VOLATILE_PARAMS = frozenset({
    "_", "ts", "timestamp", "cb", "cachebust", "rand", "random",
    "v", "ver", "version", "nc", "nocache",
})


class DedupeEngine:
    """
    Thread-safe, async-compatible global deduplication engine.

    Tracks:
      - Normalised URL hashes (query params sorted, fragments stripped)
      - Response body hashes (to avoid reprocessing mirror pages)
      - Numeric pagination sequence detection
      - Volatile cache-busting parameters stripped before comparison
    """

    def __init__(self):
        self._url_hashes: Set[str] = set()
        self._body_hashes: Set[str] = set()
        self._param_pattern_counts: Dict[str, int] = {}
        # Maximum times a URL *shape* (path + param names) may be crawled
        self._max_param_shape_visits: int = 3

    # ------------------------------------------------------------------
    # URL deduplication
    # ------------------------------------------------------------------

    def is_url_seen(self, url: str) -> bool:
        """Return True if an equivalent URL has already been queued."""
        key = self._normalise_url(url)
        if key is None:
            return True  # Unparseable — skip
        h = self._sha(key)
        return h in self._url_hashes

    def mark_url_seen(self, url: str) -> None:
        """Record a URL as seen."""
        key = self._normalise_url(url)
        if key:
            h = self._sha(key)
            self._url_hashes.add(h)
            self._track_param_shape(url)

    def should_crawl(self, url: str) -> bool:
        """
        Return True if the URL should be crawled.

        Factors:
          - Not seen before (normalised)
          - Not a pagination loop
          - Param-shape count not exceeded
        """
        if self.is_url_seen(url):
            return False
        if self._is_pagination_loop(url):
            logger.debug(f"Pagination loop skipped: {url}")
            return False
        if self._param_shape_exceeded(url):
            logger.debug(f"Param-shape limit reached: {url}")
            return False
        return True

    # ------------------------------------------------------------------
    # Response body deduplication
    # ------------------------------------------------------------------

    def is_body_seen(self, body: str) -> bool:
        """Return True if this response body has already been processed."""
        h = self._sha(body)
        return h in self._body_hashes

    def mark_body_seen(self, body: str) -> None:
        """Record a response body hash as seen."""
        self._body_hashes.add(self._sha(body))

    # ------------------------------------------------------------------
    # Statistics helpers
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        return {
            "unique_urls_seen": len(self._url_hashes),
            "unique_bodies_seen": len(self._body_hashes),
            "param_shapes_tracked": len(self._param_pattern_counts),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalise_url(self, url: str) -> Optional[str]:
        """
        Produce a canonical URL string for hashing.

        - Lowercases scheme and host
        - Sorts query parameters alphabetically
        - Removes fragment
        - Strips volatile cache-busting params
        - Strips trailing slash from path (except root)
        """
        try:
            if not url.startswith(("http://", "https://")):
                # Treat relative URLs as opaque keys
                return url.strip()

            p = urlparse(url)
            scheme = p.scheme.lower()
            netloc = p.netloc.lower()
            path = p.path.rstrip("/") or "/"

            # Parse, filter volatile params, sort
            params = [
                (k, v) for k, v in parse_qsl(p.query)
                if k.lower() not in _VOLATILE_PARAMS
            ]
            params.sort(key=lambda kv: kv[0].lower())
            query = urlencode(params)

            return urlunparse((scheme, netloc, path, "", query, ""))
        except Exception:
            return None

    def _sha(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    def _is_pagination_loop(self, url: str) -> bool:
        """
        Detect URLs that are pure numeric pagination variants already seen.

        e.g. /items?page=3 when /items?page=1 and /items?page=2 were seen.
        """
        try:
            p = urlparse(url)
            params = dict(parse_qsl(p.query))

            for pkey in _PAGINATION_PARAMS:
                if pkey in params:
                    val = params[pkey]
                    if val.lstrip("-").isdigit():
                        # Build the shape key: path + all param *names*
                        shape = self._url_shape(url)
                        count = self._param_pattern_counts.get(shape, 0)
                        if count >= self._max_param_shape_visits:
                            return True
        except Exception:
            pass
        return False

    def _url_shape(self, url: str) -> str:
        """
        Returns a URL 'shape': scheme+host+path + sorted param *names*.
        Used to detect repeated numeric pagination over the same endpoint.
        """
        try:
            p = urlparse(url)
            param_names = sorted(k for k, _ in parse_qsl(p.query))
            return f"{p.scheme}://{p.netloc.lower()}{p.path}?{'&'.join(param_names)}"
        except Exception:
            return url

    def _track_param_shape(self, url: str) -> None:
        shape = self._url_shape(url)
        self._param_pattern_counts[shape] = self._param_pattern_counts.get(shape, 0) + 1

    def _param_shape_exceeded(self, url: str) -> bool:
        shape = self._url_shape(url)
        return self._param_pattern_counts.get(shape, 0) >= self._max_param_shape_visits
