"""
Automatic Scope Derivation Engine for JSEye v3.0.1.

Derives the scan scope from a target URL — no scope file needed.
Any URL matching the root domain or its subdomains is in-scope.
External domains are recorded as references but never actively crawled.
"""

import re
from typing import Optional, Set
from urllib.parse import urlparse

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

from .logging import get_logger

logger = get_logger(__name__)


class ScopeEngine:
    """
    Derives and enforces scan scope from an input URL.

    Scope rules:
      - Matches root domain exactly (e.g., example.com)
      - Matches any subdomain (e.g., api.example.com, app.example.com)
      - Does NOT crawl external domains
      - Records external domain references for reporting
    """

    def __init__(self, target: str):
        self.target = target
        self.root_domain: str = ""
        self.registered_domain: str = ""
        self.in_scope_domains: Set[str] = set()
        self.external_refs: Set[str] = set()

        self._derive_scope(target)

    def _derive_scope(self, target: str) -> None:
        """Derive scope from target input."""
        # Normalise the input — add scheme if missing
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        parsed = urlparse(target)
        hostname = parsed.hostname or ""

        if _HAS_TLDEXTRACT:
            ext = tldextract.extract(hostname)
            if ext.domain and ext.suffix:
                self.registered_domain = f"{ext.domain}.{ext.suffix}"
                self.root_domain = self.registered_domain
            else:
                # Fallback for IPs or unusual TLDs
                self.root_domain = hostname
                self.registered_domain = hostname
        else:
            # Naive fallback: take last two parts of hostname
            parts = hostname.split(".")
            if len(parts) >= 2:
                self.registered_domain = ".".join(parts[-2:])
            else:
                self.registered_domain = hostname
            self.root_domain = self.registered_domain

        # Root + wildcard subdomain are in scope
        self.in_scope_domains.add(self.root_domain)
        logger.info(f"Scope derived: root={self.root_domain}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_in_scope(self, url: str) -> bool:
        """Return True if the URL falls within the derived scope."""
        if not url:
            return False

        try:
            if not url.startswith(("http://", "https://")):
                # Relative path — always in scope
                return True

            parsed = urlparse(url)
            hostname = parsed.hostname or ""

            if not hostname:
                return False

            # Strip port
            hostname = hostname.split(":")[0].lower()

            return self._hostname_in_scope(hostname)

        except Exception as e:
            logger.debug(f"Scope check error for {url}: {e}")
            return False

    def _hostname_in_scope(self, hostname: str) -> bool:
        """Check if a hostname is within scope."""
        root = self.root_domain.lower()

        # Exact match
        if hostname == root:
            return True

        # Subdomain match
        if hostname.endswith("." + root):
            return True

        return False

    def record_external(self, url: str) -> None:
        """Record an external URL reference without crawling it."""
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            if hostname and not self._hostname_in_scope(hostname):
                self.external_refs.add(url)
        except Exception:
            pass

    def filter_urls(self, urls: list) -> tuple:
        """
        Split a list of URLs into (in_scope, external).

        Returns:
            in_scope  — list of URLs that are within scope
            external  — list of URLs outside scope (for recording only)
        """
        in_scope = []
        external = []

        for url in urls:
            if self.is_in_scope(url):
                in_scope.append(url)
            else:
                external.append(url)
                self.record_external(url)

        return in_scope, external

    def get_scope_summary(self) -> dict:
        """Return a JSON-serialisable summary of the current scope."""
        return {
            "root_domain": self.root_domain,
            "registered_domain": self.registered_domain,
            "external_references_count": len(self.external_refs),
            "external_references": sorted(self.external_refs),
        }
