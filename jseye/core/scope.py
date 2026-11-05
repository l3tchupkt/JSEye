"""
Automatic Scope Derivation Engine for JSEye.

Derives the scan scope from a target URL — no scope file needed.
Any URL matching the root domain or its subdomains is in-scope.
External domains are recorded as references but never actively crawled.
Also protects against SSRF (private / loopback / link-local IPs) and
protocol-relative URL scope escapes.
"""

import ipaddress
from typing import Optional, Set
from urllib.parse import urlparse

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

from .logging import get_logger

logger = get_logger(__name__)


def is_private_ip(hostname: str) -> bool:
    """Return True if hostname is an IP address in private, loopback, or reserved space."""
    if not hostname:
        return False
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return False


class ScopeEngine:
    """
    Derives and enforces scan scope from an input URL.

    Scope rules:
      - Matches root domain (e.g., example.com) and subdomains (if allow_subdomains is True)
      - Matches target hostname exactly when allow_subdomains is False
      - Rejects protocol-relative escapes (//evil.com/...)
      - Rejects private/loopback IPs by default to prevent SSRF
      - Does NOT crawl external domains
      - Records external domain references for reporting
    """

    def __init__(self, target: str, allow_subdomains: bool = True, allow_private_ips: Optional[bool] = None):
        self.target = target
        self.allow_subdomains: bool = allow_subdomains
        self.target_hostname: str = ""
        self.root_domain: str = ""
        self.registered_domain: str = ""
        self.in_scope_domains: Set[str] = set()
        self.external_refs: Set[str] = set()

        self._derive_scope(target)

        # If user explicitly scanned localhost or a private IP, allow private IPs for this scan
        if allow_private_ips is None:
            self.allow_private_ips = (
                is_private_ip(self.target_hostname)
                or self.target_hostname in ("localhost", "127.0.0.1", "::1")
                or self.target_hostname.endswith(".localhost")
            )
        else:
            self.allow_private_ips = allow_private_ips

    def _derive_scope(self, target: str) -> None:
        """Derive scope from target input."""
        # Normalise the input — add scheme if missing
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        parsed = urlparse(target)
        self.target_hostname = (parsed.hostname or "").lower()

        if _HAS_TLDEXTRACT:
            ext = tldextract.extract(self.target_hostname)
            if ext.domain and ext.suffix:
                self.registered_domain = f"{ext.domain}.{ext.suffix}"
                self.root_domain = self.registered_domain
            else:
                # Fallback for IPs or unusual TLDs
                self.root_domain = self.target_hostname
                self.registered_domain = self.target_hostname
        else:
            # Naive fallback: take last two parts of hostname
            parts = self.target_hostname.split(".")
            if len(parts) >= 2:
                self.registered_domain = ".".join(parts[-2:])
            else:
                self.registered_domain = self.target_hostname
            self.root_domain = self.registered_domain

        # Root + wildcard subdomain are in scope
        self.in_scope_domains.add(self.root_domain)
        if self.target_hostname:
            self.in_scope_domains.add(self.target_hostname)
        logger.info(f"Scope derived: root={self.root_domain}, target={self.target_hostname}, allow_subs={self.allow_subdomains}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_in_scope(self, url: str) -> bool:
        """Return True if the URL falls within the derived scope."""
        if not url or not isinstance(url, str):
            return False

        url = url.strip()
        if not url:
            return False

        # Block pseudo-protocols
        lower_url = url.lower()
        if lower_url.startswith(("javascript:", "data:", "mailto:", "file:", "vbscript:", "blob:")):
            return False

        # Protocol-relative URLs: e.g. //evil.com/path
        if url.startswith("//"):
            try:
                parsed = urlparse("https:" + url)
                hostname = parsed.hostname or ""
                return self._hostname_in_scope(hostname)
            except Exception:
                return False

        # Relative paths
        if not url.startswith(("http://", "https://")):
            # If the first segment before a slash has a colon, it's likely a custom scheme
            first_segment = url.split("/")[0]
            if ":" in first_segment:
                return False
            return True

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""

            if not hostname:
                return False

            return self._hostname_in_scope(hostname)

        except Exception as e:
            logger.debug(f"Scope check error for {url}: {e}")
            return False

    def _hostname_in_scope(self, hostname: str) -> bool:
        """Check if a hostname is within scope."""
        if not hostname:
            return False

        # Strip port and trailing dots
        hostname = hostname.split(":")[0].lower().rstrip(".")

        # SSRF check: private / loopback IP protection
        if not self.allow_private_ips:
            if hostname == "localhost" or hostname.endswith(".localhost"):
                return False
            if is_private_ip(hostname):
                return False

        # Exact match to target hostname
        if hostname == self.target_hostname:
            return True

        # If subdomains are disallowed, only target hostname is in scope
        if not self.allow_subdomains:
            return False

        root = self.root_domain.lower()

        # Exact match to root domain
        if hostname == root:
            return True

        # Subdomain match
        if root and hostname.endswith("." + root):
            return True

        return False

    def record_external(self, url: str) -> None:
        """Record an external URL reference without crawling it."""
        try:
            if url.startswith("//"):
                parsed = urlparse("https:" + url)
            else:
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
            "target_hostname": self.target_hostname,
            "registered_domain": self.registered_domain,
            "allow_subdomains": self.allow_subdomains,
            "allow_private_ips": self.allow_private_ips,
            "external_references_count": len(self.external_refs),
            "external_references": sorted(self.external_refs),
        }
