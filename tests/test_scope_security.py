"""Security and edge-case tests for ScopeEngine."""

from jseye.core.scope import ScopeEngine, is_private_ip


def test_is_private_ip_detection():
    # IPv4 Private / Loopback / Link-Local
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("127.0.0.2") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("169.254.169.254") is True
    assert is_private_ip("0.0.0.0") is True

    # IPv6 Private / Loopback
    assert is_private_ip("::1") is True
    assert is_private_ip("fc00::1") is True

    # Public IPs & Domain Names
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False
    assert is_private_ip("example.com") is False
    assert is_private_ip("") is False


def test_protocol_relative_url_handling():
    engine = ScopeEngine("https://example.com")

    # In-scope protocol-relative URL
    assert engine.is_in_scope("//example.com/assets/app.js") is True
    assert engine.is_in_scope("//api.example.com/v1/auth") is True

    # Out-of-scope protocol-relative URL (scope bypass attempt)
    assert engine.is_in_scope("//evil.com/malicious.js") is False
    assert engine.is_in_scope("//attacker.net/exploit.js") is False


def test_ssrf_blocking_for_public_targets():
    engine = ScopeEngine("https://example.com", allow_private_ips=False)

    # SSRF / private IP targets must be blocked
    assert engine.is_in_scope("http://127.0.0.1/admin") is False
    assert engine.is_in_scope("http://localhost:8080/metrics") is False
    assert engine.is_in_scope("http://169.254.169.254/latest/meta-data/") is False
    assert engine.is_in_scope("http://192.168.1.100/debug") is False
    assert engine.is_in_scope("http://10.0.0.5:3000") is False


def test_explicit_local_target_allows_testing():
    # When scanning local labs or staging environments explicitly
    engine = ScopeEngine("http://127.0.0.1:8000")
    assert engine.allow_private_ips is True
    assert engine.is_in_scope("http://127.0.0.1:8000/api/users") is True


def test_subdomain_control():
    # Default: allow subdomains
    engine_subs = ScopeEngine("https://app.example.com", allow_subdomains=True)
    assert engine_subs.is_in_scope("https://api.example.com/v1") is True
    assert engine_subs.is_in_scope("https://app.example.com/v1") is True

    # No subdomains mode: only exact target hostname is in scope
    engine_nosubs = ScopeEngine("https://app.example.com", allow_subdomains=False)
    assert engine_nosubs.is_in_scope("https://app.example.com/v1") is True
    assert engine_nosubs.is_in_scope("https://api.example.com/v1") is False


def test_non_http_pseudo_protocols():
    engine = ScopeEngine("https://example.com")
    assert engine.is_in_scope("javascript:alert(1)") is False
    assert engine.is_in_scope("data:text/html,<script>alert(1)</script>") is False
    assert engine.is_in_scope("mailto:admin@example.com") is False
    assert engine.is_in_scope("file:///etc/passwd") is False


def test_relative_paths():
    engine = ScopeEngine("https://example.com")
    assert engine.is_in_scope("/api/v1/users") is True
    assert engine.is_in_scope("./static/bundle.js") is True
    assert engine.is_in_scope("../auth/login") is True

