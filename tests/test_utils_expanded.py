"""Expanded tests for utils functions and edge-case fixes."""

from jseye.core.utils import (
    clean_js_content,
    extract_endpoints_from_js,
    extract_js_strings,
    extract_parameters_from_url,
    normalize_url,
)


def test_normalize_url_relative_without_base():
    # Crucial bug fix: must not prepend ':///' to relative paths
    res = normalize_url("/api/v1/users")
    assert res == "/api/v1/users"
    assert ":///" not in res

    res_with_query = normalize_url("/search?q=test&page=2")
    assert res_with_query == "/search?q=test&page=2"
    assert ":///" not in res_with_query


def test_normalize_url_protocol_relative():
    # Protocol-relative URLs
    res = normalize_url("//example.com/api/v1")
    assert res == "https://example.com/api/v1"

    res_base = normalize_url("//example.com/api/v1", base_url="http://other.com")
    assert res_base == "http://example.com/api/v1"


def test_normalize_url_casing_and_fragments():
    url = "HTTPS://API.Example.Com:8443/v1/users#section"
    normalized = normalize_url(url)
    assert normalized == "https://api.example.com:8443/v1/users"


def test_extract_js_strings_full_literals():
    # Crucial bug fix: regex non-capturing group must extract entire string literals, not just last char
    content = """
    const apiEndpoint = "https://api.example.com/v1/checkout";
    const token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
    let path = `/users/${userId}/profile`;
    var short = 'hi';
    """
    strings = extract_js_strings(content)

    assert "https://api.example.com/v1/checkout" in strings
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" in strings
    # Ensure full strings were extracted, not single characters like 't' or '5'
    assert all(len(s) > 3 for s in strings)


def test_extract_js_strings_escaped_quotes():
    content = r"""
    const text1 = 'Don\'t touch this';
    const text2 = "She said \"hello\" to everyone";
    """
    strings = extract_js_strings(content)
    assert any("Don't touch this" in s for s in strings)
    assert any('She said "hello" to everyone' in s for s in strings)


def test_clean_js_content_preserves_urls():
    # Crucial bug fix: stripping // comments must not corrupt https:// URLs
    content = """
    // This is a line comment
    const apiUrl = "https://api.example.com/v1/users";
    /* Block comment
       spanning multiple lines */
    const isReady = true;
    """
    cleaned = clean_js_content(content)
    assert "https://api.example.com/v1/users" in cleaned
    assert "This is a line comment" not in cleaned
    assert "Block comment" not in cleaned


def test_extract_endpoints_from_js():
    js = """
    fetch("/api/v1/login", { method: "POST" });
    axios.get("/v2/users/search");
    loadScript("legacy.php");
    """
    endpoints = extract_endpoints_from_js(js)
    assert "/api/v1/login" in endpoints
    assert "/v2/users/search" in endpoints
    assert "legacy.php" in endpoints


def test_extract_parameters_from_url():
    url = "https://example.com/search?q=test&category=security&page=1&sort=desc"
    params = extract_parameters_from_url(url)
    assert set(params) == {"q", "category", "page", "sort"}

    # No query params
    assert extract_parameters_from_url("https://example.com/profile") == []

