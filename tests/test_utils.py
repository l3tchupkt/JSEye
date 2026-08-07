import pytest
from jseye.core.utils import (
    normalize_url, extract_domain, calculate_sha256, 
    decode_base64, is_js_file, mask_secret
)

def test_normalize_url():
    assert normalize_url("/api/test", "https://example.com") == "https://example.com/api/test"
    assert normalize_url("https://example.com/api?a=1#frag") == "https://example.com/api?a=1"

def test_extract_domain():
    assert extract_domain("https://api.example.com/v1") == "example.com"
    assert extract_domain("http://www.google.co.uk/") == "google.co.uk"

def test_calculate_sha256():
    expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # sha256("test")
    assert calculate_sha256("test") == expected

def test_decode_base64():
    assert decode_base64("SGVsbG8gV29ybGQ=") == "Hello World"
    assert decode_base64("aW52YWxpZA") == "invalid"  # Handles missing padding
    assert decode_base64("not_base64_!@#") is None

def test_is_js_file():
    assert is_js_file("https://example.com/app.js") is True
    assert is_js_file("https://example.com/app.js?v=123") is True
    assert is_js_file("https://example.com/script.min.js") is True
    assert is_js_file("https://example.com/index.html") is False

def test_mask_secret():
    assert mask_secret("supersecretkey1234", 4) == "supe**********1234"
    assert mask_secret("short", 4) == "*****"
