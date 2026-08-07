import pytest
from jseye.core.dedupe import DedupeEngine

@pytest.fixture
def dedupe():
    return DedupeEngine()

def test_url_normalisation_and_deduplication(dedupe):
    # Base URL
    url1 = "https://example.com/api/data?b=2&a=1"
    # Same URL, different query param order
    url2 = "https://example.com/api/data?a=1&b=2"
    # Same URL with volatile params
    url3 = "https://example.com/api/data?b=2&a=1&_=123456789"
    # Different URL
    url4 = "https://example.com/api/other"
    
    assert dedupe.is_url_seen(url1) is False
    dedupe.mark_url_seen(url1)
    
    assert dedupe.is_url_seen(url1) is True
    assert dedupe.is_url_seen(url2) is True
    assert dedupe.is_url_seen(url3) is True
    assert dedupe.is_url_seen(url4) is False

def test_pagination_loop_detection(dedupe):
    url1 = "https://example.com/api?page=1"
    url2 = "https://example.com/api?page=2"
    url3 = "https://example.com/api?page=3"
    url4 = "https://example.com/api?page=4"
    
    assert dedupe.should_crawl(url1) is True
    dedupe.mark_url_seen(url1)
    
    assert dedupe.should_crawl(url2) is True
    dedupe.mark_url_seen(url2)
    
    assert dedupe.should_crawl(url3) is True
    dedupe.mark_url_seen(url3)
    
    # 4th visit with same parameter shape should trigger pagination loop detection
    # because max_param_shape_visits is 3
    assert dedupe.should_crawl(url4) is False

def test_body_deduplication(dedupe):
    body1 = "<html><body>Test</body></html>"
    body2 = "<html><body>Test</body></html>"
    body3 = "<html><body>Different</body></html>"
    
    assert dedupe.is_body_seen(body1) is False
    dedupe.mark_body_seen(body1)
    
    assert dedupe.is_body_seen(body2) is True
    assert dedupe.is_body_seen(body3) is False
