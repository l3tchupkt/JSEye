import pytest
from jseye.core.scope import ScopeEngine

def test_scope_derivation():
    engine = ScopeEngine("https://example.com")
    assert engine.root_domain == "example.com"
    
    engine = ScopeEngine("api.example.com")
    # Subdomain provided, registered domain should still be example.com
    assert engine.root_domain == "example.com"

def test_is_in_scope():
    engine = ScopeEngine("https://example.com")
    
    assert engine.is_in_scope("https://example.com/api/v1") is True
    assert engine.is_in_scope("https://api.example.com/data") is True
    assert engine.is_in_scope("https://www.example.com/home") is True
    
    assert engine.is_in_scope("https://google.com") is False
    assert engine.is_in_scope("https://example.org") is False
    assert engine.is_in_scope("https://myexample.com") is False

def test_filter_urls():
    engine = ScopeEngine("example.com")
    urls = [
        "https://example.com/1",
        "https://api.example.com/2",
        "https://google.com",
        "https://example.org/3"
    ]
    
    in_scope, external = engine.filter_urls(urls)
    
    assert len(in_scope) == 2
    assert len(external) == 2
    assert "https://google.com" in external
    assert len(engine.external_refs) == 2
