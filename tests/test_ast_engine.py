import pytest
from jseye.core.ast_engine import JSASTAnalyzer

@pytest.fixture
def ast_analyzer():
    return JSASTAnalyzer()

def test_analyze_variables(ast_analyzer):
    content = '''
    const apiUrl = "https://api.example.com/v1";
    let count = 10;
    '''
    result = ast_analyzer.analyze(content, "test.js")
    
    variables = result['variables']
    
    api_url_var = next((v for v in variables if v['name'] == 'apiUrl'), None)
    assert api_url_var is not None
    assert api_url_var['value'] == '"https://api.example.com/v1"'
    assert api_url_var['type'] == 'string'

def test_analyze_endpoints(ast_analyzer):
    content = '''
    fetch("/api/users/12345");
    const uuidPath = "/api/resource/123e4567-e89b-12d3-a456-426614174000";
    '''
    result = ast_analyzer.analyze(content, "test.js")
    
    endpoints = result['endpoints']
    assert len(endpoints) == 2
    
    normalized_urls = [ep['normalized'] for ep in endpoints]
    assert "/api/users/{id}" in normalized_urls
    assert "/api/resource/{uuid}" in normalized_urls

def test_clean_js_content(ast_analyzer):
    content = '''
    // This is a comment
    const url = "https://example.com/api"; // URL comment
    /* Multi-line
       comment */
    '''
    cleaned = ast_analyzer._clean_js_content(content)
    
    assert "// This is a comment" not in cleaned
    assert "Multi-line" not in cleaned
    assert 'const url = "https://example.com/api";' in cleaned
