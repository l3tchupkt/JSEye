import pytest
import asyncio
from unittest.mock import AsyncMock, patch

from jseye.core.dependency_analyzer import DependencyAnalyzer

@pytest.fixture
def analyzer():
    return DependencyAnalyzer(timeout=1, max_concurrent=5)

@pytest.mark.asyncio
async def test_extract_dependencies(analyzer):
    package_data = {
        'dependencies': {'express': '^4.17.1'},
        'devDependencies': {'jest': '^27.0.0'}
    }
    deps = analyzer.extract_dependencies(package_data)
    assert 'dependencies' in deps
    assert deps['dependencies']['express'] == '^4.17.1'
    assert deps['devDependencies']['jest'] == '^27.0.0'

@pytest.mark.asyncio
async def test_is_likely_private(analyzer):
    # Public standard package
    is_private, _ = analyzer.is_likely_private('react')
    assert not is_private
    
    # Scoped private pattern
    is_private, _ = analyzer.is_likely_private('@company/internal-tools')
    assert is_private
    
    # Suffix private pattern
    is_private, _ = analyzer.is_likely_private('auth-service-internal')
    assert is_private

@pytest.mark.asyncio
async def test_check_version_suspicion(analyzer):
    # Suspicious versions
    is_suspicious, _ = analyzer.check_version_suspicion('0.0.1-dev')
    assert is_suspicious
    
    # Normal versions
    is_suspicious, _ = analyzer.check_version_suspicion('1.0.0')
    assert not is_suspicious

@pytest.mark.asyncio
async def test_check_npm_registry_rate_limit(analyzer):
    # Test rate limit logic (HTTP 429) using a mock session
    class MockResponse:
        def __init__(self, status):
            self.status = status
            
        async def __aenter__(self):
            return self
            
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
        async def json(self):
            return {'name': 'test-pkg', 'dist-tags': {'latest': '1.0.0'}}

    class MockSession:
        def __init__(self):
            self.call_count = 0
            
        def get(self, url):
            self.call_count += 1
            if self.call_count == 1:
                return MockResponse(429)
            return MockResponse(200)

    analyzer.session = MockSession()
    
    # We patch asyncio.sleep to not actually sleep during tests
    with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
        result = await analyzer.check_npm_registry('test-pkg')
        assert result['exists'] is True
        assert analyzer.session.call_count == 2
        mock_sleep.assert_called_once()
