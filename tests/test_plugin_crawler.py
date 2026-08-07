import pytest
import asyncio
from unittest.mock import AsyncMock, patch

from jseye.core.plugin_crawler import PluginBasedCrawler

@pytest.fixture
def crawler():
    config = {
        'timeout': 1, 
        'silent': True, 
        'headless': False,
        'profile_scan': False,
        'generate_graph': False,
        'output_dir': None
    }
    return PluginBasedCrawler(config)

@pytest.mark.asyncio
async def test_plugin_crawler_init(crawler):
    assert crawler.timeout == 1
    assert crawler.enable_wayback is True
    assert crawler.results['target'] == ''

@pytest.mark.asyncio
async def test_crawler_scan_target(crawler):
    # Mock the internal methods to prevent network calls
    with patch.object(crawler, '_collect_javascript_files', new_callable=AsyncMock) as mock_collect, \
         patch.object(crawler, '_setup_plugins', new_callable=AsyncMock) as mock_setup, \
         patch.object(crawler, '_execute_plugins', new_callable=AsyncMock) as mock_execute:
        
        mock_collect.return_value = [{'url': 'https://example.com/app.js', 'content': 'console.log("hello");'}]
        mock_execute.return_value = {}
        
        # Patch output manager to avoid writing files
        with patch.object(crawler.output_manager, 'persist_all') as mock_persist:
            result = await crawler.scan_target('example.com')
            
            assert result['target'] == 'example.com'
            assert len(result['js_files']) == 1
            mock_collect.assert_called_once_with('example.com')
            mock_setup.assert_called_once()
            mock_execute.assert_called_once()
            mock_persist.assert_called_once()
