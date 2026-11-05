"""Tests for DependencyAnalyzer.discover_and_analyze."""

from unittest.mock import AsyncMock, patch

import pytest

from jseye.core.dependency_analyzer import DependencyAnalyzer


@pytest.mark.asyncio
async def test_discover_and_analyze_with_manifest():
    mock_manifest = {
        'url': 'https://example.com/package.json',
        'source': '/package.json',
        'data': {
            'name': 'test-app',
            'dependencies': {
                '@company/private-pkg': '1.0.0',
                'public-pkg': '2.0.0'
            }
        },
        'type': 'package.json'
    }

    mock_npm_response = {
        '@company/private-pkg': {'exists': True, 'name': '@company/private-pkg'},
        'public-pkg': {'exists': True, 'name': 'public-pkg'}
    }

    async with DependencyAnalyzer(timeout=5) as analyzer:
        with patch.object(analyzer, 'discover_package_files', new=AsyncMock(return_value=[mock_manifest])):
            with patch.object(analyzer, 'check_npm_registry', side_effect=lambda name: mock_npm_response.get(name, {'exists': True})):
                result = await analyzer.discover_and_analyze(
                    js_files=[{'url': 'https://example.com/bundle.js'}],
                    urls=['https://example.com']
                )

                assert result['success'] is True
                assert 'statistics' in result
                assert 'vulnerable_dependencies' in result
                assert result['statistics']['confusion_risk'] >= 1
                assert len(result['vulnerable_dependencies']) >= 1
                vuln = result['vulnerable_dependencies'][0]
                assert vuln['name'] == '@company/private-pkg'
                assert vuln['severity'] == 'CRITICAL'


@pytest.mark.asyncio
async def test_discover_and_analyze_no_manifests():
    async with DependencyAnalyzer(timeout=5) as analyzer:
        with patch.object(analyzer, 'discover_package_files', new=AsyncMock(return_value=[])):
            result = await analyzer.discover_and_analyze([], ['https://example.com'])
            assert result['success'] is False
            assert result['statistics']['total_dependencies'] == 0
            assert result['vulnerable_dependencies'] == []

