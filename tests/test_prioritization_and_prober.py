"""Tests for PrioritizationEngine, PrioritizedEndpointsList, and ActiveProber safety."""

from jseye.core.active_prober import ActiveProber
from jseye.core.api_engine import APIIntelligence
from jseye.core.prioritization import PrioritizationEngine, PrioritizedEndpointsList


def test_prioritized_endpoints_list_dual_behavior():
    # Must behave as both a list and support .get(level) for dictionary compatibility
    prio_list = PrioritizedEndpointsList([
        {'url': '/api/admin', 'priority': 'high', 'priority_level': 'high'},
        {'url': '/metrics', 'priority': 'medium', 'priority_level': 'medium'},
        {'url': '/about', 'priority': 'low', 'priority_level': 'low'}
    ])

    # List behavior
    assert len(prio_list) == 3
    assert prio_list[0]['url'] == '/api/admin'
    assert isinstance(prio_list, list)

    # Dict-like .get() behavior for cli.py
    high_eps = prio_list.get('high', [])
    assert len(high_eps) == 1
    assert high_eps[0]['url'] == '/api/admin'

    med_eps = prio_list.get('medium', [])
    assert len(med_eps) == 1

    unknown = prio_list.get('unknown', 'default')
    assert unknown == 'default'


def test_prioritization_engine_produces_prioritized_endpoints():
    engine = PrioritizationEngine()
    results = {
        'endpoints': [
            '/api/v1/admin/users',
            '/api/v1/debug/info',
            '/static/bundle.js'
        ],
        'secrets': [],
        'vulnerabilities': []
    }

    prioritized = engine.prioritize_findings(results)
    assert 'prioritized_endpoints' in prioritized
    prio_eps = prioritized['prioritized_endpoints']
    assert isinstance(prio_eps, PrioritizedEndpointsList)
    assert len(prio_eps) >= 1
    # Check that high/critical endpoints are ranked
    high_or_crit = prio_eps.get('high', []) + prio_eps.get('critical', [])
    assert len(high_or_crit) >= 1


def test_active_prober_ssrf_safety():
    prober = ActiveProber()

    # Public targets allowed
    assert prober._is_safe_url("https://example.com/api/test") is True

    # Private / internal targets blocked by default
    assert prober._is_safe_url("http://127.0.0.1:8000/api") is False
    assert prober._is_safe_url("http://localhost/admin") is False
    assert prober._is_safe_url("http://169.254.169.254/latest/meta-data/") is False
    assert prober._is_safe_url("http://10.0.0.1/status") is False
    assert prober._is_safe_url("http://192.168.1.1/router") is False


def test_api_intelligence_passive_vs_active_safety():
    # Passive mode (default): active_probing=False
    passive_api = APIIntelligence(active_probing=False)
    assert passive_api.active_probing is False

    # Active mode
    active_api = APIIntelligence(active_probing=True)
    assert active_api.active_probing is True

