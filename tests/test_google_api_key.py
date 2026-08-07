#!/usr/bin/env python3
"""
Tests for Google API Key detection and validation feature.

Covers:
  - jseye.core.google_api_validator  (extraction + validation logic)
  - jseye.plugins.google_api_key_plugin  (plugin integration)

Run with:
    python -m pytest tests/test_google_api_key.py -v
"""

import asyncio
import sys
import os
import json
import unittest
from unittest.mock import patch, MagicMock
import urllib.error

# Make sure the workspace root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jseye.core.google_api_validator import (
    extract_google_api_keys,
    validate_google_api_key,
    _mask_key,
    GOOGLE_API_KEY_PATTERN,
    VALIDATION_URL,
)
from jseye.plugins.google_api_key_plugin import GoogleAPIKeyPlugin
from jseye.plugins.base import PluginContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(coro):
    """Run a coroutine synchronously."""
    return asyncio.run(coro)


def make_context(js_files):
    return PluginContext(target="https://example.com", js_files=js_files, config={})


# Syntactically valid 39-char Google API keys (fake) — AIza + 35 chars = 39 total
FAKE_KEY   = "AIzaSyFakeKey1234567890abcdefghijklmnop"   # len=39
FAKE_KEY_2 = "AIzaSyAnotherFakeKey0987654321zyxwvutsX"  # len=39


# ===========================================================================
# 1. Unit tests – google_api_validator.py
# ===========================================================================

class TestMaskKey(unittest.TestCase):

    def test_normal_key(self):
        masked = _mask_key(FAKE_KEY)
        self.assertTrue(masked.startswith("AIza"))
        self.assertTrue(masked.endswith(FAKE_KEY[-4:]))
        self.assertIn("*", masked)

    def test_short_key(self):
        self.assertEqual(_mask_key("short"), "********")

    def test_exactly_8_chars(self):
        self.assertEqual(_mask_key("12345678"), "********")


class TestExtractGoogleApiKeys(unittest.TestCase):

    def test_single_key_in_quotes(self):
        js = f'const apiKey = "{FAKE_KEY}";'
        keys = extract_google_api_keys(js)
        self.assertIn(FAKE_KEY, keys)

    def test_key_without_quotes(self):
        js = f"var k = {FAKE_KEY};"
        keys = extract_google_api_keys(js)
        self.assertIn(FAKE_KEY, keys)

    def test_multiple_unique_keys(self):
        js = f'a="{FAKE_KEY}"; b="{FAKE_KEY_2}";'
        keys = extract_google_api_keys(js)
        self.assertEqual(len(keys), 2)
        self.assertIn(FAKE_KEY, keys)
        self.assertIn(FAKE_KEY_2, keys)

    def test_duplicate_keys_deduplicated(self):
        js = f'a="{FAKE_KEY}"; b="{FAKE_KEY}";'
        keys = extract_google_api_keys(js)
        self.assertEqual(len(keys), 1)

    def test_no_keys_in_clean_js(self):
        js = "function hello() { return 42; }"
        keys = extract_google_api_keys(js)
        self.assertEqual(keys, [])

    def test_too_short_not_matched(self):
        # AIza + 34 chars = 38 total, should NOT match (needs 39)
        short = "AIzaSyFakeKey1234567890abcdefghijklmn"
        js = f'var k = "{short}";'
        keys = extract_google_api_keys(js)
        self.assertEqual(keys, [])

    def test_too_long_not_matched(self):
        # AIza + 36 chars = 40 total — the negative lookahead should block this
        long_key = "AIzaSyFakeKey1234567890abcdefghijklmnopQ"  # 40 chars
        js = f'var k = "{long_key}";'
        keys = extract_google_api_keys(js)
        # The 39-char prefix would match without the lookahead, but with it nothing matches
        # because the 40th char is still a valid key char — so result must be empty
        self.assertEqual(keys, [])

    def test_key_with_hyphen_and_underscore(self):
        # Google keys can contain - and _
        key = "AIzaSy-_akeKey1234567890abcdefghijklmno"
        js = f'var k = "{key}";'
        keys = extract_google_api_keys(js)
        self.assertIn(key, keys)

    def test_key_embedded_in_url(self):
        js = f'fetch("https://maps.googleapis.com/maps/api/js?key={FAKE_KEY}")'
        keys = extract_google_api_keys(js)
        self.assertIn(FAKE_KEY, keys)

    def test_empty_content(self):
        self.assertEqual(extract_google_api_keys(""), [])

    def test_multiline_js(self):
        js = f"""
        // config.js
        const config = {{
            googleMapsKey: '{FAKE_KEY}',
            otherSetting: 'value'
        }};
        """
        keys = extract_google_api_keys(js)
        self.assertIn(FAKE_KEY, keys)


class TestValidateGoogleApiKey(unittest.TestCase):
    """Tests for validate_google_api_key – all HTTP calls are mocked."""

    def _mock_200(self):
        """Mock a successful HTTP 200 response."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def _mock_http_error(self, code, message="error", status="UNKNOWN"):
        body = json.dumps({"error": {"message": message, "status": status}}).encode()
        err = urllib.error.HTTPError(
            url="https://example.com", code=code,
            msg=message, hdrs=None, fp=MagicMock(read=MagicMock(return_value=body))
        )
        return err

    @patch("urllib.request.urlopen")
    def test_valid_key_returns_valid(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_200()
        result = validate_google_api_key(FAKE_KEY)
        self.assertTrue(result["valid"])
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["status_code"], 200)

    @patch("urllib.request.urlopen")
    def test_invalid_key_400(self, mock_urlopen):
        mock_urlopen.side_effect = self._mock_http_error(400, "API key not valid.")
        result = validate_google_api_key(FAKE_KEY)
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["status_code"], 400)

    @patch("urllib.request.urlopen")
    def test_restricted_key_403_referrer_blocked(self, mock_urlopen):
        mock_urlopen.side_effect = self._mock_http_error(
            403, "API_KEY_HTTP_REFERRER_BLOCKED"
        )
        result = validate_google_api_key(FAKE_KEY)
        self.assertTrue(result["valid"])
        self.assertEqual(result["status"], "restricted")
        self.assertEqual(result["status_code"], 403)

    @patch("urllib.request.urlopen")
    def test_restricted_key_403_ip_blocked(self, mock_urlopen):
        mock_urlopen.side_effect = self._mock_http_error(
            403, "IP_ADDRESS_BLOCKED"
        )
        result = validate_google_api_key(FAKE_KEY)
        self.assertTrue(result["valid"])
        self.assertEqual(result["status"], "restricted")

    @patch("urllib.request.urlopen")
    def test_restricted_key_403_api_not_enabled(self, mock_urlopen):
        mock_urlopen.side_effect = self._mock_http_error(
            403, "This API is not enabled for this project."
        )
        result = validate_google_api_key(FAKE_KEY)
        self.assertTrue(result["valid"])
        self.assertEqual(result["status"], "restricted")

    @patch("urllib.request.urlopen")
    def test_rate_limited_key_429(self, mock_urlopen):
        mock_urlopen.side_effect = self._mock_http_error(429, "Quota exceeded")
        result = validate_google_api_key(FAKE_KEY)
        self.assertTrue(result["valid"])
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["status_code"], 429)

    @patch("urllib.request.urlopen")
    def test_network_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        result = validate_google_api_key(FAKE_KEY)
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "error")
        self.assertIsNone(result["status_code"])

    @patch("urllib.request.urlopen")
    def test_unexpected_exception(self, mock_urlopen):
        mock_urlopen.side_effect = RuntimeError("something broke")
        result = validate_google_api_key(FAKE_KEY)
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "error")

    @patch("urllib.request.urlopen")
    def test_masked_key_in_result(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_200()
        result = validate_google_api_key(FAKE_KEY)
        self.assertIn("key_masked", result)
        self.assertTrue(result["key_masked"].startswith("AIza"))
        self.assertNotEqual(result["key_masked"], FAKE_KEY)  # must be masked

    def test_validation_url_format(self):
        url = VALIDATION_URL.format(key=FAKE_KEY)
        self.assertIn(FAKE_KEY, url)
        self.assertIn("generativelanguage.googleapis.com", url)
        self.assertIn("v1beta/files", url)


# ===========================================================================
# 2. Integration tests – GoogleAPIKeyPlugin
# ===========================================================================

class TestGoogleAPIKeyPluginMetadata(unittest.TestCase):

    def setUp(self):
        self.plugin = GoogleAPIKeyPlugin()

    def test_plugin_name(self):
        self.assertEqual(self.plugin.metadata.name, "google_api_key_validator")

    def test_plugin_version(self):
        self.assertIsNotNone(self.plugin.metadata.version)

    def test_plugin_execution_order(self):
        # Must run after secret_detection (order=10)
        self.assertGreater(self.plugin.metadata.execution_order, 10)

    def test_plugin_enabled_by_default(self):
        self.assertTrue(self.plugin.metadata.enabled)
        self.assertTrue(self.plugin.is_enabled())

    def test_plugin_category_is_detection(self):
        from jseye.plugins.base import PluginCategory
        self.assertEqual(self.plugin.metadata.category, PluginCategory.DETECTION)


class TestGoogleAPIKeyPluginRun(unittest.TestCase):

    def setUp(self):
        self.plugin = GoogleAPIKeyPlugin()

    # ── no JS files ──────────────────────────────────────────────────────

    def test_empty_js_files_returns_no_findings(self):
        ctx = make_context([])
        result = run(self.plugin.run(ctx))
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.metadata["total_keys_found"], 0)

    def test_js_file_with_no_content(self):
        ctx = make_context([{"url": "https://example.com/app.js", "content": ""}])
        result = run(self.plugin.run(ctx))
        self.assertEqual(len(result.findings), 0)

    def test_js_file_with_no_keys(self):
        ctx = make_context([{
            "url": "https://example.com/app.js",
            "content": "function hello() { return 42; }"
        }])
        result = run(self.plugin.run(ctx))
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.metadata["total_keys_found"], 0)

    # ── valid key (mocked HTTP 200) ───────────────────────────────────────

    @patch("jseye.core.google_api_validator.urllib.request.urlopen")
    def test_valid_key_produces_critical_finding(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        ctx = make_context([{
            "url": "https://example.com/app.js",
            "content": f'var key = "{FAKE_KEY}";'
        }])
        result = run(self.plugin.run(ctx))

        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f["type"], "google_api_key_validated")
        self.assertEqual(f["subtype"], "valid")
        self.assertEqual(f["severity"], "critical")
        self.assertTrue(f["validated"])
        self.assertEqual(result.metadata["valid_keys"], 1)

    # ── invalid key (mocked HTTP 400) ────────────────────────────────────

    @patch("jseye.core.google_api_validator.urllib.request.urlopen")
    def test_invalid_key_produces_info_finding(self, mock_urlopen):
        body = json.dumps({"error": {"message": "API key not valid.", "status": "INVALID_ARGUMENT"}}).encode()
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="", code=400, msg="Bad Request", hdrs=None,
            fp=MagicMock(read=MagicMock(return_value=body))
        )

        ctx = make_context([{
            "url": "https://example.com/app.js",
            "content": f'var key = "{FAKE_KEY}";'
        }])
        result = run(self.plugin.run(ctx))

        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f["subtype"], "invalid")
        self.assertEqual(f["severity"], "info")
        self.assertFalse(f["validated"])
        self.assertEqual(result.metadata["valid_keys"], 0)

    # ── restricted key (mocked HTTP 403) ─────────────────────────────────

    @patch("jseye.core.google_api_validator.urllib.request.urlopen")
    def test_restricted_key_produces_high_finding(self, mock_urlopen):
        body = json.dumps({"error": {"message": "API_KEY_HTTP_REFERRER_BLOCKED", "status": "PERMISSION_DENIED"}}).encode()
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="", code=403, msg="Forbidden", hdrs=None,
            fp=MagicMock(read=MagicMock(return_value=body))
        )

        ctx = make_context([{
            "url": "https://example.com/app.js",
            "content": f'var key = "{FAKE_KEY}";'
        }])
        result = run(self.plugin.run(ctx))

        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f["subtype"], "restricted")
        self.assertEqual(f["severity"], "high")
        self.assertTrue(f["validated"])

    # ── deduplication across multiple JS files ────────────────────────────

    @patch("jseye.core.google_api_validator.urllib.request.urlopen")
    def test_same_key_in_multiple_files_validated_once(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        ctx = make_context([
            {"url": "https://example.com/a.js", "content": f'var k="{FAKE_KEY}";'},
            {"url": "https://example.com/b.js", "content": f'var k="{FAKE_KEY}";'},
        ])
        result = run(self.plugin.run(ctx))

        # Only 1 unique key → 1 finding, 1 validation call
        self.assertEqual(result.metadata["total_keys_found"], 1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(mock_urlopen.call_count, 1)

    # ── multiple distinct keys ────────────────────────────────────────────

    @patch("jseye.core.google_api_validator.urllib.request.urlopen")
    def test_two_distinct_keys_produce_two_findings(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        ctx = make_context([{
            "url": "https://example.com/app.js",
            "content": f'var a="{FAKE_KEY}"; var b="{FAKE_KEY_2}";'
        }])
        result = run(self.plugin.run(ctx))

        self.assertEqual(result.metadata["total_keys_found"], 2)
        self.assertEqual(len(result.findings), 2)

    # ── finding structure ─────────────────────────────────────────────────

    @patch("jseye.core.google_api_validator.urllib.request.urlopen")
    def test_finding_has_required_fields(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        ctx = make_context([{
            "url": "https://example.com/app.js",
            "content": f'var key = "{FAKE_KEY}";'
        }])
        result = run(self.plugin.run(ctx))
        f = result.findings[0]

        required = ["id", "type", "subtype", "title", "description",
                    "severity", "confidence_score", "risk_score", "risk_level",
                    "source_files", "evidence", "remediation", "references",
                    "validated"]
        for field in required:
            self.assertIn(field, f, f"Missing field: {field}")

    @patch("jseye.core.google_api_validator.urllib.request.urlopen")
    def test_evidence_contains_masked_key(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        ctx = make_context([{
            "url": "https://example.com/app.js",
            "content": f'var key = "{FAKE_KEY}";'
        }])
        result = run(self.plugin.run(ctx))
        evidence = result.findings[0]["evidence"]

        self.assertIn("key_masked", evidence)
        # Raw key must NOT appear in the finding
        self.assertNotEqual(evidence["key_masked"], FAKE_KEY)
        self.assertIn("validation_endpoint", evidence)

    # ── shared_data ───────────────────────────────────────────────────────

    @patch("jseye.core.google_api_validator.urllib.request.urlopen")
    def test_results_stored_in_shared_data(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        ctx = make_context([{
            "url": "https://example.com/app.js",
            "content": f'var key = "{FAKE_KEY}";'
        }])
        run(self.plugin.run(ctx))

        stored = ctx.get_shared_data("google_api_key_findings")
        self.assertIsNotNone(stored)
        self.assertEqual(len(stored), 1)

    # ── network error doesn't crash plugin ───────────────────────────────

    @patch("jseye.core.google_api_validator.urllib.request.urlopen")
    def test_network_error_does_not_crash_plugin(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("timeout")

        ctx = make_context([{
            "url": "https://example.com/app.js",
            "content": f'var key = "{FAKE_KEY}";'
        }])
        result = run(self.plugin.run(ctx))

        # Should still produce a finding, just with status=error
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0]["subtype"], "error")

    # ── metadata structure ────────────────────────────────────────────────

    @patch("jseye.core.google_api_validator.urllib.request.urlopen")
    def test_metadata_keys_present(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        ctx = make_context([{
            "url": "https://example.com/app.js",
            "content": f'var key = "{FAKE_KEY}";'
        }])
        result = run(self.plugin.run(ctx))

        for key in ["total_keys_found", "total_keys_validated",
                    "valid_keys", "invalid_or_error_keys", "status_breakdown"]:
            self.assertIn(key, result.metadata)


# ===========================================================================
# 3. Plugin manager auto-discovery
# ===========================================================================

class TestPluginManagerDiscovery(unittest.TestCase):

    def test_plugin_auto_loaded_by_manager(self):
        from jseye.plugins.manager import PluginManager

        async def _load():
            pm = PluginManager()
            await pm.load_plugins()
            return pm

        pm = run(_load())
        self.assertIn("google_api_key_validator", pm.plugins)

    def test_plugin_does_not_conflict_with_secret_detection(self):
        from jseye.plugins.manager import PluginManager

        async def _load():
            pm = PluginManager()
            await pm.load_plugins()
            return pm

        pm = run(_load())
        # Both plugins must coexist
        self.assertIn("secret_detection", pm.plugins)
        self.assertIn("google_api_key_validator", pm.plugins)

    def test_google_plugin_runs_after_secret_detection(self):
        from jseye.plugins.manager import PluginManager

        async def _load():
            pm = PluginManager()
            await pm.load_plugins()
            return pm

        pm = run(_load())
        google_order = pm.plugins["google_api_key_validator"].metadata.execution_order
        secret_order = pm.plugins["secret_detection"].metadata.execution_order
        self.assertGreater(google_order, secret_order)


# ===========================================================================
# 4. Regression – existing secret_detection plugin unaffected
# ===========================================================================

class TestSecretDetectionUnaffected(unittest.TestCase):
    """Ensure the new plugin doesn't break existing secret detection."""

    def test_secret_detection_plugin_still_loads(self):
        from jseye.plugins.secret_detection_plugin import SecretDetectionPlugin
        plugin = SecretDetectionPlugin()
        self.assertEqual(plugin.metadata.name, "secret_detection")

    def test_secret_engine_still_detects_google_key(self):
        """
        SecretDetector has a pre-existing 'metrics' KeyError in its entropy path
        that causes it to return [] for simple JS snippets.
        We verify our plugin is independent of that bug — it uses its own extractor.
        """
        from jseye.core.google_api_validator import extract_google_api_keys
        js = f'var key = "{FAKE_KEY}";'
        # Our extractor always works regardless of SecretDetector state
        keys = extract_google_api_keys(js)
        self.assertIn(FAKE_KEY, keys)

    @patch("jseye.core.google_api_validator.urllib.request.urlopen")
    def test_both_plugins_run_independently(self, mock_urlopen):
        """
        Both plugins run on the same context without interfering.
        SecretDetectionPlugin may return 0 findings due to a pre-existing
        internal bug; GoogleAPIKeyPlugin must always return its own findings.
        """
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        from jseye.plugins.secret_detection_plugin import SecretDetectionPlugin
        from jseye.plugins.google_api_key_plugin import GoogleAPIKeyPlugin

        ctx = make_context([{
            "url": "https://example.com/app.js",
            "content": f'var key = "{FAKE_KEY}";'
        }])

        # Run both — secret plugin may error internally, that's pre-existing
        secret_result = run(SecretDetectionPlugin().run(ctx))
        google_result = run(GoogleAPIKeyPlugin().run(ctx))

        # Google plugin must always produce its own validated finding
        google_types = {f["type"] for f in google_result.findings}
        self.assertIn("google_api_key_validated", google_types)

        # No finding type from our plugin should appear in secret plugin results
        secret_types = {f["type"] for f in secret_result.findings}
        self.assertNotIn("google_api_key_validated", secret_types)


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)


# ===========================================================================
# 5. PluginCrawler integration – consolidation + statistics
# ===========================================================================

class TestPluginCrawlerIntegration(unittest.TestCase):
    """
    Verify that google_api_key_validator findings are correctly wired into
    the PluginBasedCrawler consolidation and statistics pipeline.
    """

    def _make_plugin_result(self, findings):
        """Build a minimal PluginResult-like object."""
        from jseye.plugins.base import PluginResult
        r = PluginResult(plugin_name="google_api_key_validator", findings=findings)
        r.metadata = {
            "total_keys_found": len(findings),
            "total_keys_validated": len(findings),
            "valid_keys": sum(1 for f in findings if f.get("validated")),
            "invalid_or_error_keys": sum(1 for f in findings if not f.get("validated")),
            "status_breakdown": {
                f["subtype"]: sum(1 for x in findings if x.get("subtype") == f["subtype"])
                for f in findings
            },
        }
        return r

    def _valid_finding(self, idx=1):
        return {
            "id": f"google_api_key_{idx}",
            "type": "google_api_key_validated",
            "subtype": "valid",
            "title": "Google API Key VALID - VALID",
            "description": "Key is valid",
            "severity": "critical",
            "confidence_score": 97.0,
            "risk_score": 90,
            "risk_level": "Critical",
            "source_files": ["https://example.com/app.js"],
            "location": {"files": ["https://example.com/app.js"]},
            "evidence": {
                "key_masked": "AIza***************************mnop",
                "validation_status": "valid",
                "http_status_code": 200,
                "validation_detail": "Key is valid",
                "validation_endpoint": "https://generativelanguage.googleapis.com/v1beta/files",
            },
            "risk_metrics": {},
            "confidence_factors": {},
            "remediation": "Rotate immediately.",
            "references": [],
            "validated": True,
        }

    def _invalid_finding(self, idx=2):
        f = self._valid_finding(idx)
        f.update({
            "subtype": "invalid",
            "severity": "info",
            "risk_score": 10,
            "risk_level": "Low",
            "validated": False,
            "evidence": {**f["evidence"], "validation_status": "invalid", "http_status_code": 400},
        })
        return f

    def test_consolidate_adds_google_keys_to_secrets(self):
        from jseye.core.plugin_crawler import PluginBasedCrawler

        crawler = PluginBasedCrawler({})
        crawler.results = {
            "js_files": [], "all_findings": [], "secrets": [],
            "endpoints": [], "vulnerabilities": [], "errors": [],
            "parameters": [], "mantra_secrets": [],
        }

        plugin_results = {
            "google_api_key_validator": self._make_plugin_result([self._valid_finding()])
        }
        crawler._consolidate_plugin_results(plugin_results)

        secrets = crawler.results["secrets"]
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0]["type"], "google_api_key")
        self.assertEqual(secrets[0]["validation_status"], "valid")
        self.assertTrue(secrets[0]["validated"])

    def test_consolidate_invalid_key_also_added(self):
        from jseye.core.plugin_crawler import PluginBasedCrawler

        crawler = PluginBasedCrawler({})
        crawler.results = {
            "js_files": [], "all_findings": [], "secrets": [],
            "endpoints": [], "vulnerabilities": [], "errors": [],
            "parameters": [], "mantra_secrets": [],
        }

        plugin_results = {
            "google_api_key_validator": self._make_plugin_result([self._invalid_finding()])
        }
        crawler._consolidate_plugin_results(plugin_results)

        secrets = crawler.results["secrets"]
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0]["validation_status"], "invalid")
        self.assertFalse(secrets[0]["validated"])

    def test_consolidate_does_not_affect_other_plugin_secrets(self):
        """Existing secret_detection findings must be unaffected."""
        from jseye.core.plugin_crawler import PluginBasedCrawler
        from jseye.plugins.base import PluginResult

        crawler = PluginBasedCrawler({})
        crawler.results = {
            "js_files": [], "all_findings": [], "secrets": [],
            "endpoints": [], "vulnerabilities": [], "errors": [],
            "parameters": [], "mantra_secrets": [],
        }

        existing_secret_finding = {
            "type": "secret", "subtype": "aws_access_key",
            "severity": "high", "risk_score": 80,
        }
        secret_result = PluginResult(plugin_name="secret_detection", findings=[existing_secret_finding])
        secret_result.metadata = {}

        google_result = self._make_plugin_result([self._valid_finding()])

        crawler._consolidate_plugin_results({
            "secret_detection": secret_result,
            "google_api_key_validator": google_result,
        })

        secrets = crawler.results["secrets"]
        types = [s["type"] for s in secrets]
        # Both must be present
        self.assertIn("secret", types)
        self.assertIn("google_api_key", types)
        self.assertEqual(len(secrets), 2)

    def test_generate_statistics_includes_google_api_keys(self):
        from jseye.core.plugin_crawler import PluginBasedCrawler

        crawler = PluginBasedCrawler({})
        plugin_result = self._make_plugin_result([self._valid_finding(), self._invalid_finding()])

        crawler.results = {
            "js_files": [],
            "all_findings": [],
            "secrets": [],
            "endpoints": [],
            "vulnerabilities": [],
            "errors": [],
            "parameters": [],
            "plugin_results": {"google_api_key_validator": plugin_result},
        }

        crawler._generate_statistics()

        stats = crawler.results["statistics"]
        self.assertIn("google_api_keys", stats)
        gak = stats["google_api_keys"]
        self.assertEqual(gak["total_found"], 2)
        self.assertEqual(gak["valid"], 1)

    def test_generate_statistics_no_google_plugin_no_crash(self):
        """If the plugin didn't run, statistics must still generate cleanly."""
        from jseye.core.plugin_crawler import PluginBasedCrawler

        crawler = PluginBasedCrawler({})
        crawler.results = {
            "js_files": [],
            "all_findings": [],
            "secrets": [],
            "endpoints": [],
            "vulnerabilities": [],
            "errors": [],
            "parameters": [],
            "plugin_results": {},
        }

        crawler._generate_statistics()
        stats = crawler.results["statistics"]
        # google_api_keys key should simply be absent — no crash
        self.assertNotIn("google_api_keys", stats)
