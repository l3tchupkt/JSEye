"""Google API Key Detection & Validation Plugin for JSEye."""

import asyncio
from typing import Any, Dict, List

from jseye.core.google_api_validator import extract_google_api_keys, validate_google_api_key
from jseye.core.logging import get_logger
from jseye.plugins.base import (
    BasePlugin,
    ExploitationLikelihood,
    ExposureLevel,
    PluginCategory,
    PluginContext,
    PluginMetadata,
    PluginResult,
)

logger = get_logger(__name__)


class GoogleAPIKeyPlugin(BasePlugin):
    """
    Detects Google API keys (AIza...) in JavaScript files and validates
    each unique key against the Gemini Files API to confirm if it is
    live and working.

    This plugin is additive - it does NOT modify or replace the existing
    SecretDetectionPlugin findings.  It stores its own results under the
    shared_data key 'google_api_key_findings' and adds them to the
    PluginResult findings list with type='google_api_key_validated'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="google_api_key_validator",
            version="1.0.0",
            category=PluginCategory.DETECTION,
            risk_weight=0.9,
            description=(
                "Detects Google API keys in JS files and validates them "
                "via the Gemini Files API (v1beta/files endpoint)"
            ),
            author="JSEye Team",
            requires=[],
            enabled=True,
            execution_order=15,  # runs after secret_detection (order=10)
        )

    async def validate_context(self, context: PluginContext) -> bool:
        return True  # works even with no JS files

    async def run(self, context: PluginContext) -> PluginResult:
        result = self.create_result()
        loop = asyncio.get_event_loop()

        if not context.js_files:
            result.metadata = {"total_keys_found": 0, "total_keys_validated": 0}
            return result

        # ── Step 1: collect unique keys across all JS files ──────────────
        key_sources: Dict[str, List[str]] = {}  # key -> list of source URLs
        for js_file in context.js_files:
            content = js_file.get("content", "")
            source_url = js_file.get("url", "unknown")
            if not content:
                continue
            for key in extract_google_api_keys(content):
                key_sources.setdefault(key, []).append(source_url)

        if not key_sources:
            logger.info("No Google API keys found in JS files", target=context.target)
            result.metadata = {"total_keys_found": 0, "total_keys_validated": 0}
            return result

        logger.info(
            f"Found {len(key_sources)} unique Google API key(s), validating...",
            target=context.target,
        )

        # ── Step 2: validate each key (blocking I/O run in executor) ─────
        validated_findings: List[Dict[str, Any]] = []

        for idx, (api_key, sources) in enumerate(key_sources.items(), start=1):
            try:
                validation = await loop.run_in_executor(
                    None, validate_google_api_key, api_key
                )
            except Exception as exc:
                validation = {
                    "key_masked": api_key[:4] + "****",
                    "valid": False,
                    "status_code": None,
                    "status": "error",
                    "detail": str(exc),
                }

            is_valid = validation.get("valid", False)
            status = validation.get("status", "unknown")

            severity = _severity_for_status(status)
            confidence_score = 95.0 if status in ("valid", "restricted") else 60.0

            confidence_factors = self.calculate_confidence(
                base_confidence=confidence_score,
                contributing_factors=_contributing_factors(status),
                penalty_factors=[] if is_valid else ["Key did not pass validation"],
            )

            risk_metrics = self.create_risk_metrics(
                confidence_score=confidence_factors.final_confidence,
                exploitation_likelihood=(
                    ExploitationLikelihood.HIGH if is_valid else ExploitationLikelihood.LOW
                ),
                stability_score=90.0,
                exposure_level=ExposureLevel.PUBLIC,
                contributing_factors=_contributing_factors(status),
            )

            finding = {
                "id": f"google_api_key_{idx}",
                "type": "google_api_key_validated",
                "subtype": status,
                "title": f"Google API Key {'VALID' if is_valid else 'INVALID/ERROR'} - {status.upper()}",
                "description": (
                    f"Google API key detected in JavaScript and validated "
                    f"against Gemini Files API. Status: {status}. "
                    f"{validation.get('detail', '')}"
                ),
                "severity": severity,
                "confidence_score": confidence_factors.final_confidence,
                "risk_score": _risk_score(status),
                "risk_level": _risk_level(status),
                "source_files": sources,
                "location": {"files": sources},
                "evidence": {
                    "key_masked": validation.get("key_masked", ""),
                    "validation_status": status,
                    "http_status_code": validation.get("status_code"),
                    "validation_detail": validation.get("detail", ""),
                    "validation_endpoint": (
                        "https://generativelanguage.googleapis.com/v1beta/files"
                    ),
                },
                "risk_metrics": vars(risk_metrics),
                "confidence_factors": vars(confidence_factors),
                "remediation": _remediation(status),
                "references": [
                    "https://cloud.google.com/docs/authentication/api-keys",
                    "https://cloud.google.com/docs/authentication/api-keys#securing_an_api_key",
                ],
                "validated": is_valid,
            }

            result.add_finding(finding)
            validated_findings.append(finding)

            logger.info(
                f"Google API key [{validation.get('key_masked')}] -> {status} "
                f"(HTTP {validation.get('status_code')})",
                target=context.target,
            )

        # ── Step 3: sort by risk score, store metadata ────────────────────
        result.findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        valid_count = sum(1 for f in validated_findings if f["validated"])
        result.metadata = {
            "total_keys_found": len(key_sources),
            "total_keys_validated": len(validated_findings),
            "valid_keys": valid_count,
            "invalid_or_error_keys": len(validated_findings) - valid_count,
            "status_breakdown": _status_breakdown(validated_findings),
        }

        # Share with other plugins / report engine
        context.add_shared_data("google_api_key_findings", validated_findings)

        logger.info(
            f"Google API key validation complete: {valid_count}/{len(key_sources)} valid",
            target=context.target,
        )

        return result


# ── helpers ──────────────────────────────────────────────────────────────────

def _severity_for_status(status: str) -> str:
    return {
        "valid": "critical",
        "restricted": "high",
        "invalid": "info",
        "error": "low",
    }.get(status, "medium")


def _risk_score(status: str) -> int:
    return {"valid": 90, "restricted": 65, "invalid": 10, "error": 5}.get(status, 20)


def _risk_level(status: str) -> str:
    return {
        "valid": "Critical",
        "restricted": "High",
        "invalid": "Low",
        "error": "Low",
    }.get(status, "Medium")


def _contributing_factors(status: str) -> List[str]:
    base = ["Google API key format confirmed (AIza prefix + 35 chars)"]
    if status == "valid":
        base += [
            "Key accepted by Gemini Files API (HTTP 200)",
            "Unrestricted - usable from any origin",
        ]
    elif status == "restricted":
        base += [
            "Key exists but has API/HTTP/IP restrictions (HTTP 403)",
            "May still be exploitable depending on restriction type",
        ]
    return base


def _remediation(status: str) -> str:
    if status in ("valid", "restricted"):
        return (
            "Immediately rotate this API key in Google Cloud Console. "
            "Apply API restrictions (allowed APIs, HTTP referrers, IP addresses). "
            "Never embed API keys in client-side JavaScript. "
            "Use environment variables or a secrets manager instead."
        )
    return "No immediate action required, but review key usage and rotate as a precaution."


def _status_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    breakdown: Dict[str, int] = {}
    for f in findings:
        s = f.get("evidence", {}).get("validation_status", "unknown")
        breakdown[s] = breakdown.get(s, 0) + 1
    return breakdown
