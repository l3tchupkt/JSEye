"""Google API Key validator - checks keys against the Gemini Files API."""

import re
import urllib.request
import urllib.error
import json
from typing import Dict, Any

from .logging import get_logger

logger = get_logger(__name__)

# Google API key format: AIza followed by exactly 35 alphanumeric/-/_ chars (39 total)
# Negative lookahead ensures we don't match keys that are part of a longer token
GOOGLE_API_KEY_PATTERN = re.compile(r'AIza[0-9A-Za-z\-_]{35}(?![0-9A-Za-z\-_])')

# Validation endpoint - uses Gemini Files API (read-only, safe to probe)
VALIDATION_URL = "https://generativelanguage.googleapis.com/v1beta/files?key={key}"


def extract_google_api_keys(js_content: str) -> list:
    """Extract all Google API keys from JavaScript content."""
    return list(set(GOOGLE_API_KEY_PATTERN.findall(js_content)))


def validate_google_api_key(api_key: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Validate a Google API key by calling the Gemini Files API.

    Returns a dict with:
      - key: the API key (masked)
      - valid: bool
      - status_code: HTTP status code
      - status: 'valid' | 'invalid' | 'restricted' | 'error'
      - detail: human-readable message
    """
    masked = _mask_key(api_key)
    url = VALIDATION_URL.format(key=api_key)

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "JSEye/3.0 Google-API-Key-Validator"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            # 200 means the key is valid and unrestricted for this API
            return {
                "key_masked": masked,
                "valid": True,
                "status_code": status_code,
                "status": "valid",
                "detail": "Key is valid and accepted by Gemini Files API",
            }

    except urllib.error.HTTPError as e:
        status_code = e.code
        try:
            body = json.loads(e.read().decode("utf-8", errors="replace"))
            error_msg = body.get("error", {}).get("message", str(e))
            error_status = body.get("error", {}).get("status", "")
        except Exception:
            error_msg = str(e)
            error_status = ""

        if status_code == 400:
            return {
                "key_masked": masked,
                "valid": False,
                "status_code": status_code,
                "status": "invalid",
                "detail": f"Bad request / invalid key: {error_msg}",
            }
        elif status_code == 403:
            # 403 can mean: key valid but API not enabled, or key restricted
            if "API_KEY_HTTP_REFERRER_BLOCKED" in error_msg or "IP_ADDRESS_BLOCKED" in error_msg:
                return {
                    "key_masked": masked,
                    "valid": True,
                    "status_code": status_code,
                    "status": "restricted",
                    "detail": f"Key exists but has restrictions: {error_msg}",
                }
            return {
                "key_masked": masked,
                "valid": True,
                "status_code": status_code,
                "status": "restricted",
                "detail": f"Key valid but access denied (API not enabled or restricted): {error_msg}",
            }
        elif status_code == 429:
            return {
                "key_masked": masked,
                "valid": True,
                "status_code": status_code,
                "status": "valid",
                "detail": "Key is valid (rate limited / quota exceeded)",
            }
        else:
            return {
                "key_masked": masked,
                "valid": False,
                "status_code": status_code,
                "status": "invalid",
                "detail": f"HTTP {status_code}: {error_msg}",
            }

    except urllib.error.URLError as e:
        return {
            "key_masked": masked,
            "valid": False,
            "status_code": None,
            "status": "error",
            "detail": f"Network error during validation: {e.reason}",
        }
    except Exception as e:
        return {
            "key_masked": masked,
            "valid": False,
            "status_code": None,
            "status": "error",
            "detail": f"Unexpected error: {str(e)}",
        }


def _mask_key(key: str) -> str:
    """Show first 4 and last 4 chars, mask the rest."""
    if len(key) <= 8:
        return "********"
    return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"
