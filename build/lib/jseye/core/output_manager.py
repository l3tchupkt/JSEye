"""
Structured Output Manager for JSEye v3.0.1.

Creates and populates the output directory:

  jseye_output_<timestamp>/
    urls/          all_urls.txt, unique_urls.txt, in_scope_urls.txt
    endpoints/     endpoints.json, prioritized_endpoints.json
    parameters/    all_params.txt, high_risk_params.txt
    secrets/       secrets.json, validated_secrets.json
    requests/      captured_requests.json
    exports/       ffuf_commands.sh, curl_replay.sh, burp_sitemap.xml, wordlists.txt
    final_report.json
    final_report.html
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

from .logging import get_logger

logger = get_logger(__name__)


class OutputManager:
    """Manages structured output folder creation and writing."""

    def __init__(self, output_dir: Optional[str] = None):
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.base_dir = Path(output_dir or f"jseye_output_{ts}")
        self._ensure_dirs()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _ensure_dirs(self) -> None:
        subdirs = ["urls", "endpoints", "parameters", "secrets", "requests", "exports"]
        for sub in subdirs:
            (self.base_dir / sub).mkdir(parents=True, exist_ok=True)
        logger.info(f"Output directory: {self.base_dir}")

    # ------------------------------------------------------------------
    # Public write helpers
    # ------------------------------------------------------------------

    def write_urls(
        self,
        all_urls: List[str],
        unique_urls: List[str],
        in_scope_urls: List[str],
    ) -> None:
        self._write_lines(self.base_dir / "urls" / "all_urls.txt", all_urls)
        self._write_lines(self.base_dir / "urls" / "unique_urls.txt", unique_urls)
        self._write_lines(self.base_dir / "urls" / "in_scope_urls.txt", in_scope_urls)

    def write_endpoints(
        self,
        endpoints: List[Dict],
        prioritized: List[Dict],
    ) -> None:
        self._write_json(self.base_dir / "endpoints" / "endpoints.json", endpoints)
        self._write_json(self.base_dir / "endpoints" / "prioritized_endpoints.json", prioritized)

    def write_parameters(
        self,
        all_params: List[str],
        high_risk: List[str],
    ) -> None:
        self._write_lines(self.base_dir / "parameters" / "all_params.txt", all_params)
        self._write_lines(self.base_dir / "parameters" / "high_risk_params.txt", high_risk)

    def write_secrets(
        self,
        secrets: List[Dict],
        validated: List[Dict],
    ) -> None:
        self._write_json(self.base_dir / "secrets" / "secrets.json", secrets)
        self._write_json(self.base_dir / "secrets" / "validated_secrets.json", validated)

    def write_captured_requests(self, requests: List[Dict]) -> None:
        self._write_json(self.base_dir / "requests" / "captured_requests.json", requests)

    def write_exports(
        self,
        ffuf_lines: List[str],
        curl_lines: List[str],
        burp_xml: str,
        wordlist_lines: List[str],
    ) -> None:
        self._write_lines(self.base_dir / "exports" / "ffuf_commands.sh", ffuf_lines)
        self._write_lines(self.base_dir / "exports" / "curl_replay.sh", curl_lines)
        self._write_text(self.base_dir / "exports" / "burp_sitemap.xml", burp_xml)
        self._write_lines(self.base_dir / "exports" / "wordlists.txt", wordlist_lines)

    def write_final_report(self, report: Dict[str, Any]) -> Path:
        path = self.base_dir / "final_report.json"
        self._write_json(path, report)
        return path

    def write_html_report(self, html: str) -> Path:
        path = self.base_dir / "final_report.html"
        self._write_text(path, html)
        return path

    # ------------------------------------------------------------------
    # Convenience: build from scan results dict
    # ------------------------------------------------------------------

    def persist_all(self, results: Dict[str, Any]) -> None:
        """
        Pull everything from the main scan results dict and write to disk.
        Tolerates missing keys gracefully.
        """
        # URLs
        all_urls = results.get("all_urls", [])
        unique_urls = list(dict.fromkeys(all_urls))
        in_scope_urls = results.get("in_scope_urls", unique_urls)
        self.write_urls(all_urls, unique_urls, in_scope_urls)

        # Endpoints
        endpoints = results.get("endpoints", [])
        prio = results.get("prioritized_endpoints", endpoints)
        serialized_ep = [self._ep_to_dict(e) for e in endpoints]
        serialized_prio = [self._ep_to_dict(e) for e in prio]
        self.write_endpoints(serialized_ep, serialized_prio)

        # Parameters
        params = results.get("parameters", [])
        all_param_names = sorted(set(
            (p.name if hasattr(p, "name") else p.get("name", "")) for p in params
        ))
        high_risk = sorted(set(
            (p.name if hasattr(p, "name") else p.get("name", ""))
            for p in params
            if (p.risk_level if hasattr(p, "risk_level") else p.get("risk_level", "low"))
            in ("critical", "high")
        ))
        self.write_parameters(all_param_names, high_risk)

        # Secrets
        secrets = results.get("secrets", [])
        validated = [s for s in secrets if s.get("validated", False)]
        self.write_secrets(secrets, validated)

        # Active probing requests
        requests = results.get("captured_requests", [])
        self.write_captured_requests(requests)

        # Exports
        ffuf = self._build_ffuf(in_scope_urls)
        curl = self._build_curl(in_scope_urls)
        burp = self._build_burp(in_scope_urls)
        wordlist = all_param_names + list(dict.fromkeys(
            u.split("?")[0] for u in in_scope_urls
        ))
        self.write_exports(ffuf, curl, burp, wordlist)

        logger.info(f"All findings written to {self.base_dir}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ep_to_dict(self, ep: Any) -> Dict:
        if isinstance(ep, dict):
            return ep
        try:
            import dataclasses
            return dataclasses.asdict(ep)
        except Exception:
            return {"url": str(ep)}

    def _build_ffuf(self, urls: List[str]) -> List[str]:
        lines = ["#!/bin/bash", "# ffuf commands generated by JSEye v3.0.1", ""]
        for url in urls[:500]:
            if "?" in url:
                lines.append(f"ffuf -u '{url}&FUZZ=FUZZ' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200,201,204,301,302,307")
            else:
                lines.append(f"ffuf -u '{url}?FUZZ=FUZZ' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200,201,204,301,302,307")
        return lines

    def _build_curl(self, urls: List[str]) -> List[str]:
        lines = ["#!/bin/bash", "# cURL replay commands generated by JSEye v3.0.1", ""]
        for url in urls[:500]:
            lines.append(f"curl -sk '{url}' -H 'User-Agent: Mozilla/5.0' -o /dev/null -w '%{{http_code}} %{{url_effective}}\\n'")
        return lines

    def _build_burp(self, urls: List[str]) -> str:
        items = ""
        for url in urls[:500]:
            items += (
                f"  <item><url>{xml_escape(url)}</url>"
                f"<method>GET</method><host>{xml_escape(_extract_host(url))}</host></item>\n"
            )
        return (
            '<?xml version="1.0"?>\n'
            '<items burpVersion="2023.0" exportTime="JSEye v3.0.1">\n'
            + items
            + "</items>\n"
        )

    def _write_json(self, path: Path, data: Any) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"Failed to write {path}: {e}")

    def _write_lines(self, path: Path, lines: List[str]) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(str(l) for l in lines if l))
                if lines:
                    f.write("\n")
        except Exception as e:
            logger.warning(f"Failed to write {path}: {e}")

    def _write_text(self, path: Path, text: str) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        except Exception as e:
            logger.warning(f"Failed to write {path}: {e}")

    @property
    def output_path(self) -> str:
        return str(self.base_dir)


def _extract_host(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc or url
    except Exception:
        return url
