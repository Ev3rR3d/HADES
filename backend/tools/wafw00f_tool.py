"""HADES tool wrapper for wafw00f — WAF detection tool."""

from __future__ import annotations

import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000


class Wafw00fTool(ToolDefinition):
    name = "wafw00f"
    binary = "wafw00f"
    description = "Web Application Firewall detection — identifies WAF/IPS products protecting a target"
    category = "recon"
    risk = "low"
    timeout = 30
    params = []

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        return [url]

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        combined = stdout + "\n" + stderr

        waf_match = re.search(r"is behind\s+(.+?)(?:\s+WAF)?\.?\s*$", stdout, re.MULTILINE | re.IGNORECASE)
        if waf_match:
            waf_name = waf_match.group(1).strip()
            findings.append({"type": "waf_detected", "waf": waf_name})
            summary = f"WAF detected: {waf_name}"
        elif re.search(r"no waf detected|is not behind", stdout, re.IGNORECASE):
            summary = "No WAF detected"
        else:
            summary = f"wafw00f finished (exit {exit_code}) — review output"

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0,
            summary=summary,
            raw_output=combined.strip()[:_MAX_BYTES],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(Wafw00fTool())
