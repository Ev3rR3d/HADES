"""DalFox — automated XSS vulnerability scanner and parameter analyzer."""

from __future__ import annotations

import json
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000


class DalfoxTool(ToolDefinition):
    name = "dalfox"
    binary = "dalfox"
    description = "Automated XSS scanner — tests URL parameters for reflected, stored, and DOM-based XSS"
    category = "exploitation"
    risk = "medium"
    timeout = 180
    params = [
        ToolParam("url", "Full URL with parameters to test (e.g. https://target/search?q=test)", required=True),
        ToolParam("method", "HTTP method", default="GET", choices=["GET", "POST"]),
        ToolParam("data", "POST body data"),
        ToolParam("blind", "Blind XSS callback URL"),
        ToolParam("worker", "Number of concurrent workers", param_type="int", default=10),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        url = params.get("url") or target
        worker = str(params.get("worker", 10))

        args = [
            "url", url,
            "--silence",
            "--no-color",
            "--worker", worker,
            "--format", "json",
        ]

        method = params.get("method", "GET")
        if method.upper() == "POST":
            args.extend(["--method", "POST"])

        data = params.get("data")
        if data:
            args.extend(["--data", data])

        blind = params.get("blind")
        if blind:
            args.extend(["--blind", blind])

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # dalfox JSON output contains POC entries for confirmed XSS
            if entry.get("type") or entry.get("poc") or "POC" in line.upper():
                xss_type = entry.get("type", "reflected").lower()
                if "stored" in xss_type:
                    xss_type = "stored"
                elif "dom" in xss_type:
                    xss_type = "DOM"
                else:
                    xss_type = "reflected"

                findings.append({
                    "type": xss_type,
                    "payload": entry.get("poc", entry.get("payload", "")),
                    "parameter": entry.get("param", entry.get("parameter", "")),
                    "url": entry.get("inject_url", entry.get("url", target)),
                })

        if findings:
            summary = f"XSS FOUND — {len(findings)} confirmed vulnerability(ies)"
        elif exit_code == 0:
            summary = "dalfox: no XSS vulnerabilities found"
        else:
            summary = f"dalfox finished (exit {exit_code}) — review output for details"

        combined = stdout
        if stderr:
            combined += "\n" + stderr

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0,
            summary=summary,
            raw_output=combined.strip()[:_MAX_BYTES],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(DalfoxTool())
