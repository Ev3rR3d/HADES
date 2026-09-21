"""HADES tool wrapper for commix — automated OS command injection exploiter."""

from __future__ import annotations

import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000


class CommixTool(ToolDefinition):
    name = "commix"
    binary = "commix"
    description = "Automated command injection scanner and exploiter — tests for OS command injection vulnerabilities"
    category = "exploitation"
    risk = "high"
    timeout = 180
    params = [
        ToolParam("url", "Target URL with injectable parameter", required=True),
        ToolParam("data", "POST data (e.g. 'param1=val1&param2=val2')"),
        ToolParam("level", "Testing level 1-3 (higher = more payloads)", param_type="int", default=3),
        ToolParam("technique", "Injection techniques (e.g. 'c' classic, 'e' eval-based, 't' time-based)"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        url = params.get("url") or target
        level = params.get("level", 3)

        args = [
            f"--url={url}",
            "--batch",
            f"--level={level}",
        ]

        data = params.get("data")
        if data:
            args.append(f"--data={data}")

        technique = params.get("technique")
        if technique:
            args.append(f"--technique={technique}")

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        combined = stdout + "\n" + stderr

        vuln_matches = re.findall(
            r"The (?:GET|POST|Cookie) parameter '(\S+)' (?:seems|is) (?:injectable|vulnerable)",
            combined, re.IGNORECASE,
        )
        for param in vuln_matches:
            findings.append({
                "type": "command_injection",
                "parameter": param,
            })

        technique_matches = re.findall(
            r"The (\S+) technique (?:is|appears to be) applicable",
            combined, re.IGNORECASE,
        )
        for technique in technique_matches:
            findings.append({
                "type": "technique",
                "technique": technique,
            })

        os_match = re.search(r"Target OS:\s*(.+)", combined)
        if os_match:
            findings.append({"type": "os_info", "os": os_match.group(1).strip()})

        injectable = bool(vuln_matches) or "is vulnerable" in combined.lower()
        if injectable:
            params_found = ", ".join(vuln_matches) if vuln_matches else "unknown"
            summary = f"COMMAND INJECTION FOUND — parameter(s): {params_found}"
        elif "not appear to be injectable" in combined.lower():
            summary = "No command injection found — parameters appear safe"
        else:
            summary = f"commix finished (exit {exit_code}) — review output for details"

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0,
            summary=summary,
            raw_output=combined.strip()[:_MAX_BYTES],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(CommixTool())
