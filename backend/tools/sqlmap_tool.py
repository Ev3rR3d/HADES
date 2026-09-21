"""SQLMap — automated SQL injection detection and exploitation."""

from __future__ import annotations

import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry


class SQLMapTool(ToolDefinition):
    name = "sqlmap"
    binary = "sqlmap"
    description = "Automated SQL injection scanner — tests URL parameters for injection flaws"
    category = "exploitation"
    risk = "high"
    timeout = 300
    params = [
        ToolParam("url", "Full URL with injectable parameter (e.g. http://target/page?id=1)", required=True),
        ToolParam("level", "Test level 1-5 (higher = more payloads)", param_type="int", default=3),
        ToolParam("risk_level", "Risk level 1-3 (higher = riskier payloads)", param_type="int", default=2),
        ToolParam("technique", "Injection techniques: B=boolean, E=error, U=union, S=stacked, T=time, Q=inline", default="BEUSTQ"),
        ToolParam("forms", "Also test forms on the page", param_type="bool", default=False),
        ToolParam("batch", "Non-interactive mode (auto-answer prompts)", param_type="bool", default=True),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        url = params.get("url") or target
        level = params.get("level", 3)
        risk_level = params.get("risk_level", 2)
        technique = params.get("technique", "BEUSTQ")

        args = [
            "-u", url,
            f"--level={level}",
            f"--risk={risk_level}",
            f"--technique={technique}",
            "--batch",
            "--random-agent",
            "--output-dir=/tmp/sqlmap-output",
        ]

        if params.get("forms"):
            args.append("--forms")

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        combined = stdout + "\n" + stderr
        findings: list[dict] = []

        # Match injection confirmations like:
        # Parameter: id (GET)
        #     Type: boolean-based blind
        #     Payload: id=1 AND 1=1
        param_blocks = re.findall(
            r"Parameter:\s*(\S+).*?\n\s+Type:\s*(.*?)\n\s+.*?Payload:\s*(.*?)(?:\n|$)",
            combined, re.DOTALL,
        )
        for param, inj_type, payload in param_blocks:
            findings.append({
                "parameter": param.strip(),
                "type": inj_type.strip(),
                "payload": payload.strip(),
            })

        # Also catch single-line confirmations
        for m in re.finditer(
            r"(?:GET|POST) parameter '(\S+)' is vulnerable.*?Type:\s*(.*?)(?:\n|$)", combined,
        ):
            entry = {"parameter": m.group(1), "type": m.group(2).strip(), "payload": ""}
            if entry not in findings:
                findings.append(entry)

        injectable = "sqlmap identified" in combined.lower() or len(findings) > 0
        if injectable:
            summary = f"SQL INJECTION FOUND — {len(findings)} injection point(s) confirmed"
        elif "all tested parameters do not appear to be injectable" in combined.lower():
            summary = "No SQL injection found — all parameters appear safe"
        else:
            summary = f"sqlmap finished (exit {exit_code}) — review output for details"

        # Capture DB info if present
        db_match = re.search(r"back-end DBMS:\s*(.*?)(?:\n|$)", combined)
        if db_match:
            summary += f"\nBackend DBMS: {db_match.group(1).strip()}"

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0,
            summary=summary,
            raw_output=combined[:100_000],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(SQLMapTool())
