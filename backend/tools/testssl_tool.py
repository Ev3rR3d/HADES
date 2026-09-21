"""HADES tool wrapper for testssl.sh — TLS/SSL configuration scanner."""

from __future__ import annotations

import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000


class TestsslTool(ToolDefinition):
    name = "testssl"
    binary = "testssl"
    description = "TLS/SSL scanner — checks for protocol support, cipher suites, and known vulnerabilities (HEARTBLEED, POODLE, etc.)"
    category = "scanning"
    risk = "low"
    timeout = 300
    params = [
        ToolParam("checks", "Specific vulnerability checks (e.g. '--heartbleed --ccs --robot --poodle --beast')"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        args = ["--quiet", "--color", "0", target]

        checks = params.get("checks")
        if checks:
            import shlex
            args = shlex.split(checks) + ["--quiet", "--color", "0", target]

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if re.search(r"VULNERABLE|NOT ok", stripped, re.IGNORECASE):
                findings.append({
                    "type": "vulnerability",
                    "description": stripped,
                    "severity": "high" if "VULNERABLE" in stripped.upper() else "medium",
                })
            elif re.search(r"offered\s*\(deprecated\)|weak", stripped, re.IGNORECASE):
                findings.append({
                    "type": "weak_config",
                    "description": stripped,
                    "severity": "medium",
                })

        if findings:
            vuln_count = sum(1 for f in findings if f["type"] == "vulnerability")
            weak_count = sum(1 for f in findings if f["type"] == "weak_config")
            summary = f"testssl: {vuln_count} vulnerabilities, {weak_count} weak configurations"
        else:
            summary = "testssl: no vulnerabilities found"

        combined = stdout
        if stderr:
            combined += "\n" + stderr

        return ToolResult(
            tool=self.name,
            target=target,
            success=True,
            summary=summary,
            raw_output=combined.strip()[:_MAX_BYTES],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(TestsslTool())
