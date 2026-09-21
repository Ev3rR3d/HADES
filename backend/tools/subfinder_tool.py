"""Subfinder subdomain enumeration integration."""

from __future__ import annotations

from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry


class SubfinderTool(ToolDefinition):
    name = "subfinder"
    binary = "subfinder"
    description = "Subdomain discovery — finds subdomains via passive sources"
    category = "recon"
    risk = "low"
    timeout = 120
    params = [
        ToolParam(
            name="recursive",
            description="Enable recursive subdomain enumeration",
            param_type="bool",
            default=False,
        ),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        args = ["-d", domain, "-silent"]
        if params.get("recursive"):
            args.append("-recursive")
        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        seen: set[str] = set()

        for line in stdout.strip().splitlines():
            sub = line.strip().lower()
            if sub and sub not in seen:
                seen.add(sub)
                findings.append({"subdomain": sub})

        if findings:
            sample = [f["subdomain"] for f in findings[:10]]
            summary = f"{len(findings)} subdomain(s) found: {', '.join(sample)}"
            if len(findings) > 10:
                summary += f" ... +{len(findings) - 10} more"
        else:
            summary = "No subdomains found"

        combined = stdout
        if stderr and exit_code != 0:
            combined += "\n" + stderr

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0,
            summary=summary,
            raw_output=combined[:512_000],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(SubfinderTool())
