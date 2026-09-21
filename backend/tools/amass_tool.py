"""HADES tool wrapper for amass — in-depth attack surface mapping and subdomain enumeration."""

from __future__ import annotations

from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000


class AmassTool(ToolDefinition):
    name = "amass"
    binary = "amass"
    description = "Attack surface mapping — subdomain enumeration via DNS, scraping, APIs, and certificate transparency"
    category = "recon"
    risk = "low"
    timeout = 300
    params = [
        ToolParam("mode", "Amass subcommand", default="enum", choices=["enum", "intel"]),
        ToolParam("passive", "Passive-only mode (no DNS resolution)", param_type="bool", default=True),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        mode = params.get("mode", "enum")
        domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        args = [mode, "-d", domain]

        if params.get("passive", True):
            args.append("-passive")

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        seen: set[str] = set()

        for line in stdout.splitlines():
            sub = line.strip().lower()
            if sub and sub not in seen and not sub.startswith(("owasp", "the ", "amass", "----", "https://")):
                seen.add(sub)
                findings.append({"subdomain": sub})

        if findings:
            sample = [f["subdomain"] for f in findings[:10]]
            summary = f"amass: {len(findings)} subdomain(s) found: {', '.join(sample)}"
            if len(findings) > 10:
                summary += f" ... +{len(findings) - 10} more"
        else:
            summary = "amass: no subdomains found"

        combined = stdout
        if stderr:
            combined += "\n" + stderr

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0 or len(findings) > 0,
            summary=summary,
            raw_output=combined.strip()[:_MAX_BYTES],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(AmassTool())
