"""WhatWeb technology fingerprinting integration."""

from __future__ import annotations

import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_TECH_RE = re.compile(r"(\S+)\[([^\]]*)\]")


class WhatWebTool(ToolDefinition):
    name = "whatweb"
    binary = "whatweb"
    description = "Web technology fingerprinting — detects CMS, frameworks, servers, languages"
    category = "recon"
    risk = "low"
    timeout = 60
    params = [
        ToolParam(
            name="aggression",
            description="Aggression level (1=stealthy, 3=aggressive, 4=heavy)",
            param_type="int",
            default=1,
            choices=["1", "2", "3", "4"],
        ),
        ToolParam(name="plugins", description="Comma-separated plugin list to run"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        aggression = str(params.get("aggression", 1))
        args = ["-a", aggression, "--color=never"]

        plugins = params.get("plugins")
        if plugins:
            args += ["-p", plugins]

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        args.append(target)
        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        seen = set()

        for match in _TECH_RE.finditer(stdout):
            tech = match.group(1).strip()
            detail = match.group(2).strip()

            if tech.startswith("http") or tech in seen:
                continue
            seen.add(tech)

            version = ""
            if detail:
                ver_match = re.search(r"(\d+[\d.]*\d*)", detail)
                if ver_match:
                    version = ver_match.group(1)

            findings.append({
                "technology": tech,
                "version": version,
                "detail": detail,
            })

        techs = [f["technology"] for f in findings]
        if techs:
            summary = f"Technologies: {', '.join(techs[:20])}"
        else:
            summary = "No technologies detected"

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


registry.register(WhatWebTool())
