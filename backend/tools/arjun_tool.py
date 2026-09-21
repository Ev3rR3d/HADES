"""HADES tool wrapper for arjun — HTTP parameter discovery."""

from __future__ import annotations

import json
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000


class ArjunTool(ToolDefinition):
    name = "arjun"
    binary = "arjun"
    description = "HTTP parameter discovery — finds hidden GET/POST/JSON parameters on web endpoints"
    category = "enumeration"
    risk = "low"
    timeout = 180
    params = [
        ToolParam("method", "HTTP method to use", default="GET", choices=["GET", "POST", "JSON"]),
        ToolParam("wordlist", "Custom wordlist for parameter names"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        method = params.get("method", "GET")
        url = target if target.startswith(("http://", "https://")) else f"http://{target}"

        args = ["-u", url, "-m", method, "--stable", "-oJ", "/dev/stdout"]

        wordlist = params.get("wordlist")
        if wordlist:
            args.extend(["-w", wordlist])

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []

        try:
            data = json.loads(stdout)
            for url, param_list in data.items():
                for param in param_list:
                    findings.append({"url": url, "parameter": param})
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

        if findings:
            param_names = [f["parameter"] for f in findings[:15]]
            summary = f"arjun: {len(findings)} parameters discovered: {', '.join(param_names)}"
            if len(findings) > 15:
                summary += f" ... +{len(findings) - 15} more"
        else:
            summary = "arjun: no hidden parameters found"

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


registry.register(ArjunTool())
