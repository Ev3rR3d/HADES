"""httpx — fast HTTP probing with tech detection."""

from __future__ import annotations

import json
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry


class HttpxTool(ToolDefinition):
    name = "httpx"
    binary = "httpx"
    description = "Fast HTTP prober — detects status codes, titles, technologies, and servers"
    category = "recon"
    risk = "low"
    timeout = 60
    params = [
        ToolParam("follow_redirects", "Follow HTTP redirects", param_type="bool", default=True),
        ToolParam("paths", "Extra paths to probe, comma-separated (e.g. /admin,/login,/api)"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        args = [
            "-u", target,
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-content-length",
            "-json",
        ]

        if params.get("follow_redirects", True):
            args.append("-follow-redirects")

        paths = params.get("paths")
        if paths:
            if isinstance(paths, str):
                for p in paths.split(","):
                    p = p.strip()
                    if p:
                        args.extend(["-path", p])

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        summary_parts: list[str] = []

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            finding = {
                "url": data.get("url", target),
                "status_code": data.get("status_code", 0),
                "title": data.get("title", ""),
                "technologies": data.get("tech", []),
                "server": data.get("webserver", ""),
                "content_length": data.get("content_length", 0),
                "scheme": data.get("scheme", ""),
                "host": data.get("host", ""),
            }
            findings.append(finding)

            parts = [f"[{finding['status_code']}] {finding['url']}"]
            if finding["title"]:
                parts.append(f"Title: {finding['title']}")
            if finding["server"]:
                parts.append(f"Server: {finding['server']}")
            if finding["technologies"]:
                parts.append(f"Tech: {', '.join(finding['technologies'])}")
            summary_parts.append(" | ".join(parts))

        if summary_parts:
            summary = "\n".join(summary_parts)
        else:
            summary = f"httpx: no results (exit {exit_code})"

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0 and len(findings) > 0,
            summary=summary,
            raw_output=stdout[:50_000],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(HttpxTool())
