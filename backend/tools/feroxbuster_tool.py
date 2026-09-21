"""HADES tool wrapper for feroxbuster — recursive content discovery tool."""

from __future__ import annotations

import json
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry, resolve_wordlist

_MAX_BYTES = 512_000
_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class FeroxbusterTool(ToolDefinition):
    name = "feroxbuster"
    binary = "feroxbuster"
    description = "Recursive content discovery — fast directory and file brute-forcer with auto-recursion"
    category = "enumeration"
    risk = "low"
    timeout = 180
    params = [
        ToolParam("wordlist", "Path to wordlist file", default=_DEFAULT_WORDLIST),
        ToolParam("extensions", "Comma-separated file extensions (e.g. php,html,js)"),
        ToolParam("depth", "Recursion depth", param_type="int", default=2),
        ToolParam("threads", "Number of concurrent threads", param_type="int", default=50),
        ToolParam("filter_status", "Status codes to filter out", default="404"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        wordlist = resolve_wordlist(params.get("wordlist", _DEFAULT_WORDLIST))
        depth = str(params.get("depth", 2))
        threads = str(params.get("threads", 50))
        filter_status = str(params.get("filter_status", "404"))

        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        args = [
            "-u", url,
            "-w", wordlist,
            "-d", depth,
            "-t", threads,
            "--filter-status", filter_status,
            "-q",
            "--no-state",
            "--json",
        ]

        extensions = params.get("extensions")
        if extensions:
            args.extend(["-x", extensions])

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        status_counts: dict[int, int] = {}

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if entry.get("type") != "response":
                continue

            status = entry.get("status", 0)
            finding = {
                "url": entry.get("url", ""),
                "status": status,
                "content_length": entry.get("content_length", 0),
                "word_count": entry.get("word_count", 0),
                "line_count": entry.get("line_count", 0),
            }
            findings.append(finding)
            status_counts[status] = status_counts.get(status, 0) + 1

        if findings:
            parts = [f"feroxbuster: {len(findings)} paths discovered"]
            for code, count in sorted(status_counts.items()):
                parts.append(f"  {code}: {count}")
            summary = "\n".join(parts)
        else:
            summary = "feroxbuster: no paths discovered"

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


registry.register(FeroxbusterTool())
