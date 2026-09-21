"""HADES tool wrapper for wfuzz — web application fuzzer."""

from __future__ import annotations

import json
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry, resolve_wordlist

_MAX_BYTES = 512_000


class WfuzzTool(ToolDefinition):
    name = "wfuzz"
    binary = "wfuzz"
    description = "Web application fuzzer — brute-forces parameters, directories, and headers with advanced filtering"
    category = "exploitation"
    risk = "medium"
    timeout = 180
    params = [
        ToolParam("wordlist", "Path to wordlist file", required=True),
        ToolParam("url", "URL with FUZZ keyword (e.g. http://target/FUZZ)", required=True),
        ToolParam("filter_codes", "Status codes to hide (comma-separated)", default="404"),
        ToolParam("threads", "Number of concurrent threads", param_type="int", default=20),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        wordlist = resolve_wordlist(params.get("wordlist", ""))
        url = params.get("url", target)
        filter_codes = str(params.get("filter_codes", "404"))
        threads = str(params.get("threads", 20))

        return [
            "-z", f"file,{wordlist}",
            "-u", url,
            "--hc", filter_codes,
            "-t", threads,
            "-f", "/dev/stdout,json",
        ]

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []

        try:
            data = json.loads(stdout)
            for result in data:
                status = result.get("code", 0)
                findings.append({
                    "url": result.get("url", ""),
                    "status": status,
                    "length": result.get("chars", 0),
                    "words": result.get("words", 0),
                    "lines": result.get("lines", 0),
                    "payload": result.get("payload", ""),
                })
        except (json.JSONDecodeError, TypeError):
            for line in stdout.splitlines():
                line = line.strip()
                if not line or line.startswith(("*", "=", "Target", "Total")):
                    continue
                try:
                    entry = json.loads(line)
                    findings.append({
                        "url": entry.get("url", ""),
                        "status": entry.get("code", 0),
                        "length": entry.get("chars", 0),
                        "payload": entry.get("payload", ""),
                    })
                except (json.JSONDecodeError, TypeError):
                    continue

        if findings:
            status_counts: dict[int, int] = {}
            for f in findings:
                s = f.get("status", 0)
                status_counts[s] = status_counts.get(s, 0) + 1
            parts = [f"wfuzz: {len(findings)} results"]
            for code, count in sorted(status_counts.items()):
                parts.append(f"  {code}: {count}")
            summary = "\n".join(parts)
        else:
            summary = "wfuzz: no results"

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


registry.register(WfuzzTool())
