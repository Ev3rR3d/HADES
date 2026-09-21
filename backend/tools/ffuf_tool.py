"""HADES tool wrapper for ffuf — web fuzzer / directory brute-forcer."""

from __future__ import annotations

import json
import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry, resolve_wordlist

_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
_MAX_BYTES = 512_000


class FfufTool(ToolDefinition):
    name = "ffuf"
    binary = "ffuf"
    description = "Fast web fuzzer for directory/file discovery, virtual host enumeration, and parameter brute-forcing"
    category = "enumeration"
    risk = "low"
    timeout = 120
    params = [
        ToolParam("wordlist", "Path to wordlist file (default: dirb/common.txt ~4.6k entries)", default=_DEFAULT_WORDLIST),
        ToolParam("extensions", "Comma-separated extensions to append (e.g. php,html,js)"),
        ToolParam("method", "HTTP method", default="GET", choices=["GET", "POST", "HEAD"]),
        ToolParam("filter_codes", "Status codes to filter out", default="404"),
        ToolParam("threads", "Number of concurrent threads", param_type="int", default=40),
        ToolParam("recursion_depth", "Recursion depth (0 = off)", param_type="int", default=0),
        ToolParam("filter_size", "Filter responses by size (e.g. '0' to hide empty)"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        wordlist = resolve_wordlist(params.get("wordlist", _DEFAULT_WORDLIST))
        filter_codes = params.get("filter_codes", "404")
        threads = str(params.get("threads", 40))

        url = target.rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        url += "/FUZZ"

        args = [
            "-u", url,
            "-w", wordlist,
            "-mc", "all",
            "-fc", str(filter_codes),
            "-t", threads,
            "-of", "json",
            "-o", "/dev/stdout",
            "-s",
            "-maxtime", str(self.timeout - 15),
        ]

        extensions = params.get("extensions")
        if extensions:
            args.extend(["-e", extensions])

        filter_size = params.get("filter_size")
        if filter_size:
            args.extend(["-fs", str(filter_size)])

        depth = int(params.get("recursion_depth", 0))
        if depth > 0:
            args.extend(["-recursion", "-recursion-depth", str(depth)])

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        status_counts: dict[int, int] = {}

        try:
            data = json.loads(stdout)
            results = data.get("results", [])
            for r in results:
                status = r.get("status", 0)
                finding = {
                    "url": r.get("url", ""),
                    "status": status,
                    "size": r.get("length", 0),
                    "words": r.get("words", 0),
                }
                findings.append(finding)
                status_counts[status] = status_counts.get(status, 0) + 1
        except (json.JSONDecodeError, TypeError):
            for line in stdout.splitlines():
                m = re.search(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+)", line)
                if m:
                    status = int(m.group(2))
                    findings.append({
                        "url": m.group(1),
                        "status": status,
                        "size": int(m.group(3)),
                        "words": int(m.group(4)),
                    })
                    status_counts[status] = status_counts.get(status, 0) + 1

        if findings:
            parts = [f"ffuf: {len(findings)} paths found"]
            for code, count in sorted(status_counts.items()):
                parts.append(f"  {code}: {count}")
            summary = "\n".join(parts)
        else:
            summary = "ffuf: no paths discovered"

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0 or len(findings) > 0,
            summary=summary,
            raw_output=(stdout + "\n" + stderr).strip()[:_MAX_BYTES],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(FfufTool())
