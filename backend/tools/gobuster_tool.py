"""HADES tool wrapper for gobuster — directory/DNS/vhost brute-forcer."""

from __future__ import annotations

import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry, resolve_wordlist

_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
_MAX_BYTES = 512_000


class GobusterTool(ToolDefinition):
    name = "gobuster"
    binary = "gobuster"
    description = "Directory/file, DNS subdomain, and virtual host brute-forcer"
    category = "enumeration"
    risk = "low"
    timeout = 120
    params = [
        ToolParam("mode", "Scan mode", default="dir", choices=["dir", "dns", "vhost"]),
        ToolParam("wordlist", "Path to wordlist file (default: dirb/common.txt ~4.6k entries)", default=_DEFAULT_WORDLIST),
        ToolParam("threads", "Number of concurrent threads", param_type="int", default=40),
        ToolParam("extensions", "Comma-separated file extensions for dir mode (e.g. php,html,txt)"),
        ToolParam("status_codes", "Status codes to include (e.g. '200,301,302,403')"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        mode = params.get("mode", "dir")
        wordlist = resolve_wordlist(params.get("wordlist", _DEFAULT_WORDLIST))
        threads = str(params.get("threads", 40))

        if mode == "dns":
            domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
            args = ["dns", "-d", domain, "-w", wordlist, "-t", threads, "--no-color"]
        elif mode == "vhost":
            url = target if target.startswith(("http://", "https://")) else f"http://{target}"
            args = ["vhost", "-u", url, "-w", wordlist, "-t", threads, "--no-color"]
        else:
            url = target if target.startswith(("http://", "https://")) else f"http://{target}"
            args = ["dir", "-u", url, "-w", wordlist, "-t", threads, "--no-color"]
            extensions = params.get("extensions")
            if extensions:
                args.extend(["-x", extensions])
            status_codes = params.get("status_codes")
            if status_codes:
                args.extend(["-s", status_codes])

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        mode = "dir"

        for line in (stdout + "\n" + stderr).splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # dir mode with size: /path                 (Status: 200) [Size: 1234]
            dir_match = re.search(
                r"(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", stripped
            )
            if dir_match:
                findings.append({
                    "path": dir_match.group(1),
                    "status": int(dir_match.group(2)),
                    "size": int(dir_match.group(3)),
                })
                continue

            # dir mode without size: /path (Status: 301)
            dir_match2 = re.search(r"(/\S+)\s+\(Status:\s*(\d+)\)", stripped)
            if dir_match2:
                findings.append({
                    "path": dir_match2.group(1),
                    "status": int(dir_match2.group(2)),
                    "size": 0,
                })
                continue

            # vhost mode: "Found: host.example.com Status: 200 [Size: 1234]"
            vhost_match = re.search(r"Found:\s*(\S+)\s+Status:\s*(\d+)", stripped)
            if vhost_match:
                mode = "vhost"
                findings.append({
                    "vhost": vhost_match.group(1),
                    "status": int(vhost_match.group(2)),
                })
                continue

            # dns mode: "Found: sub.domain.com"
            dns_match = re.search(r"Found:\s*(\S+)", stripped)
            if dns_match:
                mode = "dns"
                findings.append({"subdomain": dns_match.group(1)})

        if findings:
            if mode == "dns":
                summary = f"gobuster dns: {len(findings)} subdomains found"
            elif mode == "vhost":
                summary = f"gobuster vhost: {len(findings)} virtual hosts found"
            else:
                status_counts: dict[int, int] = {}
                for f in findings:
                    s = f.get("status", 0)
                    status_counts[s] = status_counts.get(s, 0) + 1
                summary = f"gobuster dir: {len(findings)} paths found"
                for code, count in sorted(status_counts.items()):
                    summary += f"\n  {code}: {count}"
        else:
            summary = "gobuster: no results found"

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


registry.register(GobusterTool())
