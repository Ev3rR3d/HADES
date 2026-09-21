"""HADES tool wrapper for nikto — web server scanner for misconfigurations and vulnerabilities."""

from __future__ import annotations

import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000
_OSVDB_RE = re.compile(r"OSVDB-(\d+)")


class NiktoTool(ToolDefinition):
    name = "nikto"
    binary = "nikto"
    description = "Web server scanner — finds misconfigurations, dangerous files, outdated software, and known vulnerabilities"
    category = "scanning"
    risk = "medium"
    timeout = 300
    params = [
        ToolParam("tuning", "Nikto scan tuning codes (e.g. '1234567890abc')"),
        ToolParam("ssl", "Force SSL connection", param_type="bool", default=False),
        ToolParam("port", "Specific port to scan"),
        ToolParam("maxtime", "Max scan time", default="240s"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        maxtime = params.get("maxtime", "240s")

        args = [
            "-h", target,
            "-Format", "txt",
            "-nointeractive",
            "-maxtime", str(maxtime),
        ]

        if params.get("ssl"):
            args.append("-ssl")

        tuning = params.get("tuning")
        if tuning:
            args.extend(["-Tuning", tuning])

        port = params.get("port")
        if port:
            args.extend(["-p", str(port)])

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        server_info: list[str] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("+"):
                continue

            # Strip the leading "+ " prefix
            content = line.lstrip("+ ").strip()
            if not content:
                continue

            # Server identification lines
            if content.startswith("Server:"):
                server_info.append(content)
                findings.append({
                    "type": "server_info",
                    "description": content,
                })
                continue

            # Skip nikto banner/summary lines
            if any(kw in content for kw in (
                "Target IP:", "Target Hostname:", "Target Port:",
                "Start Time:", "End Time:", "host(s) tested",
                "-----------", "requests:", "Nikto v",
            )):
                continue

            finding: dict[str, Any] = {
                "type": "finding",
                "description": content,
            }

            # Extract OSVDB ID if present
            osvdb = _OSVDB_RE.search(content)
            if osvdb:
                finding["osvdb_id"] = osvdb.group(1)

            # Extract URL/path if present
            url_match = re.search(r"(/\S+)", content)
            if url_match:
                finding["url"] = url_match.group(1).rstrip(":.")

            # Categorize by keywords
            lower = content.lower()
            if "x-" in lower and "header" in lower:
                finding["type"] = "header_issue"
            elif "directory" in lower and ("index" in lower or "listing" in lower):
                finding["type"] = "directory_listing"
            elif osvdb:
                finding["type"] = "osvdb"
            elif "server" in lower or "version" in lower:
                finding["type"] = "server_info"

            findings.append(finding)

        if findings:
            issue_count = sum(1 for f in findings if f["type"] != "server_info")
            parts = [f"nikto: {len(findings)} items found ({issue_count} potential issues)"]
            if server_info:
                parts.append(server_info[0])
            summary = "\n".join(parts)
        else:
            summary = "nikto: no findings"

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


registry.register(NiktoTool())
