"""Hydra — network login brute-force tool."""

from __future__ import annotations

import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry


class HydraTool(ToolDefinition):
    name = "hydra"
    binary = "hydra"
    description = "Brute-force network logins (SSH, FTP, HTTP, etc.) with wordlists"
    category = "exploitation"
    risk = "high"
    timeout = 300
    params = [
        ToolParam("service", "Target service: ssh, ftp, http-get, http-post-form, rdp, mysql, etc.", required=True),
        ToolParam("username", "Single username to test"),
        ToolParam("userlist", "Path to username wordlist"),
        ToolParam("passlist", "Path to password wordlist", default="/usr/share/wordlists/rockyou.txt"),
        ToolParam("threads", "Parallel threads", param_type="int", default=16),
        ToolParam("port", "Target port (overrides default for service)", param_type="int"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        service = params.get("service", "ssh")
        threads = params.get("threads", 16)
        passlist = params.get("passlist", "/usr/share/wordlists/rockyou.txt")

        args = ["-t", str(threads)]

        username = params.get("username")
        userlist = params.get("userlist")
        if username:
            args.extend(["-l", username])
        elif userlist:
            args.extend(["-L", userlist])
        else:
            args.extend(["-l", "admin"])

        args.extend(["-P", passlist])

        port = params.get("port")
        if port:
            args.extend(["-s", str(port)])

        args.append(target)
        args.append(service)

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        combined = stdout + "\n" + stderr
        findings: list[dict] = []

        # [22][ssh] host: 10.0.0.1   login: admin   password: secret
        for m in re.finditer(
            r"\[(\d+)\]\[(\S+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
            combined,
        ):
            findings.append({
                "port": int(m.group(1)),
                "service": m.group(2),
                "host": m.group(3),
                "username": m.group(4),
                "password": m.group(5),
            })

        if findings:
            summary = f"CREDENTIALS FOUND — {len(findings)} valid login(s)"
            for f in findings[:5]:
                summary += f"\n  {f['service']}://{f['username']}:{f['password']}@{f['host']}:{f['port']}"
        elif "0 valid password" in combined.lower() or exit_code == 0:
            summary = "No valid credentials found"
        else:
            summary = f"hydra finished (exit {exit_code}) — review output for details"

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0,
            summary=summary,
            raw_output=combined[:100_000],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(HydraTool())
