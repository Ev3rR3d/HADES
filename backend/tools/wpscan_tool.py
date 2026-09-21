"""HADES tool wrapper for wpscan — WordPress security scanner."""

from __future__ import annotations

import json
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000


class WPScanTool(ToolDefinition):
    name = "wpscan"
    binary = "wpscan"
    description = "WordPress security scanner — enumerates users, plugins, themes, and known vulnerabilities"
    category = "scanning"
    risk = "medium"
    timeout = 300
    params = [
        ToolParam("enumerate", "What to enumerate (u=users, vp=vulnerable plugins, vt=vulnerable themes, cb=config backups)", default="u,vp,vt,cb"),
        ToolParam("api_token", "WPScan API token for vulnerability data"),
        ToolParam("detection_mode", "Detection mode", default="aggressive", choices=["passive", "mixed", "aggressive"]),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        enumerate = params.get("enumerate", "u,vp,vt,cb")
        detection_mode = params.get("detection_mode", "aggressive")

        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        args = [
            "--url", url,
            "--enumerate", enumerate,
            "--detection-mode", detection_mode,
            "--no-banner",
            "--format", "json",
            "--random-user-agent",
        ]

        api_token = params.get("api_token")
        if api_token:
            args.extend(["--api-token", api_token])

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []

        try:
            data = json.loads(stdout)

            for vuln in data.get("interesting_findings", []):
                findings.append({
                    "type": "interesting_finding",
                    "url": vuln.get("url", ""),
                    "description": vuln.get("to_s", ""),
                    "references": vuln.get("references", {}),
                })

            version_info = data.get("version", {})
            if version_info:
                findings.append({
                    "type": "version",
                    "number": version_info.get("number", "unknown"),
                    "status": version_info.get("status", ""),
                })
                for vuln in version_info.get("vulnerabilities", []):
                    findings.append({
                        "type": "vulnerability",
                        "title": vuln.get("title", ""),
                        "cve": vuln.get("references", {}).get("cve", []),
                        "fixed_in": vuln.get("fixed_in", ""),
                    })

            for slug, plugin in data.get("plugins", {}).items():
                for vuln in plugin.get("vulnerabilities", []):
                    findings.append({
                        "type": "plugin_vulnerability",
                        "plugin": slug,
                        "title": vuln.get("title", ""),
                        "cve": vuln.get("references", {}).get("cve", []),
                        "fixed_in": vuln.get("fixed_in", ""),
                    })

            for slug, theme in data.get("themes", {}).items():
                for vuln in theme.get("vulnerabilities", []):
                    findings.append({
                        "type": "theme_vulnerability",
                        "theme": slug,
                        "title": vuln.get("title", ""),
                        "cve": vuln.get("references", {}).get("cve", []),
                        "fixed_in": vuln.get("fixed_in", ""),
                    })

            for user in data.get("users", {}).values():
                findings.append({
                    "type": "user",
                    "username": user.get("slug", ""),
                    "id": user.get("id", ""),
                })

        except (json.JSONDecodeError, TypeError):
            pass

        vulns = [f for f in findings if "vulnerability" in f.get("type", "")]
        users = [f for f in findings if f.get("type") == "user"]
        if vulns:
            summary = f"wpscan: {len(vulns)} vulnerabilities found, {len(users)} users enumerated"
        elif findings:
            summary = f"wpscan: {len(findings)} items found ({len(users)} users)"
        else:
            summary = "wpscan: no findings"

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


registry.register(WPScanTool())
