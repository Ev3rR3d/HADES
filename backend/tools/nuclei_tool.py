"""HADES tool wrapper for nuclei — template-based vulnerability scanner."""

from __future__ import annotations

import json
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000


class NucleiTool(ToolDefinition):
    name = "nuclei"
    binary = "nuclei"
    description = "Fast template-based vulnerability scanner — bulk CVE, misconfig, exposure, and technology detection"
    category = "enumeration"
    risk = "medium"
    timeout = 600
    params = [
        ToolParam("severity", "Comma-separated severity filter", default="critical,high,medium"),
        ToolParam("templates", "Specific template directory or path"),
        ToolParam("tags", "Comma-separated template tags (e.g. cve,misconfig,exposure)"),
        ToolParam("rate_limit", "Max requests per second", param_type="int", default=150),
        ToolParam("bulk_size", "Parallel template execution count", param_type="int", default=25),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        severity = params.get("severity", "critical,high,medium")
        rate_limit = str(params.get("rate_limit", 150))
        bulk_size = str(params.get("bulk_size", 25))

        args = [
            "-u", target,
            "-severity", severity,
            "-rl", rate_limit,
            "-bs", bulk_size,
            "-jsonl",
            "-silent",
        ]

        templates = params.get("templates")
        if templates:
            args.extend(["-t", templates])

        tags = params.get("tags")
        if tags:
            args.extend(["-tags", tags])

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        severity_counts: dict[str, int] = {}

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = entry.get("info", {})
            sev = info.get("severity", "unknown").lower()
            matched_at = entry.get("matched-at", entry.get("host", ""))
            template_id = entry.get("template-id", entry.get("templateID", ""))
            name = info.get("name", template_id)
            description = info.get("description", "")
            extracted = entry.get("extracted-results", [])
            matcher_name = entry.get("matcher-name", "")
            curl_command = entry.get("curl-command", "")

            finding = {
                "template_id": template_id,
                "name": name,
                "severity": sev,
                "matched_at": matched_at,
                "description": description,
                "extracted_results": extracted,
            }
            if matcher_name:
                finding["matcher_name"] = matcher_name
            if curl_command:
                finding["curl_command"] = curl_command

            findings.append(finding)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if findings:
            parts = [f"nuclei: {len(findings)} vulnerabilities found"]
            for sev in ("critical", "high", "medium", "low", "info", "unknown"):
                count = severity_counts.get(sev, 0)
                if count:
                    parts.append(f"  {sev}: {count}")
            summary = "\n".join(parts)
        else:
            summary = "nuclei: no vulnerabilities found"

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


registry.register(NucleiTool())
