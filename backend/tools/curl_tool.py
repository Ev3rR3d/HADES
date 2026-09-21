"""cURL — flexible HTTP request tool for probing, testing, and exploiting web endpoints."""

from __future__ import annotations

import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry


class CurlTool(ToolDefinition):
    name = "curl"
    binary = "curl"
    description = "Flexible HTTP client — probe endpoints, test auth, send payloads, check responses. Use 'url' param for specific paths/endpoints."
    category = "exploitation"
    risk = "low"
    timeout = 30
    params = [
        ToolParam("url", "Full URL to request (overrides target). Use for specific paths like https://target/graphql or https://target/api/v1/users"),
        ToolParam("method", "HTTP method", default="GET", choices=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]),
        ToolParam("headers", "Extra headers as 'Key: Value' strings, comma-separated"),
        ToolParam("data", "Request body data (for POST/PUT/PATCH). JSON, form data, or raw payload"),
        ToolParam("cookies", "Cookies to send as 'name=value; name2=value2'"),
        ToolParam("user_agent", "Custom User-Agent string"),
        ToolParam("follow_redirects", "Follow HTTP redirects", param_type="bool", default=True),
        ToolParam("include_headers", "Include response headers in output", param_type="bool", default=True),
        ToolParam("raw_flags", "Additional raw curl flags as a string (e.g. '--connect-timeout 5 -k')"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        method = params.get("method", "GET")
        url = params.get("url") or target
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        args = ["-s", "-X", method]

        if params.get("follow_redirects", True):
            args.append("-L")

        if params.get("include_headers", True):
            args.append("-i")

        headers = params.get("headers")
        if headers:
            if isinstance(headers, str):
                for h in headers.split(","):
                    h = h.strip()
                    if h:
                        args.extend(["-H", h])
            elif isinstance(headers, list):
                for h in headers:
                    args.extend(["-H", h])

        data = params.get("data")
        if data:
            args.extend(["-d", data])

        cookies = params.get("cookies")
        if cookies:
            args.extend(["-b", cookies])

        user_agent = params.get("user_agent")
        if user_agent:
            args.extend(["-A", user_agent])

        raw_flags = params.get("raw_flags")
        if raw_flags:
            args.extend(raw_flags.split())

        args.extend(["--max-time", "20"])
        args.append(url)

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        headers_dict: dict[str, str] = {}
        status_code = 0
        body = ""

        # Parse status line (get the LAST one in case of redirects)
        for m in re.finditer(r"HTTP/[\d.]+ (\d{3})", stdout):
            status_code = int(m.group(1))

        # Split headers from body
        parts = re.split(r"\r?\n\r?\n", stdout)
        if len(parts) >= 2:
            # Last header block + body
            for i, part in enumerate(parts):
                if part.strip().startswith("HTTP/"):
                    header_block = part
                else:
                    body = "\n\n".join(parts[i:])
                    break
                header_block = part

            for line in header_block.splitlines():
                if ":" in line and not line.startswith("HTTP/"):
                    key, _, val = line.partition(":")
                    headers_dict[key.strip().lower()] = val.strip()

        server = headers_dict.get("server", "")
        content_type = headers_dict.get("content-type", "")

        finding = {
            "status_code": status_code,
            "server": server,
            "content_type": content_type,
            "headers": headers_dict,
        }
        if body:
            finding["body_length"] = len(body)
            finding["body_preview"] = body[:500]
        findings.append(finding)

        summary = f"HTTP {status_code}"
        if server:
            summary += f" | Server: {server}"
        if content_type:
            summary += f" | Type: {content_type}"
        if body:
            summary += f" | Body: {len(body)} bytes"

        security_headers = ["x-frame-options", "content-security-policy",
                            "strict-transport-security", "x-content-type-options"]
        missing = [h for h in security_headers if h not in headers_dict]
        if missing:
            summary += f"\nMissing security headers: {', '.join(missing)}"

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0,
            summary=summary,
            raw_output=stdout[:100_000],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(CurlTool())
