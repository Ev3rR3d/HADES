"""Header Probe — analyze HTTP response headers for security issues."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

logger = logging.getLogger("hades.tools.header_probe")

_MAX_OUTPUT = 512_000

_SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HSTS", "medium"),
    "Content-Security-Policy": ("CSP", "medium"),
    "X-Frame-Options": ("Clickjacking protection", "low"),
    "X-Content-Type-Options": ("MIME sniffing protection", "low"),
    "X-XSS-Protection": ("XSS filter", "info"),
    "Referrer-Policy": ("Referrer leakage protection", "low"),
    "Permissions-Policy": ("Browser feature restrictions", "info"),
}

_SERVER_VERSION_RE = re.compile(
    r"(Apache|nginx|IIS|LiteSpeed|Tomcat|Jetty|Caddy|OpenResty)"
    r"[/\s]+[\d.]+",
    re.IGNORECASE,
)


class HeaderProbeTool(ToolDefinition):
    name = "header_probe"
    binary = "curl"
    description = (
        "Analyze HTTP response headers for missing security headers, "
        "server version disclosure, and cookie security issues"
    )
    category = "scanning"
    risk = "low"
    timeout = 20
    params = [
        ToolParam("url", "Target URL to analyze headers", required=True),
    ]

    async def run(self, target: str, params: dict[str, Any] | None = None) -> ToolResult:
        params = params or {}
        if not self.is_available():
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary=f"{self.binary} not found in PATH",
                raw_output="", error=f"{self.binary} not installed",
            )

        url = params.get("url") or target
        start = time.monotonic()

        # Fetch headers
        args = ["curl", "-sI", "-k", "--max-time", "10", "-L", url]
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
            stdout_raw, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            raw_headers = stdout_raw.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            elapsed = time.monotonic() - start
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary="Request timed out", raw_output="",
                duration=elapsed, error="timeout",
            )
        except Exception as exc:
            elapsed = time.monotonic() - start
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary=f"Request failed: {exc}", raw_output="",
                duration=elapsed, error=str(exc),
            )

        if not raw_headers.strip():
            elapsed = time.monotonic() - start
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary="Empty response from server", raw_output="",
                duration=elapsed, error="empty_response",
            )

        findings: list[dict] = []
        log_rows = ["HEADER | STATUS | SEVERITY"]
        log_rows.append("-" * 60)

        # Build a lookup of present headers (case-insensitive)
        header_map: dict[str, str] = {}
        for line in raw_headers.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                header_map[key.strip().lower()] = val.strip()

        # Check security headers
        for header_name, (label, severity) in _SECURITY_HEADERS.items():
            present = header_name.lower() in header_map
            status = "PRESENT" if present else "MISSING"
            log_rows.append(f"{header_name:<35} | {status:<10} | {severity if not present else 'ok'}")

            if not present:
                findings.append({
                    "type": "missing_security_header",
                    "severity": severity,
                    "header": header_name,
                    "detail": f"Missing {label} header ({header_name})",
                    "url": url,
                })

        # Server version disclosure
        server_val = header_map.get("server", "")
        x_powered = header_map.get("x-powered-by", "")
        for label, value in [("Server", server_val), ("X-Powered-By", x_powered)]:
            if value:
                match = _SERVER_VERSION_RE.search(value)
                if match or (label == "X-Powered-By" and value):
                    log_rows.append(f"{label:<35} | {value:<30} | low")
                    findings.append({
                        "type": "server_disclosure",
                        "severity": "low",
                        "header": label,
                        "value": value,
                        "detail": f"{label} discloses: {value}",
                        "url": url,
                    })

        # Cookie analysis
        cookies: list[str] = []
        for line in raw_headers.splitlines():
            if line.lower().startswith("set-cookie:"):
                cookies.append(line.split(":", 1)[1].strip())

        for cookie in cookies:
            cookie_name = cookie.split("=")[0].strip() if "=" in cookie else cookie[:30]
            cookie_lower = cookie.lower()
            issues: list[str] = []

            if "secure" not in cookie_lower:
                issues.append("missing Secure flag")
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite attribute")

            if issues:
                detail = f"Cookie '{cookie_name}': {', '.join(issues)}"
                log_rows.append(f"Set-Cookie ({cookie_name})" + " " * max(0, 25 - len(cookie_name)) + f" | {', '.join(issues)}")
                findings.append({
                    "type": "cookie_security",
                    "severity": "low",
                    "cookie": cookie_name,
                    "issues": issues,
                    "detail": detail,
                    "url": url,
                })

        elapsed = time.monotonic() - start

        # Summary
        missing_count = sum(1 for f in findings if f["type"] == "missing_security_header")
        disclosure_count = sum(1 for f in findings if f["type"] == "server_disclosure")
        cookie_count = sum(1 for f in findings if f["type"] == "cookie_security")

        parts = []
        if missing_count:
            parts.append(f"{missing_count} missing security header(s)")
        if disclosure_count:
            parts.append(f"{disclosure_count} server disclosure(s)")
        if cookie_count:
            parts.append(f"{cookie_count} cookie issue(s)")

        if parts:
            summary = f"Header issues found: {'; '.join(parts)}"
        else:
            summary = "All security headers present, no issues detected"

        # Prepend the raw headers to log
        raw_output = "=== Response Headers ===\n" + raw_headers + "\n=== Analysis ===\n" + "\n".join(log_rows)

        return ToolResult(
            tool=self.name,
            target=target,
            success=True,
            summary=summary,
            raw_output=raw_output[:_MAX_OUTPUT],
            findings=findings,
            duration=elapsed,
            exit_code=0,
        )

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        return []

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        return ToolResult(
            tool=self.name, target=target, success=True,
            summary="", raw_output=stdout, exit_code=exit_code,
        )


registry.register(HeaderProbeTool())
