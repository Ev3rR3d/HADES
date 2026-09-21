"""Redirect Probe — test for open redirect vulnerabilities."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

logger = logging.getLogger("hades.tools.redirect_probe")

_MAX_OUTPUT = 512_000

_REDIRECT_PARAMS = [
    "url", "redirect", "next", "redir", "return", "returnUrl", "return_url",
    "redirect_uri", "redirect_url", "dest", "destination", "go", "target",
    "to", "out", "continue", "forward", "ref",
]

_PAYLOADS = [
    ("https://evil.com", "absolute URL"),
    ("//evil.com", "protocol-relative"),
    ("/\\evil.com", "backslash bypass"),
    ("https://evil.com%00.target.com", "null byte bypass"),
]


class RedirectProbeTool(ToolDefinition):
    name = "redirect_probe"
    binary = "curl"
    description = (
        "Test for open redirect vulnerabilities by injecting redirect payloads "
        "into URL parameters and checking Location headers"
    )
    category = "exploitation"
    risk = "medium"
    timeout = 30
    params = [
        ToolParam("url", "URL with redirect parameter (e.g. https://target/login?next=/dashboard)", required=True),
        ToolParam("param", "Name of the redirect parameter to test (auto-detected if empty)"),
    ]

    @staticmethod
    def _detect_redirect_param(url: str) -> str | None:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for candidate in _REDIRECT_PARAMS:
            for key in qs:
                if key.lower() == candidate.lower():
                    return key
        # Fallback: return first query param if any
        keys = list(qs.keys())
        return keys[0] if keys else None

    @staticmethod
    def _inject_payload(url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    async def _curl_redirect(self, url: str) -> tuple[int, str, str, str | None]:
        """Return (status_code, redirect_url, raw_headers, error)."""
        args = [
            "curl", "-s", "-k", "-o", "/dev/null",
            "-w", "%{redirect_url}\n%{http_code}",
            "-D", "-",
            "--max-time", "10",
            url,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
            stdout_raw, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            raw = stdout_raw.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return 0, "", "", "timeout"
        except Exception as exc:
            return 0, "", "", str(exc)

        # Split: headers come first (via -D -), then curl -w output appended
        # The -w output is the last two lines: redirect_url\nhttp_code
        lines = raw.rstrip().rsplit("\n", 2)
        if len(lines) >= 3:
            headers = "\n".join(lines[:-2])
            redirect_url = lines[-2]
            try:
                status = int(lines[-1])
            except ValueError:
                status = 0
        elif len(lines) == 2:
            headers = ""
            redirect_url = lines[0]
            try:
                status = int(lines[1])
            except ValueError:
                status = 0
        else:
            headers = raw
            redirect_url = ""
            status = 0

        return status, redirect_url, headers, None

    @staticmethod
    def _extract_location(headers: str) -> str:
        for line in headers.splitlines():
            if line.lower().startswith("location:"):
                return line.split(":", 1)[1].strip()
        return ""

    @staticmethod
    def _is_evil_redirect(value: str) -> bool:
        """Check if the redirect URL points to evil.com."""
        if not value:
            return False
        lower = value.lower()
        return "evil.com" in lower

    async def run(self, target: str, params: dict[str, Any] | None = None) -> ToolResult:
        params = params or {}
        if not self.is_available():
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary=f"{self.binary} not found in PATH",
                raw_output="", error=f"{self.binary} not installed",
            )

        url = params.get("url") or target
        param_name = params.get("param") or self._detect_redirect_param(url)

        if not param_name:
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary="No redirect parameter detected. Provide 'param' or use a URL with ?url=, ?next=, etc.",
                raw_output="", error="no_redirect_param",
            )

        start = time.monotonic()
        findings: list[dict] = []
        log_rows = [f"PAYLOAD | STATUS | REDIRECT_URL | LOCATION | VERDICT"]
        log_rows.append("-" * 90)

        for payload, payload_type in _PAYLOADS:
            test_url = self._inject_payload(url, param_name, payload)
            status, redirect_url, headers, error = await self._curl_redirect(test_url)

            if error:
                log_rows.append(f"{payload_type:<25} | ERROR: {error}")
                continue

            location = self._extract_location(headers)
            redirects_to_evil = self._is_evil_redirect(redirect_url) or self._is_evil_redirect(location)

            verdict = "VULNERABLE" if redirects_to_evil else "safe"
            log_rows.append(
                f"{payload_type:<25} | {status:<6} | "
                f"{redirect_url or '(none)':<30} | {location[:30] or '(none)':<30} | {verdict}"
            )

            if redirects_to_evil:
                findings.append({
                    "type": "open_redirect",
                    "severity": "medium",
                    "parameter": param_name,
                    "payload": payload,
                    "payload_type": payload_type,
                    "redirect_url": redirect_url or location,
                    "status_code": status,
                    "detail": f"Open redirect via {payload_type}: param '{param_name}' "
                              f"redirects to attacker-controlled domain",
                    "url": test_url,
                })

        elapsed = time.monotonic() - start

        if findings:
            types = sorted({f["payload_type"] for f in findings})
            summary = (
                f"OPEN REDIRECT — {len(findings)} confirmed redirect(s) via param '{param_name}' "
                f"({', '.join(types)})"
            )
        else:
            summary = f"No open redirect found on param '{param_name}' ({len(_PAYLOADS)} payloads tested)"

        return ToolResult(
            tool=self.name,
            target=target,
            success=True,
            summary=summary,
            raw_output="\n".join(log_rows)[:_MAX_OUTPUT],
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


registry.register(RedirectProbeTool())
