"""CORS Probe — test for Cross-Origin Resource Sharing misconfigurations."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

logger = logging.getLogger("hades.tools.cors_probe")

_MAX_OUTPUT = 512_000


class CorsProbeTool(ToolDefinition):
    name = "cors_probe"
    binary = "curl"
    description = (
        "Test for CORS misconfigurations — sends Origin headers with evil domains "
        "and checks if the server reflects them or allows credentials"
    )
    category = "exploitation"
    risk = "low"
    timeout = 30
    params = [
        ToolParam("url", "Target URL to test for CORS misconfiguration", required=True),
        ToolParam(
            "origins",
            "Comma-separated list of test origins",
            default="https://evil.com,null,https://attacker.com",
        ),
    ]

    async def _curl_origin(self, url: str, origin: str) -> tuple[str, str | None]:
        """Send a request with an Origin header and return (raw_headers, error)."""
        args = [
            "curl", "-sI", "-k", "--max-time", "10",
            "-H", f"Origin: {origin}",
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
            return stdout_raw.decode("utf-8", errors="replace"), None
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return "", "timeout"
        except Exception as exc:
            return "", str(exc)

    @staticmethod
    def _get_header(headers: str, name: str) -> str | None:
        for line in headers.splitlines():
            if line.lower().startswith(name.lower() + ":"):
                return line.split(":", 1)[1].strip()
        return None

    async def run(self, target: str, params: dict[str, Any] | None = None) -> ToolResult:
        params = params or {}
        if not self.is_available():
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary=f"{self.binary} not found in PATH",
                raw_output="", error=f"{self.binary} not installed",
            )

        url = params.get("url") or target
        origins_raw = params.get("origins", "https://evil.com,null,https://attacker.com")
        origins = [o.strip() for o in origins_raw.split(",") if o.strip()]

        start = time.monotonic()
        findings: list[dict] = []
        log_rows = ["ORIGIN | ACAO | ACAC | VERDICT"]
        log_rows.append("-" * 72)

        for origin in origins:
            raw_headers, error = await self._curl_origin(url, origin)
            if error:
                log_rows.append(f"{origin} | ERROR: {error}")
                continue

            acao = self._get_header(raw_headers, "Access-Control-Allow-Origin")
            acac = self._get_header(raw_headers, "Access-Control-Allow-Credentials")
            has_creds = acac and acac.lower() == "true"

            verdict = "safe"

            if acao == "*":
                verdict = "wildcard"
                severity = "medium"
                if has_creds:
                    severity = "high"
                    verdict = "wildcard+credentials"
                findings.append({
                    "type": "cors_misconfiguration",
                    "severity": severity,
                    "origin_tested": origin,
                    "acao": acao,
                    "credentials": has_creds,
                    "detail": f"CORS wildcard (*) allows any origin"
                              + (" with credentials" if has_creds else ""),
                    "url": url,
                })
            elif acao and acao == origin:
                verdict = "reflected"
                severity = "medium"
                if has_creds:
                    severity = "high"
                    verdict = "reflected+credentials"
                findings.append({
                    "type": "cors_misconfiguration",
                    "severity": severity,
                    "origin_tested": origin,
                    "acao": acao,
                    "credentials": has_creds,
                    "detail": f"Origin '{origin}' reflected in ACAO"
                              + (" with credentials — full exploit possible" if has_creds else ""),
                    "url": url,
                })
            elif acao and origin == "null" and acao == "null":
                verdict = "null_reflected"
                severity = "medium"
                if has_creds:
                    severity = "high"
                    verdict = "null+credentials"
                findings.append({
                    "type": "cors_misconfiguration",
                    "severity": severity,
                    "origin_tested": "null",
                    "acao": acao,
                    "credentials": has_creds,
                    "detail": "Null origin reflected — exploitable via sandboxed iframe"
                              + (" with credentials" if has_creds else ""),
                    "url": url,
                })

            log_rows.append(
                f"{origin:<30} | {acao or '(none)':<30} | "
                f"{'true' if has_creds else 'false':<6} | {verdict}"
            )

        elapsed = time.monotonic() - start

        if findings:
            high = [f for f in findings if f["severity"] == "high"]
            if high:
                summary = f"CORS CRITICAL — {len(high)} high-severity misconfiguration(s) (credentials exposed)"
            else:
                summary = f"CORS MISCONFIGURED — {len(findings)} issue(s) found"
        else:
            summary = f"CORS appears properly configured ({len(origins)} origins tested)"

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


registry.register(CorsProbeTool())
