"""Subdomain Takeover Probe — check subdomains for takeover signatures."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

logger = logging.getLogger("hades.tools.takeover_probe")

_MAX_OUTPUT = 512_000

_TAKEOVER_SIGNATURES = [
    ("There is no app configured at that hostname", "Heroku"),
    ("NoSuchBucket", "AWS S3"),
    ("Repository not found", "GitHub Pages"),
    ("No such app", "Fly.io"),
    ("Project not found", "Surge.sh"),
    ("Fastly error: unknown domain", "Fastly"),
    ("There isn't a GitHub Pages site here", "GitHub Pages"),
    ("The request could not be satisfied", "AWS CloudFront"),
    ("NoSuchKey", "AWS S3"),
    ("Sorry, this shop is currently unavailable", "Shopify"),
    ("Do you want to register", "WordPress.com"),
]


class TakeoverProbeTool(ToolDefinition):
    name = "takeover_probe"
    binary = "curl"
    description = (
        "Check subdomains for takeover signatures — detects dangling DNS "
        "pointing to deprovisioned services (Heroku, S3, GitHub Pages, etc.)"
    )
    category = "exploitation"
    risk = "medium"
    timeout = 60
    params = [
        ToolParam("subdomains", "Comma-separated list of subdomains to check", required=True),
    ]

    async def _check_dns(self, subdomain: str) -> tuple[bool, str]:
        """Return (has_dns, detail). If NXDOMAIN, has_dns=False."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", subdomain,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
            stdout_raw, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout_raw.decode("utf-8", errors="replace").strip()
            if not output:
                return False, "NXDOMAIN (no DNS records)"
            return True, output.splitlines()[0]
        except Exception:
            return True, "DNS check failed, proceeding with HTTP"

    async def _curl_subdomain(self, subdomain: str) -> tuple[str, int, str | None]:
        """Fetch the subdomain and return (body, status_code, error)."""
        url = f"https://{subdomain}"
        args = [
            "curl", "-sk", "--max-time", "10",
            "-w", "\n%{http_code}",
            "-L",
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
            # Retry with HTTP
            return await self._curl_subdomain_http(subdomain)
        except Exception as exc:
            return "", 0, str(exc)

        lines = raw.rsplit("\n", 1)
        if len(lines) == 2:
            body = lines[0]
            try:
                status = int(lines[1])
            except ValueError:
                status = 0
        else:
            body = raw
            status = 0
        return body, status, None

    async def _curl_subdomain_http(self, subdomain: str) -> tuple[str, int, str | None]:
        """Fallback: try HTTP instead of HTTPS."""
        url = f"http://{subdomain}"
        args = [
            "curl", "-s", "--max-time", "10",
            "-w", "\n%{http_code}",
            "-L",
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
            return "", 0, "timeout"
        except Exception as exc:
            return "", 0, str(exc)

        lines = raw.rsplit("\n", 1)
        if len(lines) == 2:
            body = lines[0]
            try:
                status = int(lines[1])
            except ValueError:
                status = 0
        else:
            body = raw
            status = 0
        return body, status, None

    async def run(self, target: str, params: dict[str, Any] | None = None) -> ToolResult:
        params = params or {}
        if not self.is_available():
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary=f"{self.binary} not found in PATH",
                raw_output="", error=f"{self.binary} not installed",
            )

        raw_subs = params.get("subdomains") or target
        subdomains = [s.strip() for s in raw_subs.split(",") if s.strip()]

        if not subdomains:
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary="No subdomains provided",
                raw_output="", error="empty_subdomains",
            )

        start = time.monotonic()
        findings: list[dict] = []
        log_rows = ["SUBDOMAIN | DNS | STATUS | SERVICE | VERDICT"]
        log_rows.append("-" * 80)

        for sub in subdomains:
            has_dns, dns_detail = await self._check_dns(sub)

            if not has_dns:
                log_rows.append(f"{sub:<40} | NXDOMAIN | - | - | dangling_candidate")
                findings.append({
                    "type": "subdomain_takeover",
                    "severity": "high",
                    "subdomain": sub,
                    "service": "NXDOMAIN",
                    "detail": f"Subdomain {sub} has no DNS records (NXDOMAIN) — "
                              "if a CNAME existed previously, takeover may be possible",
                })
                continue

            body, status, error = await self._curl_subdomain(sub)
            if error:
                log_rows.append(f"{sub:<40} | {dns_detail[:15]} | ERR | - | {error}")
                continue

            # Check signatures
            matched_service = None
            matched_sig = None
            for signature, service in _TAKEOVER_SIGNATURES:
                if signature.lower() in body.lower():
                    matched_service = service
                    matched_sig = signature
                    break

            verdict = "safe"
            if matched_service:
                verdict = f"TAKEOVER ({matched_service})"
                findings.append({
                    "type": "subdomain_takeover",
                    "severity": "high",
                    "subdomain": sub,
                    "service": matched_service,
                    "signature": matched_sig,
                    "status_code": status,
                    "detail": f"Subdomain {sub} shows {matched_service} takeover signature: '{matched_sig}'",
                })

            log_rows.append(
                f"{sub:<40} | {dns_detail[:15]:<15} | {status:<6} | "
                f"{matched_service or '-':<15} | {verdict}"
            )

        elapsed = time.monotonic() - start

        if findings:
            services = sorted({f.get("service", "?") for f in findings})
            summary = (
                f"TAKEOVER RISK — {len(findings)} subdomain(s) vulnerable "
                f"({', '.join(services)})"
            )
        else:
            summary = f"No takeover signatures found ({len(subdomains)} subdomain(s) checked)"

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


registry.register(TakeoverProbeTool())
