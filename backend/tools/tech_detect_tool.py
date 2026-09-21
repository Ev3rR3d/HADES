"""Tech Detect — fingerprint web technologies from HTTP responses."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

logger = logging.getLogger("hades.tools.tech_detect")

_MAX_OUTPUT = 512_000

_HEADER_SIGS = {
    "x-powered-by": lambda v: v,
    "server": lambda v: v,
    "x-generator": lambda v: v,
    "x-drupal-cache": lambda _: "Drupal",
    "x-varnish": lambda _: "Varnish",
    "x-aspnet-version": lambda v: f".NET {v}",
    "x-aspnetmvc-version": lambda v: f"ASP.NET MVC {v}",
}

_COOKIE_SIGS = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": ".NET",
    "csrftoken": "Django",
    "_rails_session": "Ruby on Rails",
    "laravel_session": "Laravel",
    "connect.sid": "Node.js/Express",
    "ci_session": "CodeIgniter",
    "CFID": "ColdFusion",
    "CFTOKEN": "ColdFusion",
}

_HTML_PATTERNS = [
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', "Generator"),
    (r'<div\s+id=["\']__next["\']', "Next.js"),
    (r'__NEXT_DATA__', "Next.js"),
    (r'__NUXT__', "Nuxt.js"),
    (r'<div\s+id=["\']app["\'][^>]*\s+data-v-', "Vue.js"),
    (r'ng-app=', "AngularJS"),
    (r'<app-root', "Angular"),
    (r'data-reactroot', "React"),
    (r'<div\s+id=["\']root["\']', "React (likely)"),
    (r'wp-content/', "WordPress"),
    (r'wp-includes/', "WordPress"),
    (r'/sites/default/files/', "Drupal"),
    (r'Joomla!', "Joomla"),
    (r'<meta[^>]+content=["\'][^"\']*Shopify', "Shopify"),
    (r'cdn\.shopify\.com', "Shopify"),
    (r'static\.squarespace\.com', "Squarespace"),
    (r'js\.stripe\.com', "Stripe"),
    (r'www\.googletagmanager\.com', "Google Tag Manager"),
    (r'cdn\.jsdelivr\.net', "jsDelivr CDN"),
    (r'cdnjs\.cloudflare\.com', "Cloudflare CDN"),
    (r'ajax\.googleapis\.com', "Google CDN"),
    (r'maxcdn\.bootstrapcdn\.com|cdn.*bootstrap', "Bootstrap"),
    (r'jquery[\.\-][\d.]+\.(?:min\.)?js', "jQuery"),
]


class TechDetectTool(ToolDefinition):
    name = "tech_detect"
    binary = "curl"
    description = (
        "Detect web technologies by analyzing HTTP headers, HTML content, "
        "cookies, and JavaScript signatures in the response"
    )
    category = "recon"
    risk = "low"
    timeout = 20
    params = [
        ToolParam("url", "Target URL to fingerprint", required=True),
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

        # Fetch page with headers
        args = [
            "curl", "-sk", "--max-time", "10",
            "-D", "-", "-o", "-",
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

        # Split headers from body
        for sep in ("\r\n\r\n", "\n\n"):
            if sep in raw:
                headers_block, body = raw.split(sep, 1)
                break
        else:
            headers_block, body = raw, ""

        detected: list[dict] = []
        seen: set[str] = set()

        def add_tech(name: str, source: str, evidence: str = "") -> None:
            key = name.lower()
            if key not in seen:
                seen.add(key)
                detected.append({
                    "technology": name,
                    "source": source,
                    "evidence": evidence[:200],
                })

        # Header analysis
        for line in headers_block.splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key_lower = key.strip().lower()
            val = val.strip()
            if key_lower in _HEADER_SIGS and val:
                tech_name = _HEADER_SIGS[key_lower](val)
                add_tech(tech_name, "header", f"{key.strip()}: {val}")

        # Cookie analysis
        for line in headers_block.splitlines():
            if not line.lower().startswith("set-cookie:"):
                continue
            cookie_str = line.split(":", 1)[1].strip()
            cookie_name = cookie_str.split("=")[0].strip() if "=" in cookie_str else ""
            for sig_name, tech in _COOKIE_SIGS.items():
                if sig_name.lower() == cookie_name.lower():
                    add_tech(tech, "cookie", f"Cookie: {sig_name}")

        # HTML pattern matching
        for pattern, tech in _HTML_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                evidence = match.group(0)[:100]
                # For generator meta tag, use captured group
                if tech == "Generator" and match.lastindex:
                    add_tech(match.group(1), "html_meta", evidence)
                else:
                    add_tech(tech, "html", evidence)

        elapsed = time.monotonic() - start

        # Build output
        findings: list[dict] = []
        log_rows = ["TECHNOLOGY | SOURCE | EVIDENCE"]
        log_rows.append("-" * 70)

        for d in detected:
            log_rows.append(f"{d['technology']:<25} | {d['source']:<10} | {d['evidence'][:40]}")
            findings.append({
                "type": "technology_detected",
                "severity": "info",
                "technology": d["technology"],
                "source": d["source"],
                "evidence": d["evidence"],
                "url": url,
            })

        if detected:
            tech_list = ", ".join(d["technology"] for d in detected[:10])
            extra = f" (+{len(detected) - 10} more)" if len(detected) > 10 else ""
            summary = f"Detected {len(detected)} technolog{'y' if len(detected) == 1 else 'ies'}: {tech_list}{extra}"
        else:
            summary = "No technologies detected"

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


registry.register(TechDetectTool())
