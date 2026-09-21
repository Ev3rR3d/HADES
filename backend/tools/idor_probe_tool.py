"""IDOR Probe — test endpoints for Insecure Direct Object Reference vulnerabilities."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

logger = logging.getLogger("hades.tools")

_REQ_TIMEOUT = 10
_MAX_IDS = 10
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class IdorProbeTool(ToolDefinition):
    name = "idor_probe"
    binary = "curl"
    description = "Test endpoints for IDOR by requesting sequential/modified IDs and comparing responses"
    category = "exploitation"
    risk = "medium"
    timeout = 60
    params = [
        ToolParam("url", "URL with ID parameter to test (e.g. https://target/api/users/1)", required=True),
        ToolParam("id_param", "Name of the ID parameter if in query string (e.g. 'id', 'user_id'). Leave empty if ID is in URL path"),
        ToolParam("headers", "Extra headers as 'Key: Value', comma-separated (e.g. 'Authorization: Bearer xxx')"),
        ToolParam("method", "HTTP method", default="GET", choices=["GET", "POST", "PUT"]),
        ToolParam("test_ids", "Comma-separated IDs to test (default: auto-generate from detected ID)", default=""),
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
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        id_param = params.get("id_param", "")
        method = params.get("method", "GET")
        headers_raw = params.get("headers", "")
        test_ids_raw = params.get("test_ids", "")

        # --- Detect original ID and build URL template ---
        original_id, id_type, url_builder = self._detect_id(url, id_param)
        if original_id is None:
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary="Could not detect an ID in the URL. Provide id_param or use a URL with a numeric/UUID segment.",
                raw_output="", error="No ID detected",
            )

        # --- Generate test IDs ---
        test_ids = self._generate_ids(original_id, id_type, test_ids_raw)

        # --- Make requests sequentially ---
        header_args = self._parse_headers(headers_raw)
        results: list[dict[str, Any]] = []
        start = time.monotonic()

        for tid in test_ids:
            test_url = url_builder(tid)
            status, size, body_hash, error = await self._curl_request(
                test_url, method, header_args,
            )
            results.append({
                "id": tid,
                "status": status,
                "size": size,
                "hash": body_hash,
                "error": error,
            })

        elapsed = time.monotonic() - start

        # --- Analyze ---
        findings, summary = self._analyze(results, original_id, url)

        # --- Raw output table ---
        lines = [f"{'ID':<40} {'Status':<8} {'Size':<10} {'BodyHash':<16}"]
        lines.append("-" * 76)
        for r in results:
            if r["error"]:
                lines.append(f"{str(r['id']):<40} {'ERR':<8} {'-':<10} {r['error']}")
            else:
                lines.append(f"{str(r['id']):<40} {r['status']:<8} {r['size']:<10} {r['hash'][:14]}")
        raw_output = "\n".join(lines)

        return ToolResult(
            tool=self.name,
            target=target,
            success=True,
            summary=summary,
            raw_output=raw_output,
            findings=findings,
            duration=elapsed,
            exit_code=0,
        )

    # ------------------------------------------------------------------
    # ID detection
    # ------------------------------------------------------------------

    def _detect_id(self, url: str, id_param: str):
        """Return (original_id, id_type, url_builder_fn) or (None, None, None)."""
        parsed = urlparse(url)

        # Query-string parameter mode
        if id_param:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            values = qs.get(id_param)
            if not values:
                return None, None, None
            original = values[0]
            id_type = "uuid" if _UUID_RE.fullmatch(original) else "numeric"

            def builder(new_id):
                new_qs = dict(parse_qs(parsed.query, keep_blank_values=True))
                new_qs[id_param] = [str(new_id)]
                flat = {k: v[0] for k, v in new_qs.items()}
                return urlunparse(parsed._replace(query=urlencode(flat)))

            return original, id_type, builder

        # Path-segment mode: find last numeric or UUID segment
        segments = parsed.path.rstrip("/").split("/")
        for i in range(len(segments) - 1, -1, -1):
            seg = segments[i]
            if _UUID_RE.fullmatch(seg):
                original = seg

                def builder(new_id, _i=i, _segs=list(segments), _p=parsed):
                    s = list(_segs)
                    s[_i] = str(new_id)
                    return urlunparse(_p._replace(path="/".join(s)))

                return original, "uuid", builder

            if seg.isdigit():
                original = seg

                def builder(new_id, _i=i, _segs=list(segments), _p=parsed):
                    s = list(_segs)
                    s[_i] = str(new_id)
                    return urlunparse(_p._replace(path="/".join(s)))

                return original, "numeric", builder

        return None, None, None

    # ------------------------------------------------------------------
    # ID generation
    # ------------------------------------------------------------------

    def _generate_ids(self, original: str, id_type: str, test_ids_raw: str) -> list[str]:
        if test_ids_raw:
            ids = [t.strip() for t in test_ids_raw.split(",") if t.strip()]
            return ids[:_MAX_IDS]

        ids: list[str] = [original]

        if id_type == "numeric":
            n = int(original)
            candidates = [n - 1, n + 1, 0, 1, 999999]
            for c in candidates:
                s = str(c)
                if s not in ids:
                    ids.append(s)
        else:
            # UUID variants
            zeroed = "00000000-0000-0000-0000-000000000000"
            # Flip last hex digit
            modified = original[:-1] + ("a" if original[-1] != "a" else "b")
            for c in [zeroed, modified]:
                if c not in ids:
                    ids.append(c)

        return ids[:_MAX_IDS]

    # ------------------------------------------------------------------
    # Header parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_headers(headers_raw: str) -> list[str]:
        args: list[str] = []
        if not headers_raw:
            return args
        for h in headers_raw.split(","):
            h = h.strip()
            if h and ":" in h:
                args.extend(["-H", h])
        return args

    # ------------------------------------------------------------------
    # Single curl request
    # ------------------------------------------------------------------

    async def _curl_request(
        self, url: str, method: str, header_args: list[str],
    ) -> tuple[int, int, str, str]:
        """Return (status_code, size, body_sha256_hex, error_string)."""
        cmd = [
            "curl", "-sk", "-o", "-",
            "-w", "\n%{http_code}\n%{size_download}",
            "-X", method,
            "--max-time", str(_REQ_TIMEOUT),
        ] + header_args + [url]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
            stdout_raw, _ = await asyncio.wait_for(
                proc.communicate(), timeout=_REQ_TIMEOUT + 5,
            )
        except asyncio.TimeoutError:
            return 0, 0, "", "timeout"
        except Exception as exc:
            return 0, 0, "", str(exc)

        output = stdout_raw.decode("utf-8", errors="replace")
        lines = output.rsplit("\n", 2)
        if len(lines) < 3:
            return 0, 0, "", "unexpected curl output"

        body = "\n".join(lines[:-2])
        try:
            status = int(lines[-2])
        except ValueError:
            status = 0
        try:
            size = int(lines[-1])
        except ValueError:
            size = len(body)

        body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
        return status, size, body_hash, ""

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    @staticmethod
    def _analyze(
        results: list[dict[str, Any]], original_id: str, url: str,
    ) -> tuple[list[dict], str]:
        findings: list[dict] = []
        successful = [r for r in results if not r["error"]]

        if not successful:
            return findings, "All requests failed — target may be unreachable"

        # Group by status code
        statuses = {r["status"] for r in successful}
        ok_results = [r for r in successful if r["status"] == 200]
        denied_results = [r for r in successful if r["status"] in (401, 403)]

        # All denied = access control working
        if len(denied_results) == len(successful):
            return findings, "All IDs returned 401/403 — access control appears enforced"

        # Check if all 200 responses have the same body hash
        if ok_results:
            hashes = {r["hash"] for r in ok_results}

            if len(hashes) == 1 and len(ok_results) > 1:
                return findings, (
                    f"All {len(ok_results)} IDs returned 200 with identical content — "
                    "likely a template page, not IDOR"
                )

            if len(hashes) > 1:
                # Different content for different IDs = potential IDOR
                # Check if non-original IDs (especially unexpected ones) got 200
                other_ok = [r for r in ok_results if str(r["id"]) != str(original_id)]
                if other_ok:
                    evidence = []
                    for r in ok_results:
                        evidence.append(
                            f"ID={r['id']}: status={r['status']}, size={r['size']}, hash={r['hash'][:14]}"
                        )
                    findings.append({
                        "type": "IDOR",
                        "severity": "high",
                        "url": url,
                        "detail": (
                            f"Different IDs return different content with HTTP 200. "
                            f"{len(other_ok)} non-original ID(s) returned accessible data."
                        ),
                        "evidence": evidence,
                    })
                    return findings, (
                        f"POTENTIAL IDOR — {len(other_ok)} other ID(s) returned 200 with "
                        "different content. Verify if data belongs to other users."
                    )

        # Edge case: ID=0 or random ID returns 200
        weird_ok = [
            r for r in ok_results
            if str(r["id"]) in ("0", "999999")
        ]
        if weird_ok:
            findings.append({
                "type": "IDOR",
                "severity": "medium",
                "url": url,
                "detail": (
                    f"Unexpected IDs ({', '.join(str(r['id']) for r in weird_ok)}) "
                    "returned HTTP 200 — possible broken access control."
                ),
            })
            return findings, (
                f"SUSPICIOUS — unexpected ID(s) returned 200. Possible broken access control."
            )

        # Mixed results but no clear IDOR
        status_summary = ", ".join(f"{s}: {sum(1 for r in successful if r['status'] == s)}" for s in sorted(statuses))
        return findings, f"Mixed responses ({status_summary}) — manual review recommended"


registry.register(IdorProbeTool())
