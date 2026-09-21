"""HADES built-in tool — fetch and analyze JavaScript files for secrets, API keys, endpoints, and sensitive patterns."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

logger = logging.getLogger("hades.tools")

_MAX_BYTES = 512_000
_MAX_URLS = 10
_MAX_FINDINGS = 200

# --- Secret patterns ---

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("Slack Token", re.compile(r"xox[bporas]-[0-9a-zA-Z-]+")),
    ("GitHub Token", re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")),
    ("Supabase URL", re.compile(r"https?://[a-z0-9]+\.supabase\.co")),
    ("Firebase URL", re.compile(r"https?://[a-z0-9-]+\.firebaseio\.com")),
    ("API Key Assignment", re.compile(
        r"""(?:api[_-]?key|apikey|api_secret)['"\s:=]+['"]?([A-Za-z0-9_\-]{16,})""", re.I
    )),
    ("Token/Secret Assignment", re.compile(
        r"""(?:token|bearer|auth[_-]?token|secret|password|passwd|pwd)['"\s:=]+['"]?([A-Za-z0-9_\-./]{8,})""", re.I
    )),
    ("High-Entropy String", re.compile(r"""['"]([A-Za-z0-9+/=_-]{32,})['"]""")),
]

# Filter out common webpack/build hashes that trigger high-entropy false positives.
_FALSE_POSITIVE_RE = re.compile(
    r"^(?:use strict|function|return|module|exports|undefined|application/json|text/html|[0-9a-f]{32,64})$", re.I
)

# --- Endpoint patterns ---

_API_ROUTE_RE = re.compile(r"""['"](/api/[^'")\s]{1,200})""")
_FULL_URL_RE = re.compile(r"""https?://[^\s'"<>()]{4,300}""")
_INTERESTING_PATH_RE = re.compile(
    r"""['"](/[^'")\s]{0,200}(?:admin|auth|login|user|account|config|setting|upload|graphql|webhook|internal|private|secret|debug|backup)[^'")\s]{0,100})""",
    re.I,
)

# --- Interesting code patterns ---

_CODE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Source Map", re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")),
    ("eval() usage", re.compile(r"\beval\s*\(")),
    ("innerHTML assignment", re.compile(r"\.innerHTML\s*=")),
    ("postMessage", re.compile(r"\.postMessage\s*\(")),
    ("message listener", re.compile(r"""addEventListener\s*\(\s*['"]message['"]""")),
    ("localStorage sensitive", re.compile(
        r"""localStorage\.(?:get|set)Item\s*\(\s*['"](?:token|key|secret|auth|session|password|jwt|api)""", re.I
    )),
    ("sessionStorage sensitive", re.compile(
        r"""sessionStorage\.(?:get|set)Item\s*\(\s*['"](?:token|key|secret|auth|session|password|jwt|api)""", re.I
    )),
]


def _get_context(content: str, match: re.Match, chars: int = 50) -> str:
    start = max(0, match.start() - chars)
    end = min(len(content), match.end() + chars)
    ctx = content[start:end].replace("\n", " ").replace("\r", "")
    return ctx


def _analyze_js(content: str, source_url: str) -> list[dict]:
    findings: list[dict] = []
    seen_values: set[str] = set()

    # Secrets
    for label, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(content):
            value = m.group(0)[:100]
            # Use last captured group if it exists, else full match
            captured = m.group(m.lastindex) if m.lastindex else m.group(0)
            captured = captured[:100]

            if captured in seen_values:
                continue
            if _FALSE_POSITIVE_RE.match(captured):
                continue
            seen_values.add(captured)

            findings.append({
                "type": "secret",
                "pattern": label,
                "value": captured,
                "source_url": source_url,
                "context": _get_context(content, m),
            })

    # API routes
    for m in _API_ROUTE_RE.finditer(content):
        route = m.group(1)
        if route not in seen_values:
            seen_values.add(route)
            findings.append({"type": "endpoint", "url": route, "source_url": source_url})

    # Full URLs (deduplicate and skip common CDN/static noise)
    for m in _FULL_URL_RE.finditer(content):
        url = m.group(0).rstrip("',\";)")
        if url in seen_values:
            continue
        lower = url.lower()
        if any(skip in lower for skip in (
            "googleapis.com/ajax", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
            "unpkg.com", "fonts.googleapis.com", "w3.org",
        )):
            continue
        seen_values.add(url)
        findings.append({"type": "endpoint", "url": url, "source_url": source_url})

    # Interesting relative paths
    for m in _INTERESTING_PATH_RE.finditer(content):
        path = m.group(1)
        if path not in seen_values and len(path) < 200:
            seen_values.add(path)
            findings.append({"type": "endpoint", "url": path, "source_url": source_url, "interesting": True})

    # Code patterns
    for label, pattern in _CODE_PATTERNS:
        matches = pattern.findall(content)
        if matches:
            ftype = "source_map" if label == "Source Map" else "code_pattern"
            finding: dict[str, Any] = {
                "type": ftype,
                "pattern": label,
                "count": len(matches),
                "source_url": source_url,
            }
            if ftype == "source_map":
                finding["value"] = matches[0] if isinstance(matches[0], str) else matches[0]
            findings.append(finding)

    return findings


async def _fetch_url(url: str, timeout: int = 15) -> tuple[str, str]:
    """Fetch a URL with curl, return (url, content). Returns empty content on failure."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sk", "--max-time", str(timeout), "--compressed", url,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
        stdout_raw, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        return url, stdout_raw.decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("js_analyze: failed to fetch %s: %s", url, exc)
        return url, ""


class JsAnalyzeTool(ToolDefinition):
    name = "js_analyze"
    binary = "curl"
    description = "Fetch and analyze JavaScript files for secrets, API keys, endpoints, and sensitive patterns"
    category = "enumeration"
    risk = "low"
    timeout = 60
    params = [
        ToolParam("urls", "Comma-separated JS file URLs to analyze", required=True),
    ]

    async def run(self, target: str, params: dict[str, Any] | None = None) -> ToolResult:
        params = params or {}
        start = time.monotonic()

        if not self.is_available():
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary=f"{self.binary} not found in PATH",
                raw_output="", error=f"{self.binary} not installed",
            )

        raw_urls = params.get("urls", target)
        if isinstance(raw_urls, list):
            urls = [u.strip() for u in raw_urls if isinstance(u, str) and u.strip()]
        else:
            urls = [u.strip() for u in str(raw_urls).split(",") if u.strip()]
        if not urls:
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary="No URLs provided", raw_output="", error="No URLs",
            )

        urls = urls[:_MAX_URLS]

        # Normalize URLs
        for i, url in enumerate(urls):
            if not url.startswith(("http://", "https://")):
                urls[i] = f"https://{url}"

        # Fetch all in parallel
        logger.info("js_analyze: fetching %d JS files", len(urls))
        results = await asyncio.gather(*[_fetch_url(u) for u in urls])

        all_findings: list[dict] = []
        raw_parts: list[str] = []
        per_file_stats: list[str] = []
        total_secrets = 0
        total_endpoints = 0
        total_source_maps = 0
        total_code_patterns = 0

        for url, content in results:
            if not content:
                per_file_stats.append(f"  {url}: FETCH FAILED")
                continue

            findings = _analyze_js(content, url)
            all_findings.extend(findings)

            secrets = [f for f in findings if f["type"] == "secret"]
            endpoints = [f for f in findings if f["type"] == "endpoint"]
            source_maps = [f for f in findings if f["type"] == "source_map"]
            code_pats = [f for f in findings if f["type"] == "code_pattern"]

            total_secrets += len(secrets)
            total_endpoints += len(endpoints)
            total_source_maps += len(source_maps)
            total_code_patterns += len(code_pats)

            stat = f"  {url}: {len(secrets)} secrets, {len(endpoints)} endpoints"
            if source_maps:
                stat += f", {len(source_maps)} source maps"
            if code_pats:
                stat += f", {len(code_pats)} code patterns"
            per_file_stats.append(stat)

            raw_parts.append(f"=== {url} ({len(content)} bytes) ===")
            for f in findings:
                if f["type"] == "secret":
                    raw_parts.append(f"  [SECRET] {f['pattern']}: {f['value']}")
                    raw_parts.append(f"    Context: {f.get('context', '')}")
                elif f["type"] == "endpoint":
                    tag = " *" if f.get("interesting") else ""
                    raw_parts.append(f"  [ENDPOINT{tag}] {f['url']}")
                elif f["type"] == "source_map":
                    raw_parts.append(f"  [SOURCE_MAP] {f.get('value', '')}")
                elif f["type"] == "code_pattern":
                    raw_parts.append(f"  [CODE] {f['pattern']} ({f['count']}x)")

        # Deduplicate findings
        seen: set[str] = set()
        deduped: list[dict] = []
        for f in all_findings:
            key = f"{f['type']}:{f.get('value', f.get('url', f.get('pattern', '')))}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        deduped = deduped[:_MAX_FINDINGS]

        elapsed = time.monotonic() - start

        # Build summary
        parts = [f"js_analyze: analyzed {len(urls)} JS files in {elapsed:.1f}s"]
        parts.append(f"  Secrets: {total_secrets} | Endpoints: {total_endpoints} | Source maps: {total_source_maps} | Code patterns: {total_code_patterns}")
        parts.append("")
        parts.append("Per-file breakdown:")
        parts.extend(per_file_stats)

        # Highlight secrets at the top
        secrets_found = [f for f in deduped if f["type"] == "secret"]
        if secrets_found:
            parts.append(f"\nSecrets found ({len(secrets_found)}):")
            for f in secrets_found[:20]:
                parts.append(f"  [{f['pattern']}] {f['value']}")
                if f.get("context"):
                    parts.append(f"    ...{f['context']}...")

        # Interesting endpoints
        interesting = [f for f in deduped if f.get("interesting")]
        if interesting:
            parts.append(f"\nInteresting paths ({len(interesting)}):")
            for f in interesting[:15]:
                parts.append(f"  {f['url']}  (from {f['source_url']})")

        # Source maps
        smaps = [f for f in deduped if f["type"] == "source_map"]
        if smaps:
            parts.append(f"\nSource maps ({len(smaps)}):")
            for f in smaps:
                parts.append(f"  {f.get('value', '')}  (from {f['source_url']})")

        summary = "\n".join(parts)
        raw_output = "\n".join(raw_parts)

        logger.info(
            "js_analyze finished in %.1fs (%d findings across %d files)",
            elapsed, len(deduped), len(urls),
        )

        return ToolResult(
            tool=self.name,
            target=target,
            success=True,
            summary=summary,
            raw_output=raw_output[:_MAX_BYTES],
            findings=deduped,
            duration=elapsed,
            exit_code=0,
        )


registry.register(JsAnalyzeTool())
