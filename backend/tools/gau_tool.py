"""HADES tool wrapper for gau (GetAllUrls) — fetches known URLs from Wayback Machine, Common Crawl, OTX, URLScan."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000
_MAX_FINDINGS = 100

_CATEGORY_PATTERNS: dict[str, list[str]] = {
    "API": ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"],
    "Admin/Config": ["/admin", "/config", "/settings", "/dashboard", "/manage", "/wp-admin"],
    "Auth": ["/login", "/auth", "/oauth", "/signup", "/register", "/token"],
    "Files": [".js", ".json", ".xml", ".yaml", ".env", ".bak", ".sql", ".log"],
}

# Priority order for capping findings — interesting categories first.
_PRIORITY = ["API", "Admin/Config", "Auth", "Files", "Other"]


class GauTool(ToolDefinition):
    name = "gau"
    binary = "gau"
    description = (
        "Fetch known URLs for a domain from Wayback Machine, Common Crawl, OTX, "
        "and URLScan — discovers hidden endpoints, old admin panels, API routes"
    )
    category = "recon"
    risk = "low"
    timeout = 120
    params = [
        ToolParam(
            "providers",
            "Comma-separated URL sources",
            default="wayback,commoncrawl,otx,urlscan",
        ),
        ToolParam(
            "blacklist",
            "Comma-separated extensions to exclude",
            default="css,png,jpg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3,pdf",
        ),
        ToolParam(
            "threads",
            "Number of threads",
            param_type="int",
            default=5,
        ),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        providers = params.get("providers", "wayback,commoncrawl,otx,urlscan")
        blacklist = params.get("blacklist", "css,png,jpg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3,pdf")
        threads = str(params.get("threads", 5))

        return [
            "--providers", providers,
            "--blacklist", blacklist,
            "--threads", threads,
            "--subs",
            domain,
        ]

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        seen: set[str] = set()
        categorized: dict[str, list[str]] = {cat: [] for cat in _PRIORITY}

        for line in stdout.strip().splitlines():
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)

            cat = self._categorize(url)
            categorized[cat].append(url)

        total = len(seen)

        # Build capped findings list, prioritizing interesting categories.
        findings: list[dict] = []
        remaining = _MAX_FINDINGS
        for cat in _PRIORITY:
            urls = categorized[cat]
            if not urls:
                continue
            take = min(len(urls), remaining)
            for u in urls[:take]:
                findings.append({"url": u, "category": cat})
            remaining -= take
            if remaining <= 0:
                break

        # Summary.
        counts = {cat: len(urls) for cat, urls in categorized.items() if urls}
        parts = [f"gau: {total} unique URLs discovered"]
        for cat in _PRIORITY:
            if cat in counts:
                parts.append(f"  {cat}: {counts[cat]}")

        # Show top interesting URLs in summary.
        for cat in _PRIORITY[:-1]:  # Skip "Other" in highlights.
            urls = categorized[cat]
            if urls:
                parts.append(f"\n{cat} ({len(urls)}):")
                for u in urls[:10]:
                    parts.append(f"  {u}")
                if len(urls) > 10:
                    parts.append(f"  ... +{len(urls) - 10} more")

        summary = "\n".join(parts) if total else f"gau: no URLs discovered (exit {exit_code})"

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0 and total > 0,
            summary=summary,
            raw_output=stdout[:_MAX_BYTES],
            findings=findings,
            exit_code=exit_code,
        )

    @staticmethod
    def _categorize(url: str) -> str:
        lower = url.lower()
        for cat, patterns in _CATEGORY_PATTERNS.items():
            if any(p in lower for p in patterns):
                return cat
        return "Other"


registry.register(GauTool())
