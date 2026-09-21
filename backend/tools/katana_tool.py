"""HADES tool wrapper for katana — web crawler / spider by ProjectDiscovery."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000

_INTERESTING_PATTERNS = {
    "admin": "Admin panel",
    "login": "Login page",
    "dashboard": "Dashboard",
    "api/": "API endpoint",
    "/api": "API endpoint",
    "graphql": "GraphQL endpoint",
    "upload": "File upload",
    "config": "Configuration file",
    "backup": "Backup file",
    ".env": "Environment file",
    "debug": "Debug endpoint",
    "swagger": "API documentation",
    "openapi": "API documentation",
    "token": "Token endpoint",
    "auth": "Auth endpoint",
    "register": "Registration page",
    "reset": "Password reset",
    "websocket": "WebSocket endpoint",
    "ws://": "WebSocket endpoint",
    "wss://": "WebSocket endpoint",
}

_STATIC_EXTENSIONS = frozenset({
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
})


class KatanaTool(ToolDefinition):
    name = "katana"
    binary = "katana"
    description = "Web crawler/spider — discovers endpoints, JS files, API routes, forms, and links from a target website"
    category = "recon"
    risk = "low"
    timeout = 240
    params = [
        ToolParam("depth", "Maximum crawl depth", param_type="int", default=3),
        ToolParam("js_crawl", "Enable headless JS rendering crawl", param_type="bool", default=True),
        ToolParam("scope", "Regex to limit crawl scope (e.g. .*\\.target\\.com)"),
        ToolParam("extensions", "Comma-separated extensions to filter by (e.g. php,js,html)"),
        ToolParam("output_format", "Output format", default="json", choices=["url", "json"]),
        ToolParam("concurrency", "Number of concurrent requests", param_type="int", default=10),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        url = target
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        depth = str(params.get("depth", 3))

        concurrency = str(params.get("concurrency", 10))

        args = [
            "-u", url,
            "-d", depth,
            "-silent",
            "-nc",
            "-kf", "all",
            "-ef", "css,png,jpg,gif,svg,ico,woff,woff2,ttf,eot",
            "-c", concurrency,
            "-or",
            "-ob",
        ]

        if params.get("js_crawl", True):
            args.append("-jc")

        if params.get("output_format", "json") == "json":
            args.append("-jsonl")

        scope = params.get("scope")
        if scope:
            args.extend(["-cs", scope])

        extensions = params.get("extensions")
        if extensions:
            args.extend(["-em", extensions])

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []
        seen_urls: set[str] = set()
        categories: dict[str, int] = {}

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            url = ""
            endpoint: dict[str, Any] = {}

            try:
                data = json.loads(line)
                url = data.get("request", {}).get("endpoint", "") or data.get("url", "")
                resp_headers = data.get("response", {}).get("headers", {})
                content_type = (
                    resp_headers.get("Content-Type")
                    or resp_headers.get("content-type")
                    or resp_headers.get("content_type", "")
                )
                endpoint = {
                    "url": url,
                    "method": data.get("request", {}).get("method", "GET"),
                    "status_code": data.get("response", {}).get("status_code", 0),
                    "content_type": content_type,
                    "source": data.get("request", {}).get("source", ""),
                }
            except json.JSONDecodeError:
                url = line
                endpoint = {"url": url, "method": "GET"}

            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            parsed = urlparse(url)
            path_lower = parsed.path.lower()

            if any(path_lower.endswith(ext) for ext in _STATIC_EXTENSIONS):
                continue

            cat = self._categorize(url, path_lower)
            endpoint["category"] = cat
            categories[cat] = categories.get(cat, 0) + 1

            for pattern, label in _INTERESTING_PATTERNS.items():
                if pattern in url.lower():
                    endpoint["interesting"] = label
                    break

            findings.append(endpoint)

        interesting = [f for f in findings if "interesting" in f]
        js_files = [f for f in findings if f.get("category") == "JavaScript"]

        parts = [f"katana: {len(findings)} unique endpoints discovered"]
        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            parts.append(f"  {cat}: {count}")
        if interesting:
            parts.append(f"\nInteresting finds ({len(interesting)}):")
            for f in interesting[:15]:
                parts.append(f"  [{f['interesting']}] {f['url']}")
        if js_files:
            parts.append(f"\nJS files: {len(js_files)}")
            for f in js_files[:10]:
                parts.append(f"  {f['url']}")

        summary = "\n".join(parts) if findings else f"katana: no endpoints discovered (exit {exit_code})"

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0 and len(findings) > 0,
            summary=summary,
            raw_output=stdout[:_MAX_BYTES],
            findings=findings,
            exit_code=exit_code,
        )

    @staticmethod
    def _categorize(url: str, path_lower: str) -> str:
        if path_lower.endswith(".js"):
            return "JavaScript"
        if path_lower.endswith((".json", ".xml", ".yaml", ".yml")):
            return "Data file"
        if "/api/" in path_lower or "/api" == path_lower or path_lower.startswith("/v1/") or path_lower.startswith("/v2/"):
            return "API endpoint"
        if "graphql" in path_lower:
            return "GraphQL"
        if any(x in path_lower for x in ("/login", "/signin", "/auth", "/register", "/signup")):
            return "Auth page"
        if path_lower.endswith((".php", ".asp", ".aspx", ".jsp")):
            return "Dynamic page"
        return "Page"


registry.register(KatanaTool())
