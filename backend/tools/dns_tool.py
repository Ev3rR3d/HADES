"""DNS enumeration tools — whois and dig."""

from __future__ import annotations

import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry


# ── Whois ──────────────────────────────────────────────────────────────────

# Multiple patterns per field to handle ICANN, BR (.br), and other TLD formats
_WHOIS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("registrar", re.compile(r"^\s*Registrar:\s*(.+)", re.MULTILINE | re.IGNORECASE)),
    ("creation_date", re.compile(r"^\s*(?:Creat(?:ion|ed)\s*Date|created):\s*(.+)", re.MULTILINE | re.IGNORECASE)),
    ("expiry_date", re.compile(r"^\s*(?:(?:Registry\s*)?Expir(?:y|ation)\s*Date|expires):\s*(.+)", re.MULTILINE | re.IGNORECASE)),
    ("name_servers", re.compile(r"^\s*(?:Name\s*Server|nserver):\s*(.+)", re.MULTILINE | re.IGNORECASE)),
    ("registrant_org", re.compile(r"^\s*(?:Registrant\s*Organi[sz]ation|owner|org):\s*(.+)", re.MULTILINE | re.IGNORECASE)),
    ("registrant_country", re.compile(r"^\s*(?:Registrant\s*Country|country):\s*(.+)", re.MULTILINE | re.IGNORECASE)),
    ("status", re.compile(r"^\s*(?:Domain\s*Status|status):\s*(.+)", re.MULTILINE | re.IGNORECASE)),
    ("updated_date", re.compile(r"^\s*(?:Updated?\s*Date|changed):\s*(.+)", re.MULTILINE | re.IGNORECASE)),
]


class WhoisTool(ToolDefinition):
    name = "whois"
    binary = "whois"
    description = "WHOIS lookup — registrar, dates, nameservers, registrant info"
    category = "recon"
    risk = "low"
    timeout = 30
    params = []

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        return [domain]

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        info: dict[str, Any] = {}
        name_servers: list[str] = []
        statuses: list[str] = []

        for field_name, pattern in _WHOIS_PATTERNS:
            for m in pattern.finditer(stdout):
                val = m.group(1).strip()
                if not val:
                    continue
                if field_name == "name_servers":
                    ns = val.split()[0].lower().rstrip(".")
                    if ns and ns not in name_servers:
                        name_servers.append(ns)
                elif field_name == "status":
                    statuses.append(val)
                elif field_name not in info:
                    info[field_name] = val

        if name_servers:
            info["name_servers"] = name_servers
        if statuses:
            info["status"] = statuses

        parts = []
        if info.get("registrar"):
            parts.append(f"Registrar: {info['registrar']}")
        if info.get("registrant_org"):
            parts.append(f"Org: {info['registrant_org']}")
        if name_servers:
            parts.append(f"NS: {', '.join(name_servers[:4])}")
        if info.get("creation_date"):
            parts.append(f"Created: {info['creation_date']}")
        if info.get("expiry_date"):
            parts.append(f"Expires: {info['expiry_date']}")

        summary = " | ".join(parts) if parts else "No WHOIS data found"

        findings = [info] if info else []

        combined = stdout
        if stderr and exit_code != 0:
            combined += "\n" + stderr

        return ToolResult(
            tool=self.name,
            target=target,
            success=bool(info),
            summary=summary,
            raw_output=combined[:512_000],
            findings=findings,
            exit_code=exit_code,
        )


# ── Dig ────────────────────────────────────────────────────────────────────

_DIG_ANSWER_RE = re.compile(
    r"^(\S+)\.\s+\d+\s+IN\s+(\S+)\s+(.+)$",
    re.MULTILINE,
)


class DigTool(ToolDefinition):
    name = "dig"
    binary = "dig"
    description = "DNS record lookup — A, AAAA, MX, NS, TXT, CNAME, SOA"
    category = "recon"
    risk = "low"
    timeout = 30
    params = [
        ToolParam(
            name="record_type",
            description="DNS record type to query",
            choices=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"],
            default="A",
        ),
        ToolParam(
            name="server",
            description="DNS server to query (e.g. 8.8.8.8)",
            default="8.8.8.8",
        ),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        rtype = params.get("record_type", "A")
        server = params.get("server", "8.8.8.8")
        return [f"@{server}", domain, rtype, "+noall", "+answer", "+authority"]

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []

        for m in _DIG_ANSWER_RE.finditer(stdout):
            name, rtype, value = m.group(1), m.group(2), m.group(3).strip().rstrip(".")
            findings.append({
                "name": name,
                "type": rtype,
                "value": value,
            })

        if findings:
            types_found = sorted({f["type"] for f in findings})
            summary = f"{len(findings)} DNS record(s): {', '.join(types_found)}"
            for f in findings[:8]:
                summary += f"\n  {f['type']} {f['value']}"
        else:
            summary = "No DNS records found"

        combined = stdout
        if stderr:
            combined += "\n" + stderr

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0 or bool(findings),
            summary=summary,
            raw_output=combined[:512_000],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(WhoisTool())
registry.register(DigTool())
