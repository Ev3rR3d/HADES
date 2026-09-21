"""HADES tool wrapper for nmap — network port scanner with service detection."""

from __future__ import annotations

import re
from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry

_MAX_BYTES = 512_000

_DEFAULT_PORTS = "80,443,8080,8443,8000,3000,5000,9090,9443"


class NmapTool(ToolDefinition):
    name = "nmap"
    binary = "nmap"
    description = "Port scanner with service/version detection — focused on web service ports"
    category = "recon"
    risk = "low"
    timeout = 300
    params = [
        ToolParam("ports", "Comma-separated ports to scan", default=_DEFAULT_PORTS),
        ToolParam(
            "scan_type", "Scan type flag",
            choices=["-sV", "-sC", "-A"], default="-sV",
        ),
        ToolParam("scripts", "NSE scripts to run (e.g. http-headers,http-title,ssl-cert)"),
        ToolParam("top_ports", "Scan top N ports instead of specific list", param_type="int"),
    ]

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        # Strip protocol prefix
        target = re.sub(r"^https?://", "", target).rstrip("/")

        scan_type = params.get("scan_type", "-sV")
        args = [target, scan_type, "--open", "-T4", "--min-rate", "1000"]

        top_ports = params.get("top_ports")
        if top_ports:
            args.extend(["--top-ports", str(top_ports)])
        else:
            ports = params.get("ports", _DEFAULT_PORTS)
            args.extend(["-p", ports])

        scripts = params.get("scripts")
        if scripts:
            args.extend(["--script", scripts])

        args.extend(["-oN", "-"])

        return args

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        findings: list[dict] = []

        # Match lines like: 80/tcp  open  http  Apache httpd 2.4.54
        port_re = re.compile(
            r"^(\d+)/(tcp|udp)\s+(open)\s+(\S+)\s*(.*)?$"
        )

        for line in stdout.splitlines():
            m = port_re.match(line.strip())
            if not m:
                continue
            port, proto, state, service, version = m.groups()
            findings.append({
                "port": int(port),
                "protocol": proto,
                "state": state,
                "service": service,
                "version": (version or "").strip(),
            })

        if findings:
            services = [
                f"{f['port']}/{f['protocol']} {f['service']}"
                + (f" ({f['version']})" if f["version"] else "")
                for f in findings
            ]
            summary = f"nmap: {len(findings)} open port(s)\n" + "\n".join(
                f"  {s}" for s in services
            )
        else:
            summary = "nmap: no open ports found"

        combined = stdout
        if stderr:
            combined += "\n" + stderr

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0,
            summary=summary,
            raw_output=combined.strip()[:_MAX_BYTES],
            findings=findings,
            exit_code=exit_code,
        )


registry.register(NmapTool())
