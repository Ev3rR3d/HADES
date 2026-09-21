"""Generic command executor — gives Claude full access to any Kali tool."""

from __future__ import annotations

from typing import Any

from tools.base import ToolDefinition, ToolParam, ToolResult, registry


class ExecTool(ToolDefinition):
    name = "exec"
    binary = "bash"
    description = (
        "Run ANY shell command. Use for Kali tools without a dedicated wrapper: "
        "wfuzz, commix, paramspider, arjun, dalfox, xsstrike, dirb, wpscan, "
        "jq, grep, awk, base64, openssl, or any custom curl/wget pipeline. "
        "Full bash syntax supported including pipes and redirects. "
        "IMPORTANT: destructive operations (DELETE, mutations, cleanup) require operator approval."
    )
    category = "exploitation"
    risk = "medium"
    timeout = 120
    params = [
        ToolParam("command", "The full shell command to execute", required=True),
    ]

    def is_available(self) -> bool:
        return True

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        command = params.get("command", "")
        return ["-c", command]

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        combined = stdout
        if stderr:
            combined += "\n" + stderr

        lines = [l for l in combined.strip().splitlines() if l.strip()]
        if len(lines) <= 10:
            summary = "\n".join(lines) if lines else f"No output (exit {exit_code})"
        else:
            summary = "\n".join(lines[:5] + [f"  ... ({len(lines) - 10} more lines)"] + lines[-5:])

        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0,
            summary=summary,
            raw_output=combined[:500_000],
            findings=[],
            exit_code=exit_code,
        )


registry.register(ExecTool())
