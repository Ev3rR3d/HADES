"""Base classes for the HADES tool registry."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("hades.tools")

_MAX_OUTPUT_BYTES = 512_000
_WORDLIST_DIRS = [
    "/usr/share/wordlists/seclists/Discovery/Web-Content",
    "/usr/share/wordlists/dirb",
    "/usr/share/wordlists",
    "/usr/share/seclists/Discovery/Web-Content",
]


def resolve_wordlist(name: str) -> str:
    """Resolve a bare wordlist name (e.g. 'raft-medium-words') to a full path."""
    if os.path.isfile(name):
        return name
    bare = name if name.endswith(".txt") else name + ".txt"
    for d in _WORDLIST_DIRS:
        candidate = os.path.join(d, bare)
        if os.path.isfile(candidate):
            return candidate
    return name


@dataclass
class ToolParam:
    name: str
    description: str
    param_type: str = "string"
    required: bool = False
    default: Any = None
    choices: list[str] | None = None


@dataclass
class ToolResult:
    tool: str
    target: str
    success: bool
    summary: str
    raw_output: str
    findings: list[dict] = field(default_factory=list)
    duration: float = 0.0
    exit_code: int = -1
    error: str = ""


class ToolDefinition:
    """Base class for all tool integrations. Subclass and implement build_args + parse_output."""

    name: str = ""
    binary: str = ""
    description: str = ""
    category: str = ""  # recon, scanning, enumeration, exploitation
    risk: str = "low"  # low, medium, high
    timeout: int = 120
    params: list[ToolParam] = []

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        raise NotImplementedError

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> ToolResult:
        combined = stdout
        if stderr and exit_code != 0:
            combined += "\n" + stderr
        return ToolResult(
            tool=self.name,
            target=target,
            success=exit_code == 0,
            summary=self._auto_summary(stdout, exit_code),
            raw_output=combined[:_MAX_OUTPUT_BYTES],
            exit_code=exit_code,
        )

    def _auto_summary(self, output: str, exit_code: int) -> str:
        lines = output.strip().splitlines()
        if not lines:
            return f"{self.name}: no output (exit {exit_code})"
        kept = [l for l in lines if l.strip() and not l.startswith("#")]
        if len(kept) <= 10:
            return "\n".join(kept)
        return "\n".join(kept[:5] + [f"  ... ({len(kept) - 10} more lines)"] + kept[-5:])

    def schema_for_claude(self) -> dict:
        params_dict = {
            p.name: {
                "description": p.description,
                "type": p.param_type,
                "required": p.required,
                **({"default": p.default} if p.default is not None else {}),
                **({"choices": p.choices} if p.choices else {}),
            }
            for p in self.params
        }
        if self.name not in ("exec",):
            params_dict["extra_args"] = {
                "description": "Additional raw CLI flags appended to the command (e.g. '--script vuln' for nmap, '-e php,bak' for ffuf)",
                "type": "string",
                "required": False,
            }
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "risk": self.risk,
            "params": params_dict,
        }

    async def run(self, target: str, params: dict[str, Any] | None = None) -> ToolResult:
        params = params or {}
        if not self.is_available():
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary=f"{self.binary} not found in PATH",
                raw_output="", error=f"{self.binary} not installed",
            )

        extra_args = params.pop("extra_args", "") or params.pop("raw_flags", "")
        try:
            args = self.build_args(target, params)
        except ValueError as e:
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary=str(e), raw_output="", error=str(e),
            )
        if extra_args:
            if isinstance(extra_args, list):
                args.extend(str(a) for a in extra_args)
            elif isinstance(extra_args, str):
                import shlex
                args.extend(shlex.split(extra_args))
        cmd = [self.binary] + args

        logger.info("Running: %s %s", self.binary, " ".join(args)[:200])
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )

            try:
                stdout_raw, stderr_raw = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                import os, signal
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()
                elapsed = time.monotonic() - start
                return ToolResult(
                    tool=self.name, target=target, success=False,
                    summary=f"{self.name} timed out after {self.timeout}s",
                    raw_output="", duration=elapsed, exit_code=-1,
                    error=f"Timed out after {self.timeout}s",
                )

            elapsed = time.monotonic() - start
            stdout_str = stdout_raw.decode("utf-8", errors="replace")
            stderr_str = stderr_raw.decode("utf-8", errors="replace")
            exit_code = proc.returncode or 0

            result = self.parse_output(stdout_str, stderr_str, exit_code, target)
            result.duration = elapsed

            logger.info(
                "%s finished in %.1fs (exit=%d, output=%d chars, %d findings)",
                self.name, elapsed, exit_code, len(stdout_str), len(result.findings),
            )
            return result

        except Exception as exc:
            elapsed = time.monotonic() - start
            logger.exception("Tool %s crashed", self.name)
            return ToolResult(
                tool=self.name, target=target, success=False,
                summary=f"{self.name} error: {exc}",
                raw_output="", duration=elapsed,
                error=str(exc),
            )


class CustomCliTool(ToolDefinition):
    """A user-defined CLI tool created from the database."""

    def __init__(self, name: str, binary: str, description: str, category: str,
                 risk: str, timeout: int, args_template: str, display_name: str = ""):
        self.name = name
        self.binary = binary
        self.description = description or f"Custom tool: {display_name or name}"
        self.category = category
        self.risk = risk
        self.timeout = timeout
        self._args_template = args_template
        self.params = [
            ToolParam("extra_flags", "Additional CLI flags to append", required=False),
        ]
        self.is_custom = True

    def is_available(self) -> bool:
        if os.path.isfile(self.binary) and os.access(self.binary, os.X_OK):
            return True
        return shutil.which(self.binary) is not None

    def build_args(self, target: str, params: dict[str, Any]) -> list[str]:
        import shlex
        rendered = self._args_template.replace("{target}", target)
        return shlex.split(rendered)


class ToolRegistry:
    """Global registry of available tools."""

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        self._tools[tool.name] = tool

    def unregister(self, name: str) -> bool:
        return self._tools.pop(name, None) is not None

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def list_tools(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def available_tools(self) -> list[ToolDefinition]:
        return [t for t in self._tools.values() if t.is_available()]

    def catalog_for_claude(self) -> list[dict]:
        catalog = []
        for t in self._tools.values():
            schema = t.schema_for_claude()
            if not t.is_available():
                schema["unavailable"] = True
                schema["description"] += f" [NOT INSTALLED — use exec to run {t.binary} manually]"
            catalog.append(schema)
        return catalog


registry = ToolRegistry()
