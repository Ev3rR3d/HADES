"""Async command executor with streaming, timeouts, and safety checks."""

from __future__ import annotations

import asyncio
import re
import signal
from typing import AsyncIterator, Callable, Coroutine, Optional

from config import settings

# ---------------------------------------------------------------------------
# Safety: commands that should never run
# ---------------------------------------------------------------------------

_BLOCKED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\brm\s+(-\w*r\w*f\w*|-\w*f\w*r\w*)\s+/\s*$"),   # rm -rf /
    re.compile(r"\brm\s+(-\w*r\w*f\w*|-\w*f\w*r\w*)\s+/\s+"),     # rm -rf / (with trailing args)
    re.compile(r"\bmkfs\b"),                                         # filesystem format
    re.compile(r"\bdd\b.*\bof=/dev/[sh]d"),                          # dd to raw disk
    re.compile(r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;?\s*:"),             # fork bomb
    re.compile(r"\b(shutdown|reboot|halt|poweroff)\b"),              # host shutdown
    re.compile(r">\s*/dev/[sh]d"),                                   # write to raw disk
    re.compile(r"\bchmod\s+(-\w+\s+)*777\s+/\s*$"),                 # chmod 777 /
]

_DESTRUCTIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\b(DELETE|DROP|TRUNCATE|ALTER|UPDATE|INSERT)\b', re.IGNORECASE),
    re.compile(r'\b(cleanup|delete|remove|destroy|purge|wipe|reset)_', re.IGNORECASE),
    re.compile(r'"mutation\s*\{?\s*(delete|remove|cleanup|drop|destroy|update|insert|create)', re.IGNORECASE),
    re.compile(r'-X\s*(DELETE|PUT|PATCH|POST)\b.*(/admin|/delete|/remove|/destroy|/drop|/reset|/cleanup)', re.IGNORECASE),
]


_SINGLE_TARGET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\bWHERE\b.*\b(id|ID)\s*=\s*\S+', re.IGNORECASE),
    re.compile(r'\bLIMIT\s+1\b', re.IGNORECASE),
    re.compile(r'-X\s*(DELETE|PUT|PATCH)\b.*/([\w-]+/\d+|[\w-]+/[a-f0-9-]{8,})\b', re.IGNORECASE),
    re.compile(r'/(users|items|posts|accounts|records|resources|orders|products|customers)/\d+', re.IGNORECASE),
    re.compile(r'/(users|items|posts|accounts|records|resources|orders|products|customers)/[a-f0-9-]{8,}', re.IGNORECASE),
]


def check_destructive_scope(command: str) -> tuple[str | None, bool]:
    """Return (warning_message, is_mass_operation) for a command.

    - (None, False) if not destructive
    - (warning, False) if single-target destructive (has WHERE id=X, LIMIT 1, or targets /resource/123)
    - (warning, True) if mass destructive (no WHERE, no specific ID — affects all records)
    """
    matched_pattern = None
    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(command):
            matched_pattern = pattern
            break

    if matched_pattern is None:
        return (None, False)

    warning = f"Destructive operation detected ({matched_pattern.pattern})"

    # Check if it targets a single resource
    for sp in _SINGLE_TARGET_PATTERNS:
        if sp.search(command):
            return (warning, False)

    return (warning, True)


def check_destructive(command: str) -> str | None:
    """Return a warning if the command appears destructive (writes/deletes data)."""
    warning, is_mass = check_destructive_scope(command)
    if warning:
        return f"BLOCKED: {warning}. HADES only performs read operations."
    return None


def check_command_safety(command: str) -> Optional[str]:
    """Return a rejection reason if the command is blocked, else None."""
    for pattern in _BLOCKED_PATTERNS:
        if pattern.search(command):
            return f"Blocked: command matches dangerous pattern ({pattern.pattern})"
    return None


# ---------------------------------------------------------------------------
# Execution result
# ---------------------------------------------------------------------------

class ExecutionResult:
    """Container for a completed command execution."""

    def __init__(self, exit_code: int, stdout: str, stderr: str, timed_out: bool = False):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out

    @property
    def output(self) -> str:
        """Combined stdout + stderr for display."""
        parts: list[str] = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append(self.stderr)
        combined = "\n".join(parts)
        if self.timed_out:
            combined += "\n[Command timed out]"
        return combined


# ---------------------------------------------------------------------------
# Streaming executor
# ---------------------------------------------------------------------------

# Type alias for the streaming callback: receives (stream_name, chunk)
StreamCallback = Callable[[str, str], Coroutine]


_MAX_OUTPUT_BYTES = 512_000  # 512 KB cap per stream


async def execute_command(
    command: str,
    timeout: int | None = None,
    on_output: StreamCallback | None = None,
) -> ExecutionResult:
    """
    Execute a shell command asynchronously.

    Args:
        command: The shell command string to execute.
        timeout: Per-command timeout in seconds (capped at MAX_COMMAND_TIMEOUT).
        on_output: Async callback called with (stream_name, chunk) for real-time
                   streaming. stream_name is 'stdout' or 'stderr'.

    Returns:
        ExecutionResult with exit code, captured output, and timeout flag.
    """
    effective_timeout = min(timeout or 120, settings.MAX_COMMAND_TIMEOUT)

    # Safety gate
    reason = check_command_safety(command)
    if reason:
        return ExecutionResult(exit_code=1, stdout="", stderr=reason, timed_out=False)

    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        # Use a process group so we can kill the whole tree
        preexec_fn=lambda: __import__("os").setpgrp(),
    )

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    timed_out = False

    async def _read_stream(
        stream: asyncio.StreamReader | None,
        name: str,
        buf: list[str],
    ) -> None:
        if stream is None:
            return
        total_bytes = 0
        capped = False
        while True:
            line = await stream.readline()
            if not line:
                break
            decoded = line.decode("utf-8", errors="replace")
            if not capped:
                total_bytes += len(line)
                if total_bytes > _MAX_OUTPUT_BYTES:
                    buf.append(f"\n[... output capped at {_MAX_OUTPUT_BYTES // 1024} KB — {total_bytes:,} bytes total ...]\n")
                    capped = True
                else:
                    buf.append(decoded)
            if on_output is not None:
                if not capped:
                    await on_output(name, decoded)

    try:
        await asyncio.wait_for(
            asyncio.gather(
                _read_stream(process.stdout, "stdout", stdout_chunks),
                _read_stream(process.stderr, "stderr", stderr_chunks),
                process.wait(),
            ),
            timeout=effective_timeout,
        )
    except asyncio.TimeoutError:
        timed_out = True
        # Kill the entire process group
        try:
            import os
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        if on_output is not None:
            await on_output("stderr", f"\n[Command timed out after {effective_timeout}s]\n")

    exit_code = process.returncode if process.returncode is not None else -1

    return ExecutionResult(
        exit_code=exit_code,
        stdout="".join(stdout_chunks),
        stderr="".join(stderr_chunks),
        timed_out=timed_out,
    )


async def kill_process(process: asyncio.subprocess.Process) -> None:
    """Forcefully kill a running process and its children."""
    try:
        import os
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.kill()
    except ProcessLookupError:
        pass
    await process.wait()
