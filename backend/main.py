"""HADES backend — FastAPI application with REST + WebSocket endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from auth import create_token, decode_token, get_current_user, hash_password, verify_password

from claude_client import ClaudeClient, TextChunk, TokenUsageUpdate, ToolCallResult
from config import settings
from database import Database
from executor import check_command_safety, execute_command
from orchestrator import ScanOrchestrator, ScanProgress
from screenshot import capture_evidence

# Import all tool modules to register them in the global registry
import tools.whatweb_tool    # noqa: F401
import tools.dns_tool        # noqa: F401
import tools.subfinder_tool  # noqa: F401
import tools.ffuf_tool       # noqa: F401
import tools.gobuster_tool   # noqa: F401
import tools.nuclei_tool     # noqa: F401
import tools.sqlmap_tool     # noqa: F401
import tools.hydra_tool      # noqa: F401
import tools.curl_tool       # noqa: F401
import tools.httpx_tool      # noqa: F401
import tools.exec_tool       # noqa: F401
import tools.nikto_tool      # noqa: F401
import tools.nmap_tool       # noqa: F401
import tools.katana_tool     # noqa: F401
import tools.dalfox_tool     # noqa: F401
import tools.gau_tool        # noqa: F401
import tools.js_analyze_tool # noqa: F401
import tools.xss_probe_tool  # noqa: F401
import tools.sqli_probe_tool  # noqa: F401
import tools.idor_probe_tool  # noqa: F401
import tools.wpscan_tool      # noqa: F401
import tools.wafw00f_tool     # noqa: F401
import tools.arjun_tool       # noqa: F401
import tools.testssl_tool     # noqa: F401
import tools.feroxbuster_tool # noqa: F401
import tools.amass_tool       # noqa: F401
import tools.wfuzz_tool       # noqa: F401
import tools.commix_tool      # noqa: F401
import tools.cors_probe_tool  # noqa: F401
import tools.header_probe_tool  # noqa: F401
import tools.redirect_probe_tool  # noqa: F401
import tools.subdomain_takeover_tool  # noqa: F401
import tools.tech_detect_tool  # noqa: F401
import tools.lfi_probe_tool  # noqa: F401
from tools.base import CustomCliTool, registry as tool_registry

from models import (
    ChangePasswordRequest,
    CommandStatus,
    CreateCustomToolRequest,
    CreateProfileRequest,
    CreateProjectRequest,
    CreateSessionRequest,
    CreateUserRequest,
    CustomTool,
    Finding,
    Lead,
    LeadStatus,
    LoginRequest,
    Message,
    MessageRole,
    PendingCommand,
    Phase,
    Project,
    ProjectResponse,
    RiskLevel,
    ScanProfile,
    Session,
    SessionResponse,
    SessionStatus,
    UpdateCustomToolRequest,
    UpdateProfileRequest,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/tmp/hades-backend.log"),
    ],
)
logger = logging.getLogger("hades")

# ---------------------------------------------------------------------------
# Application globals
# ---------------------------------------------------------------------------

db = Database()
claude = ClaudeClient()

# Track active WebSocket connections per session
_ws_connections: dict[str, list[WebSocket]] = {}
_MAX_BROADCAST_LINES = 150

# Token budget per session (0 = unlimited)
_token_budgets: dict[str, int] = {}
_DEFAULT_TOKEN_BUDGET = 0
_BUDGET_WARN_PCT = 0.70
_BUDGET_PAUSE_PCT = 0.90

# Session flow control: "running" | "paused" | "stopped"
_session_state: dict[str, str] = {}
# Track running Claude CLI processes so we can kill them on stop
_active_processes: dict[str, asyncio.subprocess.Process] = {}
# Track running orchestrated scans so we can abort them
_active_scans: dict[str, ScanOrchestrator] = {}

# Authorization system for destructive operations
_pending_authorizations: dict[str, asyncio.Event] = {}
_authorization_results: dict[str, bool] = {}


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.connect()
    logger.info("Database connected at %s", db.db_path)

    # Create default admin user if it doesn't exist
    existing = await db.get_user_by_username("admin")
    if not existing:
        await db.create_user({
            "id": str(uuid.uuid4()),
            "username": "admin",
            "password_hash": hash_password("P@ssw0rd"),
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        logger.info("Created default admin user: admin")

    # Load custom tools into registry
    custom_tools = await db.get_custom_tools()
    for ct in custom_tools:
        tool_registry.register(CustomCliTool(
            name=ct.name, binary=ct.binary_path, description=ct.description,
            category=ct.category, risk=ct.risk, timeout=ct.timeout,
            args_template=ct.args_template, display_name=ct.display_name,
        ))
    if custom_tools:
        logger.info("Loaded %d custom tools into registry", len(custom_tools))

    yield
    await db.close()
    logger.info("Database closed")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="HADES",
    description="Hacking Automated Discovery & Exploitation System — AI-powered penetration testing assistant",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# NOTE: frontend static mount is registered AFTER all API routes (bottom of file)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _broadcast(session_id: str, payload: dict[str, Any]) -> None:
    """Send a JSON message to all WebSocket clients on a session."""
    dead: list[WebSocket] = []
    for ws in _ws_connections.get(session_id, []):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    # Clean up dead connections
    for ws in dead:
        try:
            _ws_connections[session_id].remove(ws)
        except ValueError:
            pass


async def _broadcast_token_usage(session_id: str, usage: TokenUsageUpdate) -> None:
    """Broadcast token usage update and check budget limits."""
    total = usage.cumulative_input + usage.cumulative_output
    budget = _token_budgets.get(session_id, _DEFAULT_TOKEN_BUDGET)

    payload: dict[str, Any] = {
        "type": "token_usage",
        "turn_input": usage.input_tokens,
        "turn_output": usage.output_tokens,
        "total_input": usage.cumulative_input,
        "total_output": usage.cumulative_output,
        "total": total,
        "budget": budget,
    }

    if budget > 0:
        pct = total / budget
        payload["budget_pct"] = round(pct * 100, 1)
        if pct >= _BUDGET_PAUSE_PCT:
            payload["budget_status"] = "paused"
            payload["budget_message"] = f"Token budget {pct:.0%} used — session auto-paused. Increase budget or start a new session."
            logger.warning("Session %s hit token budget pause (%d/%d)", session_id[:8], total, budget)
        elif pct >= _BUDGET_WARN_PCT:
            payload["budget_status"] = "warning"
            payload["budget_message"] = f"Token budget {pct:.0%} used ({total:,}/{budget:,})"

    await _broadcast(session_id, payload)


async def _process_tool_calls(
    session_id: str,
    tool_calls: list[ToolCallResult],
    target: str,
    phase: str,
    findings: list[Finding],
) -> None:
    """
    Handle tool calls from Claude: create pending commands, findings,
    or update phase. Sends results back to Claude for multi-tool-call
    turns and broadcasts updates to WebSocket clients.
    """
    for tc in tool_calls:
        try:
            if tc.tool_name == "run_command":
                cmd = ClaudeClient.parse_command(session_id, tc)

                if cmd.risk_level in (RiskLevel.low, RiskLevel.medium):
                    cmd.status = CommandStatus.approved
                    await db.create_command(cmd)
                    await _broadcast(session_id, {
                        "type": "command_auto_executed",
                        "command": cmd.model_dump(mode="json"),
                    })
                    logger.info(
                        "Auto-approved command [%s] (risk=%s): %s",
                        cmd.id[:8], cmd.risk_level.value, cmd.command,
                    )
                    safety_issue = check_command_safety(cmd.command)
                    if safety_issue:
                        await db.update_command_status(
                            cmd.id, CommandStatus.rejected, output=safety_issue,
                        )
                        await _broadcast(session_id, {
                            "type": "command_rejected",
                            "id": cmd.id,
                            "reason": safety_issue,
                        })
                        logger.warning(
                            "Auto-approved command blocked by safety gate: %s",
                            safety_issue,
                        )
                    else:
                        asyncio.create_task(
                            _execute_and_feed_back(session_id, cmd)
                        )
                else:
                    await db.create_command(cmd)
                    await _broadcast(session_id, {
                        "type": "command_pending",
                        "command": cmd.model_dump(mode="json"),
                    })
                    logger.info(
                        "Pending command [%s] (risk=%s): %s",
                        cmd.id[:8], cmd.risk_level.value, cmd.command,
                    )

            elif tc.tool_name == "add_finding":
                finding = ClaudeClient.parse_finding(session_id, tc)
                if await db.finding_exists(session_id, finding.title):
                    logger.info("Skipping duplicate finding: %s", finding.title)
                    continue
                await db.create_finding(finding)
                await _broadcast(session_id, {
                    "type": "finding",
                    "finding": finding.model_dump(mode="json"),
                })
                logger.info("Finding [%s]: %s (%s)", finding.id[:8], finding.title, finding.severity.value)

            elif tc.tool_name == "add_lead":
                lead = ClaudeClient.parse_lead(session_id, tc)
                if await db.lead_exists(session_id, lead.title):
                    logger.info("Skipping duplicate lead: %s", lead.title)
                    continue
                await db.create_lead(lead)
                await _broadcast(session_id, {
                    "type": "lead",
                    "lead": lead.model_dump(mode="json"),
                })
                logger.info("Lead [%s]: %s (%s)", lead.id[:8], lead.title, lead.category.value)

            elif tc.tool_name == "update_phase":
                new_phase, reason = ClaudeClient.parse_phase(tc)
                await db.update_session_phase(session_id, new_phase)
                await _broadcast(session_id, {
                    "type": "phase_change",
                    "phase": new_phase.value,
                    "reason": reason,
                })
                logger.info("Phase update %s: %s", new_phase.value, reason)

        except Exception as exc:
            logger.exception("Error processing tool call %s: %s", tc.tool_name, exc)


async def _handle_user_message(session_id: str, content: str) -> None:
    """Process a user chat message: save it, send to Claude, stream responses."""
    session = await db.get_session(session_id)
    if session is None:
        await _broadcast(session_id, {"type": "error", "message": "Session not found"})
        return

    # Check session flow control
    state = _session_state.get(session_id, "running")
    if state == "stopped":
        await _broadcast(session_id, {
            "type": "error",
            "message": "Session is stopped. Resume it before sending messages.",
        })
        return
    if state == "paused":
        await _broadcast(session_id, {
            "type": "error",
            "message": "Session is paused. Resume it before sending messages.",
        })
        return

    # Check token budget before sending to Claude
    budget = _token_budgets.get(session_id, _DEFAULT_TOKEN_BUDGET)
    if budget > 0:
        usage = claude.get_token_usage(session_id)
        total = usage["input_tokens"] + usage["output_tokens"]
        if total / budget >= _BUDGET_PAUSE_PCT:
            await _broadcast(session_id, {
                "type": "token_usage",
                "budget_status": "paused",
                "budget_message": f"Session paused — token budget {total/budget:.0%} used ({total:,}/{budget:,}). Increase budget via settings or start a new session.",
                "total": total,
                "budget": budget,
            })
            return

    # Get project scope for authorization context
    project = await db.get_project(session.project_id) if session.project_id else None
    scope = project.scope if project else None
    client = project.client if project else ""

    # Save user message
    user_msg = Message(session_id=session_id, role=MessageRole.user, content=content)
    await db.add_message(user_msg)

    findings = await db.get_findings(session_id)
    leads = await db.get_leads(session_id)

    # Seed command history from DB if not already populated (e.g. after orchestrated scan)
    if not claude._commands_history.get(session_id):
        db_commands = await db.get_commands(session_id)
        if db_commands:
            claude.seed_commands_from_db(session_id, db_commands)

    # Stream Claude's response
    full_text = ""
    tool_calls: list[ToolCallResult] = []

    try:
        async for chunk in claude.chat_stream(
            session_id=session_id,
            user_message=content,
            target=session.target,
            phase=session.phase.value,
            findings=findings,
            scope=scope,
            leads=leads,
            client=client,
        ):
            if isinstance(chunk, TextChunk):
                if chunk.done:
                    pass
                else:
                    full_text += chunk.text
                    await _broadcast(session_id, {
                        "type": "message",
                        "role": "assistant",
                        "content": chunk.text,
                        "streaming": True,
                    })
            elif isinstance(chunk, TokenUsageUpdate):
                await _broadcast_token_usage(session_id, chunk)
            elif isinstance(chunk, ToolCallResult):
                tool_calls.append(chunk)

    except Exception as exc:
        logger.exception("Claude API error for session %s", session_id)
        await _broadcast(session_id, {"type": "error", "message": f"AI error: {exc}"})
        return

    # Clean structured tags from text for display/storage
    clean_text = claude.clean_response_text(full_text) if full_text else ""

    # Always send streaming=false to finalize the streaming message on the frontend
    # (resets streamingMessage accumulator even if clean_text is empty)
    if full_text:
        await _broadcast(session_id, {
            "type": "message",
            "role": "assistant",
            "content": clean_text,
            "streaming": False,
        })

    # Save assistant message
    if clean_text or tool_calls:
        assistant_msg = Message(
            session_id=session_id,
            role=MessageRole.assistant,
            content=clean_text or full_text,
        )
        await db.add_message(assistant_msg)

    # If Claude returned nothing at all, auto-retry once with conversation reset
    if not clean_text and not tool_calls:
        logger.warning("Empty response for session %s, attempting retry with conversation reset", session_id[:8])
        claude.clear_history(session_id)
        # Restore command history for the reset context
        await _broadcast(session_id, {
            "type": "message",
            "role": "assistant",
            "content": "[Retrying with fresh context...]",
            "streaming": False,
        })
        # Re-run with fresh conversation (recursive, but only once since history is cleared)
        retry_text = ""
        retry_tool_calls: list[ToolCallResult] = []
        try:
            async for chunk in claude.chat_stream(
                session_id=session_id,
                user_message=content,
                target=session.target,
                phase=session.phase.value,
                findings=findings,
                scope=scope,
                leads=leads,
                client=client,
            ):
                if isinstance(chunk, TextChunk):
                    if not chunk.done:
                        retry_text += chunk.text
                        await _broadcast(session_id, {
                            "type": "message",
                            "role": "assistant",
                            "content": chunk.text,
                            "streaming": True,
                        })
                elif isinstance(chunk, TokenUsageUpdate):
                    await _broadcast_token_usage(session_id, chunk)
                elif isinstance(chunk, ToolCallResult):
                    retry_tool_calls.append(chunk)
        except Exception as exc:
            logger.exception("Retry also failed for session %s", session_id)

        retry_clean = claude.clean_response_text(retry_text) if retry_text else ""
        if retry_clean:
            await _broadcast(session_id, {
                "type": "message",
                "role": "assistant",
                "content": retry_clean,
                "streaming": False,
            })
        if retry_clean or retry_tool_calls:
            msg = Message(session_id=session_id, role=MessageRole.assistant, content=retry_clean or retry_text)
            await db.add_message(msg)

        if not retry_clean and not retry_tool_calls:
            await _broadcast(session_id, {
                "type": "message",
                "role": "assistant",
                "content": "[HADES: Claude returned no response after retry. Check the backend logs for errors.]",
                "streaming": False,
            })
        elif retry_tool_calls:
            findings = await db.get_findings(session_id)
            await _process_tool_calls(
                session_id, retry_tool_calls, session.target, session.phase.value, findings,
            )
        return

    # Handle tool calls (commands, findings, phase changes)
    if tool_calls:
        findings = await db.get_findings(session_id)
        await _process_tool_calls(
            session_id, tool_calls, session.target, session.phase.value, findings
        )


async def _handle_auto_recon(session_id: str) -> None:
    """Auto-start orchestrated scan when a new session is created."""
    await _run_orchestrated_scan(session_id)


_MAX_DB_OUTPUT_CHARS = 100_000  # 100 KB cap for command output stored in DB


async def _execute_and_feed_back(session_id: str, cmd: PendingCommand) -> None:
    """Execute an approved command, stream output, and feed results back to Claude."""
    session = await db.get_session(session_id)
    if session is None:
        return

    broadcast_count = 0

    async def on_output(stream_name: str, chunk: str) -> None:
        nonlocal broadcast_count
        broadcast_count += 1
        if broadcast_count <= _MAX_BROADCAST_LINES:
            await _broadcast(session_id, {
                "type": "command_output",
                "id": cmd.id,
                "output": chunk,
                "streaming": True,
            })
        elif broadcast_count == _MAX_BROADCAST_LINES + 1:
            await _broadcast(session_id, {
                "type": "command_output",
                "id": cmd.id,
                "output": f"\n[... display truncated at {_MAX_BROADCAST_LINES} lines — full output saved ...]\n",
                "streaming": True,
            })

    result = await execute_command(
        command=cmd.command,
        on_output=on_output,
    )

    full_output = result.output
    exit_code = result.exit_code

    # Cap output stored in DB to avoid bloating SQLite
    db_output = full_output
    if db_output and len(db_output) > _MAX_DB_OUTPUT_CHARS:
        db_output = db_output[:_MAX_DB_OUTPUT_CHARS] + f"\n[... truncated, {len(full_output):,} chars total]"

    # Update command in DB
    await db.update_command_status(
        cmd.id,
        CommandStatus.executed if exit_code == 0 else CommandStatus.failed,
        output=db_output,
        exit_code=exit_code,
    )

    # Broadcast completion
    await _broadcast(session_id, {
        "type": "command_complete",
        "id": cmd.id,
        "exit_code": exit_code,
    })

    # Check flow control before feeding back to Claude
    state = _session_state.get(session_id, "running")
    if state in ("paused", "stopped"):
        await _broadcast(session_id, {
            "type": "message",
            "role": "assistant",
            "content": f"[Command finished. Session is {state} — resume to continue analysis.]",
            "streaming": False,
        })
        return

    # Feed the output back to Claude for analysis
    project = await db.get_project(session.project_id) if session.project_id else None
    scope = project.scope if project else None
    client = project.client if project else ""
    findings = await db.get_findings(session_id)
    leads = await db.get_leads(session_id)
    full_text = ""
    new_tool_calls: list[ToolCallResult] = []

    try:
        async for chunk in claude.feed_command_output(
            session_id=session_id,
            command=cmd.command,
            output=full_output or "(no output)",
            exit_code=exit_code,
            target=session.target,
            phase=session.phase.value,
            findings=findings,
            scope=scope,
            client=client,
            leads=leads,
        ):
            if isinstance(chunk, TextChunk):
                if chunk.done:
                    pass
                else:
                    full_text += chunk.text
                    await _broadcast(session_id, {
                        "type": "message",
                        "role": "assistant",
                        "content": chunk.text,
                        "streaming": True,
                    })
            elif isinstance(chunk, TokenUsageUpdate):
                await _broadcast_token_usage(session_id, chunk)
            elif isinstance(chunk, ToolCallResult):
                new_tool_calls.append(chunk)

    except Exception as exc:
        logger.exception("Claude error during command output analysis")
        await _broadcast(session_id, {"type": "error", "message": f"AI error: {exc}"})
        return

    # Clean and send final message (always send streaming=false to reset frontend accumulator)
    clean_text = claude.clean_response_text(full_text) if full_text else ""
    if full_text:
        await _broadcast(session_id, {
            "type": "message",
            "role": "assistant",
            "content": clean_text,
            "streaming": False,
        })

    # Save assistant response
    if clean_text or new_tool_calls:
        assistant_msg = Message(
            session_id=session_id,
            role=MessageRole.assistant,
            content=clean_text or full_text,
        )
        await db.add_message(assistant_msg)

    # If Claude returned nothing, retry once with conversation reset
    if not clean_text and not new_tool_calls:
        logger.warning("Empty response after command output for session %s, retrying with reset", session_id[:8])
        claude.clear_history(session_id)
        await _broadcast(session_id, {
            "type": "message",
            "role": "assistant",
            "content": "[Retrying analysis with fresh context...]",
            "streaming": False,
        })
        retry_text = ""
        retry_tcs: list[ToolCallResult] = []
        try:
            async for chunk in claude.feed_command_output(
                session_id=session_id,
                command=cmd.command,
                output=full_output or "(no output)",
                exit_code=exit_code,
                target=session.target,
                phase=session.phase.value,
                findings=findings,
                scope=scope,
                leads=leads,
                client=client,
            ):
                if isinstance(chunk, TextChunk):
                    if not chunk.done:
                        retry_text += chunk.text
                        await _broadcast(session_id, {
                            "type": "message", "role": "assistant",
                            "content": chunk.text, "streaming": True,
                        })
                elif isinstance(chunk, TokenUsageUpdate):
                    await _broadcast_token_usage(session_id, chunk)
                elif isinstance(chunk, ToolCallResult):
                    retry_tcs.append(chunk)
        except Exception as exc:
            logger.exception("Retry failed for command output analysis")

        retry_clean = claude.clean_response_text(retry_text) if retry_text else ""
        if retry_clean:
            await _broadcast(session_id, {
                "type": "message", "role": "assistant",
                "content": retry_clean, "streaming": False,
            })
        if retry_clean or retry_tcs:
            msg = Message(session_id=session_id, role=MessageRole.assistant, content=retry_clean or retry_text)
            await db.add_message(msg)
        if not retry_clean and not retry_tcs:
            await _broadcast(session_id, {
                "type": "message", "role": "assistant",
                "content": "[HADES: No response after retry. Send a follow-up message to continue.]",
                "streaming": False,
            })
        elif retry_tcs:
            findings = await db.get_findings(session_id)
            await _process_tool_calls(session_id, retry_tcs, session.target, session.phase.value, findings)
        return

    # Handle any new tool calls
    if new_tool_calls:
        findings = await db.get_findings(session_id)
        await _process_tool_calls(
            session_id, new_tool_calls, session.target,
            session.phase.value, findings,
        )


# ---------------------------------------------------------------------------
# REST endpoints — Auth
# ---------------------------------------------------------------------------

@app.post("/api/auth/login")
async def login(req: LoginRequest):
    """Authenticate a user and return a JWT token."""
    user = await db.get_user_by_username(req.username)
    if user is None or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_token(user["id"], user["username"], user["role"])
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        },
    }


@app.get("/api/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    """Return the current authenticated user."""
    return user


@app.post("/api/auth/change-password")
async def change_own_password(req: ChangePasswordRequest, user: dict = Depends(get_current_user)):
    """Change the current user's own password."""
    db_user = await db.get_user_by_username(user["username"])
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(req.current_password, db_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    await db.update_user_password(user["id"], hash_password(req.new_password))
    return {"ok": True, "message": "Password changed"}


# ---------------------------------------------------------------------------
# REST endpoints — User Management (admin only)
# ---------------------------------------------------------------------------

@app.get("/api/users")
async def list_users(user: dict = Depends(get_current_user)):
    """List all users (admin only)."""
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return await db.list_users()


@app.post("/api/users")
async def create_user_endpoint(req: CreateUserRequest, user: dict = Depends(get_current_user)):
    """Create a new user (admin only)."""
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    if req.role not in ("admin", "operator"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'operator'")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    existing = await db.get_user_by_username(req.username)
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")
    new_user = {
        "id": str(uuid.uuid4()),
        "username": req.username,
        "password_hash": hash_password(req.password),
        "role": req.role,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    result = await db.create_user(new_user)
    return result


@app.delete("/api/users/{user_id}")
async def delete_user_endpoint(user_id: str, user: dict = Depends(get_current_user)):
    """Delete a user (admin only). Cannot delete self or last admin."""
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    deleted = await db.delete_user(user_id)
    if not deleted:
        raise HTTPException(status_code=400, detail="Cannot delete user (not found or last admin)")
    return {"ok": True}


@app.post("/api/users/{user_id}/password")
async def reset_user_password(user_id: str, req: ChangePasswordRequest, user: dict = Depends(get_current_user)):
    """Reset a user's password. Admin can reset any; operator can change own only."""
    if user["role"] != "admin" and user_id != user["id"]:
        raise HTTPException(status_code=403, detail="Admin access required to change other users' passwords")
    if user_id == user["id"] and user["role"] != "admin":
        # Operator changing own password — require current password
        db_user = await db.get_user_by_username(user["username"])
        if db_user is None or not verify_password(req.current_password, db_user["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
    target_user = await db.get_user(user_id)
    if target_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    await db.update_user_password(user_id, hash_password(req.new_password))
    return {"ok": True, "message": f"Password updated for {target_user['username']}"}


# ---------------------------------------------------------------------------
# REST endpoints — Projects
# ---------------------------------------------------------------------------

@app.post("/api/projects", response_model=Project)
async def create_project(req: CreateProjectRequest, user: dict = Depends(get_current_user)):
    """Create a new pentest engagement project."""
    project = Project(
        name=req.name,
        client=req.client,
        description=req.description,
        scope=req.scope,
        start_date=req.start_date,
        end_date=req.end_date,
    )
    await db.create_project(project)
    logger.info("Created project %s: %s (client: %s)", project.id[:8], project.name, project.client)
    return project


@app.get("/api/projects")
async def list_projects(user: dict = Depends(get_current_user)):
    """List all projects with session/finding counts."""
    return await db.list_projects_with_stats()


@app.get("/api/projects/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str, user: dict = Depends(get_current_user)):
    """Get a project with its sessions and finding summary."""
    project = await db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    sessions = await db.get_project_sessions(project_id)
    findings_by_severity = await db.get_project_findings_summary(project_id)
    total_findings = sum(findings_by_severity.values())

    return ProjectResponse(
        project=project,
        sessions=sessions,
        total_findings=total_findings,
        findings_by_severity=findings_by_severity,
    )


@app.put("/api/projects/{project_id}", response_model=Project)
async def update_project(project_id: str, req: CreateProjectRequest, user: dict = Depends(get_current_user)):
    """Update an existing project."""
    existing = await db.get_project(project_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Project not found")

    updated = await db.update_project(
        project_id,
        name=req.name,
        client=req.client,
        description=req.description,
        scope=req.scope,
        start_date=req.start_date,
        end_date=req.end_date,
    )
    logger.info("Updated project %s: %s", project_id[:8], req.name)
    return updated


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str, user: dict = Depends(get_current_user)):
    """Delete a project and all its sessions/data."""
    # Clear Claude conversation history for all sessions in this project
    sessions = await db.get_project_sessions(project_id)
    for s in sessions:
        claude.clear_history(s.id)

    deleted = await db.delete_project(project_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Project not found")
    logger.info("Deleted project %s and all associated data", project_id[:8])
    return {"ok": True}


@app.get("/api/projects/{project_id}/analytics")
async def get_project_analytics(project_id: str, session_id: str | None = None, user: dict = Depends(get_current_user)):
    """Get aggregated KPI analytics for a project, optionally filtered by session."""
    project = await db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    analytics = await db.get_project_analytics(project_id, session_id=session_id)
    return {
        "project_id": project_id,
        "project_name": project.name,
        **analytics,
    }


@app.get("/api/projects/{project_id}/sessions", response_model=list[Session])
async def list_project_sessions(project_id: str, user: dict = Depends(get_current_user)):
    """List all sessions for a project."""
    project = await db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return await db.get_project_sessions(project_id)


# ---------------------------------------------------------------------------
# REST endpoints — Sessions
# ---------------------------------------------------------------------------

@app.post("/api/sessions", response_model=Session)
async def create_session(req: CreateSessionRequest, user: dict = Depends(get_current_user)):
    """Create a new penetration testing session within a project."""
    # Verify the project exists
    project = await db.get_project(req.project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    session = Session(project_id=req.project_id, name=req.name, target=req.target, profile_id=req.profile_id)
    await db.create_session(session)
    logger.info("Created session %s: %s -> %s (project: %s, profile: %s)", session.id[:8], session.name, session.target, req.project_id[:8], req.profile_id or "default")

    # Auto-start recon in background
    asyncio.create_task(_handle_auto_recon(session.id))

    return session


@app.get("/api/sessions", response_model=list[Session])
async def list_sessions(user: dict = Depends(get_current_user)):
    """List all sessions."""
    return await db.list_sessions()


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str, user: dict = Depends(get_current_user)) -> SessionResponse:
    """Get a session with its messages, findings, and pending commands."""
    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    messages = await db.get_messages(session_id)
    findings = await db.get_findings(session_id)
    leads = await db.get_leads(session_id)
    pending = await db.get_pending_commands(session_id)

    return SessionResponse(
        session=session,
        messages=messages,
        findings=findings,
        leads=leads,
        pending_commands=pending,
    )


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str, user: dict = Depends(get_current_user)):
    """Delete a session and all associated data."""
    orch = _active_scans.pop(session_id, None)
    if orch:
        orch.abort()
    await claude.abort_session(session_id)
    claude.clear_history(session_id)
    _session_state.pop(session_id, None)
    _ws_connections.pop(session_id, None)
    _token_budgets.pop(session_id, None)

    deleted = await db.delete_session(session_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Session not found")
    logger.info("Deleted session %s (scan aborted, process killed, state cleaned)", session_id[:8])
    return {"ok": True}


@app.get("/api/sessions/{session_id}/findings", response_model=list[Finding])
async def get_findings(session_id: str, user: dict = Depends(get_current_user)):
    """Get all findings for a session."""
    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return await db.get_findings(session_id)


@app.get("/api/sessions/{session_id}/leads", response_model=list[Lead])
async def get_leads(session_id: str, user: dict = Depends(get_current_user)):
    """Get all leads for a session."""
    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return await db.get_leads(session_id)


@app.post("/api/leads/{lead_id}/status")
async def update_lead_status_endpoint(lead_id: str, status: str, user: dict = Depends(get_current_user)):
    """Update a lead's status (open, investigating, escalated, dismissed)."""
    try:
        new_status = LeadStatus(status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    await db.update_lead_status(lead_id, new_status)
    return {"ok": True, "lead_id": lead_id, "status": new_status.value}


def _build_steps_to_reproduce(
    finding: Finding, executed_cmds: list[PendingCommand],
) -> list[str]:
    """Correlate commands that led to a finding based on timestamps."""
    finding_ts = finding.created_at
    preceding = [c for c in executed_cmds if c.created_at <= finding_ts]
    relevant = preceding[-5:]
    steps: list[str] = []
    for i, c in enumerate(relevant, 1):
        steps.append(f"{i}. Executar: `{c.command}`")
        if c.output:
            output_preview = c.output.strip()[:600]
            if len(c.output.strip()) > 600:
                output_preview += "\n   [... saída truncada]"
            steps.append(f"   ```")
            steps.append(f"   {output_preview}")
            steps.append(f"   ```")
    return steps


_SEVERITY_PT = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
    "info": "Informativa",
}

_SEVERITY_CVSS_RANGE = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "info": (0.0, 0.0),
}

_SEVERITY_CVSS_DEFAULT = {
    "critical": 9.5,
    "high": 7.8,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}

_SEVERITY_VECTOR_DEFAULT = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "low": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "info": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
}


@app.get("/api/sessions/{session_id}/report")
async def generate_report(session_id: str, user: dict = Depends(get_current_user)):
    """Generate a professional pentest report in Portuguese (PTES methodology)."""
    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    project = await db.get_project(session.project_id) if session.project_id else None
    findings = await db.get_findings(session_id)
    leads = await db.get_leads(session_id)
    commands = await db.get_commands(session_id)
    executed_cmds = [c for c in commands if c.status in (CommandStatus.executed, CommandStatus.failed)]

    client_name = (project.client if project and project.client else
                   project.name if project else session.target)
    target = session.target
    scope_list = project.scope if project and project.scope else [target]
    report_date = datetime.now(timezone.utc).strftime("%d/%m/%Y")

    L: list[str] = []

    # =========================================================================
    # CAPA (Cover)
    # =========================================================================
    L.append("═" * 70)
    L.append("")
    L.append("")
    L.append("        RELATÓRIO TÉCNICO DE SEGURANÇA OFENSIVA")
    L.append("")
    L.append("")
    L.append(f"        Cliente: {client_name}")
    L.append("")
    L.append("        Classificação: Confidencial")
    L.append("")
    L.append(f"        Data: {report_date}")
    L.append("")
    L.append("")
    L.append("═" * 70)
    L.append("")
    L.append("")

    # =========================================================================
    # SUMÁRIO (Table of Contents)
    # =========================================================================
    L.append("SUMÁRIO")
    L.append("─" * 70)
    toc_items = [
        "1. Metodologia",
        "2. Classificação CVSS",
        "3. Introdução",
        "4. Versionamento",
        "5. Vulnerabilidades Detectadas",
        "6. Detalhamento das Vulnerabilidades",
    ]
    open_leads = [ld for ld in leads if ld.status.value == "open"]
    next_num = 7
    if open_leads:
        toc_items.append(f"{next_num}. Leads em Aberto")
        next_num += 1
    toc_items.append(f"{next_num}. Conclusão")
    next_num += 1
    toc_items.append(f"{next_num}. Apêndice: Comandos Executados")
    for item in toc_items:
        L.append(f"  {item}")
    L.append("")
    L.append("")

    # =========================================================================
    # 1. METODOLOGIA
    # =========================================================================
    L.append("═" * 70)
    L.append("1. METODOLOGIA")
    L.append("═" * 70)
    L.append("")
    L.append("Utilizamos uma metodologia de ataque baseada no Penetration Testing")
    L.append("Execution Standard (PTES), visando fornecer um dos melhores e mais")
    L.append("atuais métodos para testar a segurança dos ativos. As etapas seguidas:")
    L.append("")
    ptes_phases = [
        ("Pré-Engajamento",
         "Definição do escopo, regras de execução e critérios de sucesso, "
         "alinhando objetivos e limitações com as áreas envolvidas."),
        ("Reconhecimento",
         "Coleta de informações sobre o alvo (OSINT e scans ativos) para "
         "identificar serviços expostos, versões de software e possíveis "
         "vetores de ataque."),
        ("Modelagem de Ameaças",
         "Definição dos vetores de ataque, avaliando se os controles "
         "existentes são capazes de identificar ou bloquear as abordagens."),
        ("Análise de Vulnerabilidade",
         "Descoberta de falhas em sistemas e aplicações que podem ser "
         "exploradas, incluindo configurações incorretas e design inseguro."),
        ("Exploração",
         "Estabelecimento de acesso ao sistema contornando restrições de "
         "segurança, executado como um ataque de precisão baseado nas "
         "vulnerabilidades identificadas."),
        ("Pós-Exploração",
         "Determinação do valor da máquina comprometida e manutenção do "
         "controle para avaliar impacto real e possibilidade de "
         "movimentação lateral."),
        ("Relatório",
         "Comunicação dos achados, objetivos e recomendações ao leitor, "
         "incluindo evidências técnicas e passos para reprodução."),
    ]
    for phase_name, phase_desc in ptes_phases:
        L.append(f"  • {phase_name}:")
        L.append(f"    {phase_desc}")
        L.append("")
    L.append("")

    # =========================================================================
    # 2. CLASSIFICAÇÃO CVSS
    # =========================================================================
    L.append("═" * 70)
    L.append("2. CLASSIFICAÇÃO CVSS")
    L.append("═" * 70)
    L.append("")
    L.append("Os critérios de classificação de severidade são baseados no CVSS 3.1:")
    L.append("")
    L.append("┌────────────┬─────────────┬─────────────────────────────────────────┐")
    L.append("│ Severidade │   Score     │ Descrição                               │")
    L.append("├────────────┼─────────────┼─────────────────────────────────────────┤")
    L.append("│ Crítica    │  9.0 – 10   │ Execução de código arbitrário, acesso   │")
    L.append("│            │             │ a dados confidenciais. Prioridade máx.  │")
    L.append("├────────────┼─────────────┼─────────────────────────────────────────┤")
    L.append("│ Alta       │  7.0 – 8.9  │ Acesso remoto, execução de código ou    │")
    L.append("│            │             │ controle do sistema.                    │")
    L.append("├────────────┼─────────────┼─────────────────────────────────────────┤")
    L.append("│ Média      │  4.0 – 6.9  │ Leitura de informações privilegiadas,   │")
    L.append("│            │             │ pode ser reclassificada como Alta.      │")
    L.append("├────────────┼─────────────┼─────────────────────────────────────────┤")
    L.append("│ Baixa      │  0.1 – 3.9  │ Vazamento de informações, auxílio para  │")
    L.append("│            │             │ ataques mais sofisticados.              │")
    L.append("└────────────┴─────────────┴─────────────────────────────────────────┘")
    L.append("")
    L.append("O Common Vulnerability Scoring System (CVSS) 3.1 é um padrão")
    L.append("internacional para mensurar a gravidade de vulnerabilidades. A")
    L.append("pontuação vai de 0 a 10 e considera métricas Base (explorabilidade")
    L.append("e impacto), Temporal e Ambiental.")
    L.append("")
    L.append("")

    # =========================================================================
    # 3. INTRODUÇÃO
    # =========================================================================
    L.append("═" * 70)
    L.append("3. INTRODUÇÃO")
    L.append("═" * 70)
    L.append("")
    L.append("Escopo")
    L.append("─" * 40)
    L.append("")
    L.append("Os testes contidos neste relatório foram realizados nos ativos abaixo:")
    L.append("")
    L.append("┌─────────────────────────────────────────────────────────────────────┐")
    L.append("│ Escopo                                                              │")
    L.append("├─────────────────────────────────────────────────────────────────────┤")
    for s in scope_list:
        L.append(f"│ {s:<67} │")
    L.append("└─────────────────────────────────────────────────────────────────────┘")
    L.append("")
    L.append("O modelo utilizado neste teste foi Gray-box (automatizado via HADES AI).")
    L.append("")
    L.append("")

    # =========================================================================
    # 4. VERSIONAMENTO
    # =========================================================================
    L.append("═" * 70)
    L.append("4. VERSIONAMENTO")
    L.append("═" * 70)
    L.append("")
    L.append("┌─────────┬────────────┬──────────────┬──────────────────────────────┐")
    L.append("│ Versão  │ Data       │ Autor        │ Observações                  │")
    L.append("├─────────┼────────────┼──────────────┼──────────────────────────────┤")
    L.append(f"│ 1.0     │ {report_date:<10} │ HADES AI     │ Geração automática           │")
    L.append("└─────────┴────────────┴──────────────┴──────────────────────────────┘")
    L.append("")
    L.append("")

    # =========================================================================
    # 5. VULNERABILIDADES DETECTADAS (Summary Table)
    # =========================================================================
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity_counts[f.severity.value] += 1

    L.append("═" * 70)
    L.append("5. VULNERABILIDADES DETECTADAS")
    L.append("═" * 70)
    L.append("")
    L.append("As vulnerabilidades a seguir foram identificadas durante a Avaliação")
    L.append("Técnica de Segurança. Cada uma está documentada com severidade,")
    L.append("descrição detalhada, passos para reprodução, impactos potenciais e")
    L.append("recomendações de correção.")
    L.append("")

    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_group_names = {
        "critical": "Críticas",
        "high": "Altas",
        "medium": "Médias",
        "low": "Baixas",
        "info": "Informativas",
    }

    finding_num = 0
    numbered_findings: list[tuple[int, Finding]] = []
    for sev in severity_order:
        sev_findings = [f for f in findings if f.severity.value == sev]
        if not sev_findings:
            continue
        L.append(f"  {severity_group_names[sev]}:")
        for f in sev_findings:
            finding_num += 1
            numbered_findings.append((finding_num, f))
            cvss_score = _SEVERITY_CVSS_DEFAULT[sev]
            status = "Pendente de Correção"
            L.append(f"    #{finding_num} - {f.title}")
            L.append(f"      {target}  |  {cvss_score} - {status}")
        L.append("")

    if not findings:
        L.append("  Nenhuma vulnerabilidade foi identificada durante o teste.")
        L.append("")
    L.append("")

    # =========================================================================
    # 6. DETALHAMENTO DAS VULNERABILIDADES
    # =========================================================================
    L.append("═" * 70)
    L.append("6. DETALHAMENTO DAS VULNERABILIDADES")
    L.append("═" * 70)
    L.append("")

    for num, f in numbered_findings:
        sev = f.severity.value
        sev_pt = _SEVERITY_PT.get(sev, sev.capitalize())
        cvss_score = _SEVERITY_CVSS_DEFAULT[sev]
        cvss_vector = _SEVERITY_VECTOR_DEFAULT[sev]

        L.append("─" * 70)
        L.append("")
        L.append(f"  Ativo:            {target}")
        L.append(f"  Severidade:       {sev_pt}")
        L.append(f"  Vulnerabilidade:  #{num} - {f.title}")
        L.append(f"  CVSS Score:       {cvss_score}")
        L.append(f"                    {cvss_vector}")
        L.append("")

        # --- Descrição ---
        L.append("  Descrição:")
        L.append("")
        desc_lines = f.description.strip().split("\n")
        for dl in desc_lines:
            L.append(f"    {dl}")
        L.append("")

        # --- Evidência ---
        if f.evidence:
            L.append("  Evidência:")
            L.append("  ```")
            evidence_lines = f.evidence.strip().split("\n")
            for el in evidence_lines:
                L.append(f"  {el}")
            L.append("  ```")
            L.append("")

        # --- Passos para Reprodução ---
        steps = _build_steps_to_reproduce(f, executed_cmds)
        if steps:
            L.append("  Passos para Reprodução:")
            L.append("")
            for step_line in steps:
                L.append(f"    {step_line}")
            L.append("")
        else:
            L.append("  Passos para Reprodução:")
            L.append("")
            L.append("    1. Acessar o ativo alvo listado acima")
            L.append(f"    2. Verificar a vulnerabilidade: {f.title}")
            L.append("    3. Consultar a evidência apresentada para confirmação")
            L.append("")

        # --- Correções ---
        if f.remediation:
            L.append("  Correções:")
            remediation_items = f.remediation.strip().split("\n")
            for ri in remediation_items:
                ri = ri.strip()
                if ri:
                    if ri.startswith(("- ", "* ", "• ")):
                        ri = ri[2:]
                    L.append(f"    • {ri}")
            L.append("")

        # --- Impacto da Correção ---
        L.append("  Impacto da Correção:")
        L.append("")
        L.append(f"    A implementação das correções recomendadas para a vulnerabilidade")
        L.append(f"    \"{f.title}\" resultará na eliminação ou mitigação significativa do")
        L.append(f"    risco associado. Sistemas ou integrações que dependam do")
        L.append(f"    comportamento atual podem requerer ajustes. Após a aplicação, o")
        L.append(f"    ativo estará em conformidade com as melhores práticas de segurança,")
        L.append(f"    reduzindo a superfície de ataque identificada.")
        L.append("")
        L.append("")

    # =========================================================================
    # 7. LEADS EM ABERTO (if any)
    # =========================================================================
    section_num = 7
    if open_leads:
        L.append("═" * 70)
        L.append(f"{section_num}. LEADS EM ABERTO")
        L.append("═" * 70)
        L.append("")
        L.append("Os seguintes pontos foram identificados e requerem investigação")
        L.append("adicional para determinar se representam vulnerabilidades exploráveis:")
        L.append("")
        for i, ld in enumerate(open_leads, 1):
            desc = ld.description.replace("\n", " ").strip()[:300]
            L.append(f"  {i}. {ld.title}")
            L.append(f"     Categoria: {ld.category.value}")
            L.append(f"     {desc}")
            L.append("")
        L.append("")
        section_num += 1

    # =========================================================================
    # CONCLUSÃO
    # =========================================================================
    L.append("═" * 70)
    L.append(f"{section_num}. CONCLUSÃO")
    L.append("═" * 70)
    L.append("")

    total = len(findings)
    if total == 0:
        L.append(f"Os testes de segurança realizados no ativo {target} não identificaram")
        L.append("vulnerabilidades exploráveis durante o período de avaliação. Isso indica")
        L.append("uma postura de segurança adequada para os vetores testados, porém não")
        L.append("garante ausência total de falhas.")
    else:
        L.append(f"Os testes de segurança realizados no ativo {target} demonstram que o")
        L.append("ambiente possui vulnerabilidades que podem ser exploradas por agentes")
        L.append("maliciosos. Essas falhas aumentam a superfície de ataque e podem")
        L.append("comprometer a confidencialidade, integridade e disponibilidade das")
        L.append("informações processadas.")
        L.append("")

        if severity_counts["critical"] > 0:
            crit_names = [f.title for f in findings if f.severity.value == "critical"]
            L.append(f"Destaca-se, de forma prioritária, a(s) vulnerabilidade(s) classificada(s)")
            L.append(f"como Crítica(s): {', '.join(crit_names)}. A correção deve ser tratada")
            L.append("com prioridade máxima, devido ao impacto direto na segurança dos dados")
            L.append("e na continuidade operacional.")
            L.append("")

        if severity_counts["high"] > 0 or severity_counts["medium"] > 0:
            L.append("As vulnerabilidades de severidade Alta e Média indicam fragilidades nos")
            L.append("controles de acesso, tratamento de erros e gestão de informações. Essas")
            L.append("falhas podem ser combinadas em cenários reais para facilitar o")
            L.append("reconhecimento do ambiente e a exploração de funcionalidades internas.")
            L.append("")

        L.append("Recomenda-se priorizar a correção imediata das vulnerabilidades de")
        L.append("severidade Crítica, seguida pela remediação das classificadas como Alta")
        L.append("e Média. A incorporação de práticas contínuas de segurança ao ciclo de")
        L.append("desenvolvimento (SSDLC) e a realização periódica de testes contribuirão")
        L.append("para a redução de riscos e alinhamento com OWASP Top 10, CIS Controls")
        L.append("e CVSS 3.1.")

    L.append("")
    L.append("")
    section_num += 1

    # =========================================================================
    # APÊNDICE: COMANDOS EXECUTADOS
    # =========================================================================
    if executed_cmds:
        L.append("═" * 70)
        L.append(f"{section_num}. APÊNDICE: COMANDOS EXECUTADOS")
        L.append("═" * 70)
        L.append("")
        L.append(f"Total de comandos executados: {len(executed_cmds)}")
        L.append("")
        for i, c in enumerate(executed_cmds, 1):
            exit_str = str(c.exit_code) if c.exit_code is not None else "N/A"
            L.append(f"  [{i:03d}] {c.command}")
            L.append(f"        Fase: {c.phase.value} | Risco: {c.risk_level.value} | Exit: {exit_str}")
        L.append("")

    # =========================================================================
    # RODAPÉ
    # =========================================================================
    L.append("═" * 70)
    now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    L.append(f"Relatório gerado automaticamente por HADES AI em {now_str}")
    L.append("Classificação: Confidencial")
    L.append("═" * 70)

    report_md = "\n".join(L)

    return {
        "session_id": session_id,
        "report": report_md,
        "findings_count": len(findings),
        "commands_count": len(executed_cmds),
    }


@app.get("/api/sessions/{session_id}/report/pdf")
async def generate_report_pdf(session_id: str, user: dict = Depends(get_current_user)):
    """Generate a professional PDF pentest report for the session."""
    from report_pdf import generate_pdf

    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    project = await db.get_project(session.project_id) if session.project_id else None
    findings = await db.get_findings(session_id)
    leads = await db.get_leads(session_id)
    commands = await db.get_commands(session_id)

    try:
        pdf_bytes = generate_pdf(session, project, findings, leads, commands)
    except Exception as exc:
        import traceback
        logger.error("PDF generation failed for session %s: %s\n%s", session_id[:8], exc, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

    filename = f"HADES_Report_{session.target.replace(' ', '_')}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/commands/{command_id}/approve")
async def approve_command(command_id: str, user: dict = Depends(get_current_user)):
    """Approve a pending command for execution."""
    cmd = await db.get_command(command_id)
    if cmd is None:
        raise HTTPException(status_code=404, detail="Command not found")
    if cmd.status != CommandStatus.pending:
        raise HTTPException(status_code=400, detail=f"Command is already {cmd.status.value}")

    # Safety check
    safety_issue = check_command_safety(cmd.command)
    if safety_issue:
        await db.update_command_status(cmd.id, CommandStatus.rejected, output=safety_issue)
        raise HTTPException(status_code=400, detail=safety_issue)

    await db.update_command_status(cmd.id, CommandStatus.approved)
    logger.info("Approved command [%s]: %s", cmd.id[:8], cmd.command)

    # Execute in background so the REST response returns immediately
    asyncio.create_task(_execute_and_feed_back(cmd.session_id, cmd))

    return {"ok": True, "command_id": command_id, "status": "approved"}


@app.post("/api/commands/{command_id}/reject")
async def reject_command(command_id: str, user: dict = Depends(get_current_user)):
    """Reject a pending command."""
    cmd = await db.get_command(command_id)
    if cmd is None:
        raise HTTPException(status_code=404, detail="Command not found")
    if cmd.status != CommandStatus.pending:
        raise HTTPException(status_code=400, detail=f"Command is already {cmd.status.value}")

    await db.update_command_status(cmd.id, CommandStatus.rejected)
    logger.info("Rejected command [%s]: %s", cmd.id[:8], cmd.command)

    # Notify Claude about the rejection so it can suggest alternatives
    session = await db.get_session(cmd.session_id)
    if session:
        project = await db.get_project(session.project_id) if session.project_id else None
        findings = await db.get_findings(cmd.session_id)
        leads = await db.get_leads(cmd.session_id)
        rejection_msg = (
            f"The operator REJECTED the command: `{cmd.command}`\n"
            "Suggest an alternative approach or ask for clarification."
        )
        full_text = ""
        new_tool_calls: list[ToolCallResult] = []

        try:
            async for chunk in claude.chat_stream(
                session_id=cmd.session_id,
                user_message=rejection_msg,
                target=session.target,
                phase=session.phase.value,
                findings=findings,
                leads=leads,
                client=project.client if project else "",
            ):
                if isinstance(chunk, TextChunk):
                    if not chunk.done:
                        full_text += chunk.text
                        await _broadcast(cmd.session_id, {
                            "type": "message",
                            "role": "assistant",
                            "content": chunk.text,
                            "streaming": True,
                        })
                elif isinstance(chunk, TokenUsageUpdate):
                    await _broadcast_token_usage(cmd.session_id, chunk)
                elif isinstance(chunk, ToolCallResult):
                    new_tool_calls.append(chunk)
        except Exception as exc:
            logger.exception("Claude error during rejection feedback")

        clean_text = claude.clean_response_text(full_text) if full_text else ""
        if clean_text:
            await _broadcast(cmd.session_id, {
                "type": "message",
                "role": "assistant",
                "content": clean_text,
                "streaming": False,
            })

        if clean_text or new_tool_calls:
            assistant_msg = Message(
                session_id=cmd.session_id,
                role=MessageRole.assistant,
                content=clean_text or full_text,
            )
            await db.add_message(assistant_msg)

        if new_tool_calls:
            findings = await db.get_findings(cmd.session_id)
            await _process_tool_calls(
                cmd.session_id, new_tool_calls, session.target,
                session.phase.value, findings,
            )

    await _broadcast(cmd.session_id, {
        "type": "command_rejected",
        "id": cmd.id,
    })

    return {"ok": True, "command_id": command_id, "status": "rejected"}


# ---------------------------------------------------------------------------
# REST endpoints — Token Usage & Budget
# ---------------------------------------------------------------------------

@app.get("/api/sessions/{session_id}/tokens")
async def get_token_usage(session_id: str, user: dict = Depends(get_current_user)):
    """Get cumulative token usage for a session."""
    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    usage = claude.get_token_usage(session_id)
    budget = _token_budgets.get(session_id, _DEFAULT_TOKEN_BUDGET)
    total = usage["input_tokens"] + usage["output_tokens"]
    return {
        "session_id": session_id,
        **usage,
        "total": total,
        "budget": budget,
        "budget_pct": round((total / budget) * 100, 1) if budget > 0 else None,
    }


@app.post("/api/sessions/{session_id}/budget")
async def set_token_budget(session_id: str, budget: int, user: dict = Depends(get_current_user)):
    """Set token budget for a session (0 = unlimited)."""
    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    _token_budgets[session_id] = max(0, budget)
    logger.info("Token budget set for session %s: %d", session_id[:8], budget)
    return {"ok": True, "session_id": session_id, "budget": _token_budgets[session_id]}


# ---------------------------------------------------------------------------
# REST endpoints — Session Flow Control
# ---------------------------------------------------------------------------

@app.post("/api/sessions/{session_id}/pause")
async def pause_session(session_id: str, user: dict = Depends(get_current_user)):
    """Pause a session — stops the auto-execution chain after current command finishes."""
    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    _session_state[session_id] = "paused"
    await _broadcast(session_id, {"type": "session_state", "state": "paused"})
    logger.info("Session %s paused", session_id[:8])
    return {"ok": True, "state": "paused"}


@app.post("/api/sessions/{session_id}/resume")
async def resume_session(session_id: str, user: dict = Depends(get_current_user)):
    """Resume a paused session."""
    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    _session_state[session_id] = "running"
    await _broadcast(session_id, {"type": "session_state", "state": "running"})
    logger.info("Session %s resumed", session_id[:8])
    return {"ok": True, "state": "running"}


@app.post("/api/sessions/{session_id}/stop")
async def stop_session(session_id: str, user: dict = Depends(get_current_user)):
    """Stop a session — kills any running Claude process and halts the chain."""
    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    _session_state[session_id] = "stopped"
    aborted = await claude.abort_session(session_id)
    # Also abort any running orchestrated scan
    orch = _active_scans.get(session_id)
    if orch:
        orch.abort()
    await _broadcast(session_id, {
        "type": "session_state",
        "state": "stopped",
        "message": "Session stopped" + (" — AI process killed" if aborted else ""),
    })
    logger.info("Session %s stopped (process killed: %s)", session_id[:8], aborted)
    return {"ok": True, "state": "stopped", "process_killed": aborted}


@app.get("/api/sessions/{session_id}/state")
async def get_session_state(session_id: str, user: dict = Depends(get_current_user)):
    """Get current flow-control state for a session."""
    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session_id,
        "state": _session_state.get(session_id, "running"),
        "busy": claude.is_busy(session_id),
    }


# ---------------------------------------------------------------------------
# REST endpoints — Orchestrated Scan
# ---------------------------------------------------------------------------


async def _run_orchestrated_scan(session_id: str) -> None:
    """Background task: run a full orchestrated scan for a session."""
    session = await db.get_session(session_id)
    if session is None:
        return

    # Wait for at least one WS client (up to 10s)
    for _ in range(20):
        if _ws_connections.get(session_id):
            break
        await asyncio.sleep(0.5)

    project = await db.get_project(session.project_id) if session.project_id else None
    scope = project.scope if project else [session.target]
    client = project.client if project else ""

    await _broadcast(session_id, {
        "type": "scan_status",
        "status": "starting",
        "message": f"Starting orchestrated scan of {session.target}...",
    })

    async def on_progress(p: ScanProgress) -> None:
        await _broadcast(session_id, {
            "type": "scan_progress",
            "round": p.round_num,
            "total_rounds": p.total_rounds,
            "phase": p.phase,
            "tasks_total": p.tasks_total,
            "tasks_completed": p.tasks_completed,
            "task_name": p.task_name,
            "task_status": p.task_status,
            "message": p.message,
        })

    async def plan_fn(sid: str, message: str) -> str:
        result = await claude.plan_stream(sid, message)
        usage = claude.get_token_usage(session_id)
        total_in = usage.get("input_tokens", 0)
        total_out = usage.get("output_tokens", 0)
        await _broadcast_token_usage(session_id, TokenUsageUpdate(
            input_tokens=0, output_tokens=0,
            cumulative_input=total_in, cumulative_output=total_out,
        ))
        return result

    from models import Severity, LeadCategory

    async def _capture_finding_screenshots(finding: "Finding", target: str) -> None:
        """Capture screenshots for a finding's evidence URLs (runs in background)."""
        try:
            paths = await capture_evidence(
                finding.evidence or "",
                target,
                finding.session_id,
                finding.id,
            )
            if paths:
                paths_str = "|".join(paths)
                await db.update_finding_screenshots(finding.id, paths_str)
                logger.info("Screenshots captured for finding %s: %d images", finding.id[:8], len(paths))
        except Exception as exc:
            logger.warning("Screenshot capture failed for finding %s: %s", finding.id[:8], exc)

    saved_finding_count = 0
    saved_lead_count = 0

    async def on_finding(f_data: dict) -> None:
        nonlocal saved_finding_count
        try:
            title = f_data.get("title", "Untitled")
            if await db.finding_exists(session_id, title):
                logger.info("Skipping duplicate finding: %s", title)
                return

            severity_val = f_data.get("severity", "info")
            try:
                severity = Severity(severity_val)
            except ValueError:
                severity = Severity.info

            finding = Finding(
                session_id=session_id,
                title=title,
                severity=severity,
                description=f_data.get("description", ""),
                evidence=f_data.get("evidence"),
                remediation=f_data.get("remediation"),
            )
            await db.create_finding(finding)
            await _broadcast(session_id, {
                "type": "finding",
                "finding": finding.model_dump(mode="json"),
            })
            saved_finding_count += 1
            logger.info("Scan finding [%s]: %s (%s)", finding.id[:8], finding.title, finding.severity.value)

            # Capture screenshots in background (non-blocking)
            if finding.evidence:
                asyncio.create_task(_capture_finding_screenshots(finding, session.target))
        except Exception as exc:
            logger.exception("Error saving scan finding: %s", exc)

    async def on_lead(l_data: dict) -> None:
        nonlocal saved_lead_count
        try:
            title = l_data.get("title", "Untitled")
            if await db.lead_exists(session_id, title):
                logger.info("Skipping duplicate lead: %s", title)
                return

            raw_cat = l_data.get("category", "other")
            try:
                category = LeadCategory(raw_cat)
            except ValueError:
                category = LeadCategory.other

            lead = Lead(
                session_id=session_id,
                title=title,
                category=category,
                description=l_data.get("description", ""),
            )
            await db.create_lead(lead)
            await _broadcast(session_id, {
                "type": "lead",
                "lead": lead.model_dump(mode="json"),
            })
            saved_lead_count += 1
            logger.info("Scan lead [%s]: %s", lead.id[:8], lead.title)
        except Exception as exc:
            logger.exception("Error saving scan lead: %s", exc)

    async def on_command(cmd_data: dict) -> None:
        """Persist each tool execution from the orchestrator to the commands table."""
        try:
            from models import RiskLevel, CommandStatus
            risk_map = {"low": RiskLevel.low, "medium": RiskLevel.medium, "high": RiskLevel.high}
            status_map = {"completed": CommandStatus.executed, "failed": CommandStatus.rejected, "skipped": CommandStatus.rejected}
            cmd = PendingCommand(
                session_id=session_id,
                command=cmd_data.get("command", "unknown"),
                reason=cmd_data.get("reason", ""),
                risk_level=risk_map.get(cmd_data.get("risk_level", "low"), RiskLevel.low),
                phase=cmd_data.get("phase", "recon"),
                status=status_map.get(cmd_data.get("status", "completed"), CommandStatus.executed),
                output=cmd_data.get("output", ""),
                exit_code=cmd_data.get("exit_code", -1),
            )
            await db.create_command(cmd)
            await _broadcast(session_id, {
                "type": "command_complete",
                "command": cmd.model_dump(mode="json"),
            })
        except Exception as exc:
            logger.warning("Error saving scan command: %s", exc)

    async def on_authorize(tool: str, command: str, reason: str) -> bool:
        """Ask the operator to approve a destructive command via WebSocket."""
        import uuid as _uuid
        auth_id = str(_uuid.uuid4())[:8]
        event = asyncio.Event()
        _pending_authorizations[auth_id] = event
        _authorization_results[auth_id] = False

        await _broadcast(session_id, {
            "type": "authorization_request",
            "auth_id": auth_id,
            "tool": tool,
            "command": command,
            "reason": reason,
            "message": f"Destructive operation detected. Approve execution?",
        })

        try:
            await asyncio.wait_for(event.wait(), timeout=120)
        except asyncio.TimeoutError:
            logger.warning("Authorization timeout for %s", auth_id)
            await _broadcast(session_id, {
                "type": "authorization_timeout",
                "auth_id": auth_id,
                "message": "Authorization timed out — command skipped.",
            })
            return False
        finally:
            _pending_authorizations.pop(auth_id, None)
            result = _authorization_results.pop(auth_id, False)

        return result

    # Load profile tool filter if set
    allowed_tools = None
    if session.profile_id:
        profile = await db.get_profile(session.profile_id)
        if profile and profile.tools:
            allowed_tools = profile.tools
            logger.info("Scan using profile '%s': %d tools", profile.name, len(allowed_tools))

    orchestrator = ScanOrchestrator(
        registry=tool_registry,
        plan_fn=plan_fn,
        scope=scope,
        on_authorize=on_authorize,
        allowed_tools=allowed_tools,
    )
    _active_scans[session_id] = orchestrator

    try:
        result = await orchestrator.run(
            session_id=session_id,
            target=session.target,
            client=client,
            on_progress=on_progress,
            on_finding=on_finding,
            on_lead=on_lead,
            on_command=on_command,
        )

        # Broadcast completion
        await _broadcast(session_id, {
            "type": "scan_status",
            "status": "completed",
            "message": f"Scan complete: {result.get('rounds', 0)} rounds, "
                       f"{saved_finding_count} findings, "
                       f"{saved_lead_count} leads.",
            "summary": result.get("analysis", ""),
        })

        # Send summary as assistant message
        summary_lines = [
            f"**Orchestrated scan complete** — {result.get('rounds', 0)} rounds, "
            f"{result.get('tools_run', 0)} tools executed.",
        ]
        if saved_finding_count:
            summary_lines.append(f"\n**{saved_finding_count} findings** recorded.")
        if saved_lead_count:
            summary_lines.append(f"\n**{saved_lead_count} leads** for further investigation.")
        if result.get("analysis"):
            summary_lines.append(f"\n**Analysis:** {result['analysis']}")

        summary_text = "\n".join(summary_lines)
        await _broadcast(session_id, {
            "type": "message",
            "role": "assistant",
            "content": summary_text,
            "streaming": False,
        })
        msg = Message(session_id=session_id, role=MessageRole.assistant, content=summary_text)
        await db.add_message(msg)

    except Exception as exc:
        logger.exception("Orchestrated scan failed for session %s", session_id[:8])
        await _broadcast(session_id, {
            "type": "scan_status",
            "status": "error",
            "message": f"Scan error: {exc}",
        })
        await _broadcast(session_id, {
            "type": "error",
            "message": f"Orchestrated scan failed: {exc}",
        })
    finally:
        _active_scans.pop(session_id, None)


@app.post("/api/sessions/{session_id}/scan")
async def start_scan(session_id: str, user: dict = Depends(get_current_user)):
    """Start an orchestrated parallel scan for a session."""
    session = await db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    if session_id in _active_scans:
        raise HTTPException(status_code=409, detail="Scan already running for this session")

    asyncio.create_task(_run_orchestrated_scan(session_id))
    logger.info("Orchestrated scan started for session %s: %s", session_id[:8], session.target)
    return {"ok": True, "session_id": session_id, "message": "Orchestrated scan started"}


@app.post("/api/sessions/{session_id}/scan/abort")
async def abort_scan(session_id: str, user: dict = Depends(get_current_user)):
    """Abort a running orchestrated scan."""
    orch = _active_scans.get(session_id)
    if orch is None:
        raise HTTPException(status_code=404, detail="No active scan for this session")
    orch.abort()
    logger.info("Scan abort requested for session %s", session_id[:8])
    return {"ok": True, "message": "Scan abort requested"}


@app.post("/api/sessions/{session_id}/scan/skip/{tool_name}")
async def skip_tool(session_id: str, tool_name: str, user: dict = Depends(get_current_user)):
    """Skip a running tool during an orchestrated scan."""
    orch = _active_scans.get(session_id)
    if orch is None:
        raise HTTPException(status_code=404, detail="No active scan for this session")
    skipped = orch.skip_tool(tool_name)
    if skipped:
        logger.info("Skipping tool %s in session %s", tool_name, session_id[:8])
        return {"ok": True, "message": f"Skipping {tool_name}"}
    raise HTTPException(status_code=404, detail=f"Tool {tool_name} is not currently running")


@app.get("/api/tools")
async def list_tools(user: dict = Depends(get_current_user)):
    """List all available Kali tools in the registry."""
    all_tools = tool_registry.list_tools()
    return {
        "tools": [
            {**t.schema_for_claude(), "installed": t.is_available(),
             "is_custom": getattr(t, "is_custom", False)}
            for t in all_tools
        ],
        "total": len(all_tools),
    }


# ---------------------------------------------------------------------------
# REST endpoints — Scan Profiles
# ---------------------------------------------------------------------------

@app.get("/api/profiles")
async def list_profiles(user: dict = Depends(get_current_user)):
    profiles = await db.get_profiles()
    return [p.model_dump(mode="json") for p in profiles]


@app.get("/api/profiles/{profile_id}")
async def get_profile(profile_id: str, user: dict = Depends(get_current_user)):
    profile = await db.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile.model_dump(mode="json")


@app.post("/api/profiles")
async def create_profile(req: CreateProfileRequest, user: dict = Depends(get_current_user)):
    profile = ScanProfile(name=req.name, description=req.description, tools=req.tools)
    await db.create_profile(profile)
    return profile.model_dump(mode="json")


@app.put("/api/profiles/{profile_id}")
async def update_profile(profile_id: str, req: UpdateProfileRequest, user: dict = Depends(get_current_user)):
    profile = await db.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    if profile.is_default:
        raise HTTPException(status_code=403, detail="Cannot edit default profiles")
    await db.update_profile(profile_id, name=req.name, description=req.description, tools=req.tools)
    updated = await db.get_profile(profile_id)
    return updated.model_dump(mode="json")


@app.delete("/api/profiles/{profile_id}")
async def delete_profile(profile_id: str, user: dict = Depends(get_current_user)):
    ok = await db.delete_profile(profile_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot delete default profiles or profile not found")
    return {"ok": True}


# ---------------------------------------------------------------------------
# REST endpoints — Custom Tools
# ---------------------------------------------------------------------------

@app.get("/api/custom-tools")
async def list_custom_tools(user: dict = Depends(get_current_user)):
    tools = await db.get_custom_tools()
    return [t.model_dump(mode="json") for t in tools]


@app.post("/api/custom-tools")
async def create_custom_tool(req: CreateCustomToolRequest, user: dict = Depends(get_current_user)):
    existing = tool_registry.get(req.name)
    if existing and not getattr(existing, "is_custom", False):
        raise HTTPException(status_code=409, detail=f"Tool name '{req.name}' conflicts with a built-in tool")
    tool = CustomTool(
        name=req.name, display_name=req.display_name, description=req.description,
        category=req.category, binary_path=req.binary_path, args_template=req.args_template,
        risk=req.risk, timeout=req.timeout,
    )
    await db.create_custom_tool(tool)
    tool_registry.register(CustomCliTool(
        name=tool.name, binary=tool.binary_path, description=tool.description,
        category=tool.category, risk=tool.risk, timeout=tool.timeout,
        args_template=tool.args_template, display_name=tool.display_name,
    ))
    logger.info("Custom tool registered: %s (%s)", tool.name, tool.binary_path)
    return tool.model_dump(mode="json")


@app.put("/api/custom-tools/{tool_id}")
async def update_custom_tool(tool_id: str, req: UpdateCustomToolRequest, user: dict = Depends(get_current_user)):
    existing = await db.get_custom_tool(tool_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Custom tool not found")
    if req.name and req.name != existing.name:
        builtin = tool_registry.get(req.name)
        if builtin and not getattr(builtin, "is_custom", False):
            raise HTTPException(status_code=409, detail=f"Tool name '{req.name}' conflicts with a built-in tool")
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    await db.update_custom_tool(tool_id, **updates)
    tool_registry.unregister(existing.name)
    updated = await db.get_custom_tool(tool_id)
    tool_registry.register(CustomCliTool(
        name=updated.name, binary=updated.binary_path, description=updated.description,
        category=updated.category, risk=updated.risk, timeout=updated.timeout,
        args_template=updated.args_template, display_name=updated.display_name,
    ))
    return updated.model_dump(mode="json")


@app.delete("/api/custom-tools/{tool_id}")
async def delete_custom_tool(tool_id: str, user: dict = Depends(get_current_user)):
    existing = await db.get_custom_tool(tool_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Custom tool not found")
    ok = await db.delete_custom_tool(tool_id)
    if ok:
        tool_registry.unregister(existing.name)
        logger.info("Custom tool removed: %s", existing.name)
    return {"ok": ok}


# ---------------------------------------------------------------------------
# REST endpoints — Settings / Status
# ---------------------------------------------------------------------------

@app.get("/api/status")
async def get_status():
    """Check Claude CLI availability and auth status."""
    import shutil

    claude_bin = shutil.which("claude") or "claude"
    found = shutil.which("claude") is not None

    if not found:
        return {
            "claude_found": False,
            "claude_path": None,
            "authenticated": False,
            "error": "Claude CLI not found in PATH. Install it: npm install -g @anthropic-ai/claude-code",
            "model": None,
        }

    try:
        from claude_client import _clean_env
        clean_env = _clean_env()
        proc = await asyncio.create_subprocess_exec(
            claude_bin, "-p", "--output-format", "json",
            "--max-turns", "1",
            "Reply with exactly: HADES_OK",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=clean_env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")

        if proc.returncode == 0 and "HADES_OK" in stdout_text:
            model = None
            try:
                import json as _json
                data = _json.loads(stdout_text)
                model = data.get("model")
            except Exception:
                pass
            return {
                "claude_found": True,
                "claude_path": claude_bin,
                "authenticated": True,
                "error": None,
                "model": model,
            }

        raw_error = stderr_text.strip() or stdout_text.strip() or f"Exit code {proc.returncode}"
        error_msg = raw_error
        try:
            import json as _json
            parsed = _json.loads(raw_error)
            error_msg = parsed.get("result") or raw_error
        except Exception:
            pass
        is_auth_error = any(kw in error_msg.lower() for kw in ["api key", "auth", "login", "unauthorized", "credential"])

        return {
            "claude_found": True,
            "claude_path": claude_bin,
            "authenticated": False,
            "error": error_msg[:500],
            "auth_hint": "Run 'claude login' in your terminal to authenticate" if is_auth_error else None,
            "model": None,
        }

    except asyncio.TimeoutError:
        return {
            "claude_found": True,
            "claude_path": claude_bin,
            "authenticated": False,
            "error": "Claude CLI timed out (30s). It may be waiting for input or stuck.",
            "model": None,
        }
    except Exception as exc:
        return {
            "claude_found": True,
            "claude_path": claude_bin,
            "authenticated": False,
            "error": str(exc)[:500],
            "model": None,
        }


@app.get("/api/skills")
async def list_skills(user: dict = Depends(get_current_user)):
    """List available pentest phases and skill categories."""
    return {
        "phases": [
            {
                "id": "recon",
                "name": "Reconnaissance",
                "description": "Passive information gathering (OSINT, DNS, WHOIS)",
                "tools": ["whois", "dig", "nslookup", "theHarvester", "amass", "subfinder"],
            },
            {
                "id": "scanning",
                "name": "Scanning",
                "description": "Active network and port scanning",
                "tools": ["nmap", "masscan", "rustscan"],
            },
            {
                "id": "enumeration",
                "name": "Enumeration",
                "description": "Service enumeration and vulnerability detection",
                "tools": ["nuclei", "nikto", "gobuster", "ffuf", "enum4linux", "smbclient"],
            },
            {
                "id": "exploitation",
                "name": "Exploitation",
                "description": "Vulnerability exploitation and access attempts",
                "tools": ["sqlmap", "hydra", "metasploit", "searchsploit"],
            },
            {
                "id": "post_exploitation",
                "name": "Post-Exploitation",
                "description": "Privilege escalation, lateral movement, data exfiltration",
                "tools": ["linpeas", "winpeas", "mimikatz", "bloodhound"],
            },
            {
                "id": "reporting",
                "name": "Reporting",
                "description": "Compile findings into a penetration test report",
                "tools": [],
            },
        ],
    }


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """Main chat WebSocket connection for a pentest session."""
    # Validate token from query parameter
    token = websocket.query_params.get("token", "")
    if not token:
        await websocket.close(code=4001, reason="Missing token")
        return
    try:
        decode_token(token)
    except Exception:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    # Verify session exists
    session = await db.get_session(session_id)
    if session is None:
        await websocket.close(code=4004, reason="Session not found")
        return

    await websocket.accept()

    # Register connection
    if session_id not in _ws_connections:
        _ws_connections[session_id] = []
    _ws_connections[session_id].append(websocket)

    # Load conversation history into Claude client
    messages = await db.get_messages(session_id)
    claude.load_history(session_id, messages)

    logger.info("WebSocket connected for session %s", session_id[:8])

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "message": "Invalid JSON"})
                continue

            msg_type = data.get("type", "")

            if msg_type == "message":
                content = data.get("content", "").strip()
                if not content:
                    await websocket.send_json({"type": "error", "message": "Empty message"})
                    continue
                # Process in background so the receive loop stays responsive
                task = asyncio.create_task(_handle_user_message(session_id, content))
                task.add_done_callback(
                    lambda t: t.exception() and logger.error("Chat task failed: %s", t.exception())
                )

            elif msg_type == "authorization_response":
                auth_id = data.get("auth_id", "")
                approved = data.get("approved", False)
                if auth_id in _pending_authorizations:
                    _authorization_results[auth_id] = approved
                    _pending_authorizations[auth_id].set()
                    logger.info("Authorization %s: %s", auth_id, "APPROVED" if approved else "DENIED")
                else:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Authorization {auth_id} not found or already expired",
                    })

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

            else:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Unknown message type: {msg_type}",
                })

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected for session %s", session_id[:8])
    except Exception as exc:
        logger.exception("WebSocket error for session %s", session_id[:8])
    finally:
        # Unregister connection
        try:
            _ws_connections[session_id].remove(websocket)
            if not _ws_connections[session_id]:
                del _ws_connections[session_id]
        except (ValueError, KeyError):
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Static file serving + SPA fallback (MUST be after all API routes)
# ---------------------------------------------------------------------------

_frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _frontend_dist.is_dir():
    from fastapi.responses import FileResponse

    app.mount("/assets", StaticFiles(directory=str(_frontend_dist / "assets")), name="static-assets")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        """Serve index.html for all non-API routes (SPA client-side routing)."""
        file_path = _frontend_dist / full_path
        if full_path and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(_frontend_dist / "index.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
        log_level="info",
    )
