"""HADES Scan Orchestrator — parallel tool execution driven by AI planning."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

from executor import check_destructive, check_destructive_scope
from tools.base import ToolRegistry, ToolResult
from waf_bypass import BrowserSession

logger = logging.getLogger("hades.orchestrator")

_MAX_ROUNDS = 15
_MAX_PARALLEL_TOOLS = 6
_MAX_RESULT_CHARS_PER_TOOL = 8000
_MAX_RESULT_CHARS_EXEC = 20000

_KNOWN_BACKEND_PATTERNS = [
    'supabase.co', 'supabase.com', 'firebaseio.com', 'firebase.com',
    'firebaseapp.com', 'hubspot.com', 'hubapi.com', 'auth0.com', 'okta.com',
    'amazonaws.com', 'cloudfront.net', 'azurewebsites.net', 'azure-api.net',
    'herokuapp.com', 'vercel.app', 'netlify.app', 'render.com',
    'sentry.io', 'segment.io', 'segment.com', 'stripe.com',
    'graphql', 'api.', 'cdn.', 'storage.googleapis.com',
    'cloudfunctions.net', 'run.app', 'appspot.com',
    'powerbi.com', 'tinybird.co', 'resend.com', 'clerk.dev',
    'clerk.com', 'postmark.com', 'sendgrid.net', 'twilio.com',
    'algolia.net', 'algolia.com', 'meilisearch.com',
]


@dataclass
class ScanTask:
    tool: str
    params: dict[str, Any] = field(default_factory=dict)
    priority: int = 1
    reason: str = ""


@dataclass
class ScanPlan:
    analysis: str = ""
    tasks: list[ScanTask] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    leads: list[dict] = field(default_factory=list)
    phase: str = "recon"
    done: bool = False
    done_reason: str = ""


@dataclass
class ScanProgress:
    round_num: int
    total_rounds: int
    phase: str
    tasks_total: int
    tasks_completed: int
    task_name: str = ""
    task_status: str = ""  # running, completed, failed
    message: str = ""


ProgressCallback = Callable[[ScanProgress], Coroutine]
FindingCallback = Callable[[dict], Coroutine]
LeadCallback = Callable[[dict], Coroutine]
CommandCallback = Callable[[dict], Coroutine]

_WAF_SIGNATURES = [
    "security checkpoint", "vercel security", "cloudflare", "captcha",
    "challenge-platform", "ray id", "attention required", "access denied",
    "403 forbidden", "bot detection", "please verify", "checking your browser",
    "ddos protection", "incapsula", "sucuri", "akamai", "blocked by",
    "waf", "web application firewall",
]


def _summarize_result(result: ToolResult) -> str:
    """Build a token-efficient summary of a tool result for Claude.

    Strategy: exploitation tools (exec, curl, smart probes) get full output
    because Claude needs response bodies to find vulns. Scanning tools get
    minimal output unless they found something interesting.
    """
    exploit_tools = ("exec", "curl", "sqli_probe", "xss_probe", "idor_probe",
                     "cors_probe", "lfi_probe", "redirect_probe", "js_analyze")
    is_exploit = result.tool in exploit_tools
    max_chars = _MAX_RESULT_CHARS_EXEC if is_exploit else _MAX_RESULT_CHARS_PER_TOOL

    parts = [f"## {result.tool} → {result.target} (exit={result.exit_code}, {result.duration:.1f}s)"]

    if result.error:
        parts.append(f"ERROR: {result.error}")
        msg = "\n".join(parts)
        if len(msg) > 80000:
            msg = msg[:80000] + "\n[results truncated for token efficiency]"
        return msg

    if result.summary:
        parts.append(result.summary)

    if result.findings:
        parts.append(f"\nFindings ({len(result.findings)}):")
        for f in result.findings[:30]:
            parts.append(f"  - {json.dumps(f)}")
        if len(result.findings) > 30:
            parts.append(f"  ... +{len(result.findings) - 30} more")

    # Token optimization: only include raw output when it matters
    has_useful_output = (
        is_exploit
        or result.findings
        or result.exit_code != 0
        or (result.raw_output and any(kw in result.raw_output.lower() for kw in (
            "api", "key", "token", "secret", "password", "admin", "auth",
            "supabase", "firebase", "graphql", "error", "exception", "sql",
            "vulnerable", "injection", "xss", "upload",
        )))
    )

    if result.raw_output and has_useful_output:
        budget = max_chars - len("\n".join(parts)) - 50
        if budget > 500:
            raw = result.raw_output[:budget]
            if len(result.raw_output) > budget:
                raw += f"\n[truncated — {len(result.raw_output)} total]"
            parts.append(f"\nRaw output:\n{raw}")
    elif result.raw_output and not has_useful_output:
        parts.append(f"\n[Raw output suppressed — {len(result.raw_output)} chars, no interesting patterns. Use exec to re-fetch if needed.]")

    text = "\n".join(parts)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n[truncated]"
    return text


def _validate_target_in_scope(target: str, scope: list[str]) -> bool:
    """Basic scope guard — check if target matches any scope entry."""
    if not scope:
        return True
    target_lower = target.lower().strip()
    for entry in scope:
        entry_lower = entry.lower().strip()
        if entry_lower in target_lower or target_lower in entry_lower:
            return True
        if target_lower.endswith("." + entry_lower):
            return True
    return False


def _extract_hosts_from_output(text: str) -> set[str]:
    """Extract hostnames/URLs from tool output that may be backend infrastructure."""
    hosts: set[str] = set()
    for m in re.finditer(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', text):
        hosts.add(m.group(1).lower())
    return hosts


def _extract_json_object(text: str) -> str | None:
    """Extract the outermost JSON object from text, handling braces inside strings."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        c = text[i]
        if escape:
            escape = False
            continue
        if c == '\\' and in_string:
            escape = True
            continue
        if c == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:] if depth > 0 else None


def parse_plan_json(text: str) -> ScanPlan:
    """Extract a JSON plan from Claude's response (may be wrapped in markdown)."""
    # Try to find JSON block in markdown code fence
    json_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if json_match:
        text = json_match.group(1)

    raw_json = _extract_json_object(text)
    if not raw_json:
        return ScanPlan(analysis="Failed to parse plan — no JSON found", done=True)

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        # Try fixing common issues: trailing commas, unescaped control chars, newlines in strings
        fixed = re.sub(r',\s*([}\]])', r'\1', raw_json)
        fixed = re.sub(r'(?<=": ")([^"]*?)(?<!\\)\n([^"]*?)(?=")', r'\1\\n\2', fixed)
        fixed = fixed.replace('\t', '\\t').replace('\r', '\\r')
        # Try truncating at last valid closing brace if JSON was cut off
        for attempt in (fixed, fixed.rstrip() + '}', fixed.rstrip() + ']}'):
            try:
                data = json.loads(attempt)
                break
            except json.JSONDecodeError:
                continue
        else:
            logger.warning("Failed to parse plan JSON, raw length=%d", len(raw_json))
            logger.debug("Raw JSON start: %.500s", raw_json)
            return ScanPlan(analysis="JSON parse error — retrying next round", done=False)

    tasks = []
    for t in data.get("tasks", []):
        tasks.append(ScanTask(
            tool=t.get("tool", ""),
            params=t.get("params", {}),
            priority=t.get("priority", 1),
            reason=t.get("reason", ""),
        ))

    return ScanPlan(
        analysis=data.get("analysis", ""),
        tasks=tasks,
        findings=data.get("findings", []),
        leads=data.get("leads", []),
        phase=data.get("phase", "recon"),
        done=data.get("done", False),
        done_reason=data.get("done_reason", ""),
    )


class ScanOrchestrator:
    """Drives a parallel-tool scan loop: plan → execute → analyze → repeat."""

    def __init__(
        self,
        registry: ToolRegistry,
        plan_fn: Callable,
        scope: list[str] | None = None,
        on_authorize: Callable | None = None,
        allowed_tools: list[str] | None = None,
    ):
        self._registry = registry
        self._plan_fn = plan_fn  # async fn(session_id, message) -> str
        self._scope = scope or []
        self._discovered_hosts: set[str] = set()
        self._aborted = False
        self._running_tasks: dict[str, asyncio.Task] = {}
        self._on_authorize = on_authorize  # async fn(tool, command, reason) -> bool
        self._waf_cookies: str = ""  # Cookie header from WAF bypass
        self._waf_user_agent: str = ""  # UA that passed the challenge
        self._browser: BrowserSession | None = None  # Persistent browser for WAF bypass
        self._allowed_tools: set[str] | None = set(allowed_tools) if allowed_tools else None

    def _is_in_scope(self, host_or_cmd: str, is_exec: bool = False) -> bool:
        """Check scope including discovered infrastructure hosts."""
        full_scope = list(self._scope) + list(self._discovered_hosts)
        if is_exec:
            return not full_scope or any(s.lower() in host_or_cmd.lower() for s in full_scope)
        return _validate_target_in_scope(host_or_cmd, full_scope)

    def _expand_scope_from_output(self, results: list[ToolResult]) -> None:
        """Auto-expand scope with backend hosts discovered in tool output."""
        if not self._scope:
            return
        for r in results:
            if not r.raw_output:
                continue
            hosts = _extract_hosts_from_output(r.raw_output)
            for host in hosts:
                if host in self._discovered_hosts or host in (s.lower() for s in self._scope):
                    continue
                # Accept hosts that are clearly backend infrastructure:
                # - supabase.co, firebase, hubspot, auth0, okta, etc.
                # - hosts referenced from target's JS/HTML
                if any(b in host for b in _KNOWN_BACKEND_PATTERNS):
                    self._discovered_hosts.add(host)
                    logger.info("Scope auto-expanded: %s (discovered from %s output)", host, r.tool)

    def abort(self):
        self._aborted = True
        for task in self._running_tasks.values():
            task.cancel()
        self._running_tasks.clear()
        if self._browser:
            asyncio.ensure_future(self._browser.stop())
            self._browser = None

    def skip_tool(self, tool_name: str) -> bool:
        task = self._running_tasks.get(tool_name)
        if task and not task.done():
            task.cancel()
            logger.info("Skipping tool: %s", tool_name)
            return True
        return False

    async def run(
        self,
        session_id: str,
        target: str,
        client: str,
        on_progress: ProgressCallback | None = None,
        on_finding: FindingCallback | None = None,
        on_lead: LeadCallback | None = None,
        on_command: CommandCallback | None = None,
    ) -> list[dict]:
        """Run a full orchestrated scan. Returns all collected findings."""
        all_findings: list[dict] = []
        all_leads: list[dict] = []
        all_results: list[ToolResult] = []
        round_num = 0
        waf_detected = False

        catalog = self._registry.catalog_for_claude()
        if self._allowed_tools:
            catalog = [t for t in catalog if t["name"] in self._allowed_tools]
            logger.info("Profile filter active: %d tools allowed", len(catalog))

        logger.info("Starting orchestrated scan for %s (round 1 — deterministic recon)", target)

        if on_progress:
            await on_progress(ScanProgress(
                round_num=0, total_rounds=_MAX_ROUNDS,
                phase="recon", tasks_total=0, tasks_completed=0,
                message="Iniciando reconhecimento inicial...",
                task_status="thinking",
            ))

        # Round 1 is DETERMINISTIC — always run the same recon tools
        # so results are consistent between scans.
        plan = self._build_deterministic_round1(target)
        if self._allowed_tools:
            plan.tasks = [t for t in plan.tasks if t.tool in self._allowed_tools]
        logger.info("Round 1 plan: %d fixed recon tasks", len(plan.tasks))

        async def _emit_findings_leads(plan: ScanPlan) -> None:
            for f in plan.findings:
                if isinstance(f, dict):
                    all_findings.append(f)
                    if on_finding:
                        await on_finding(f)
            for l in plan.leads:
                if isinstance(l, dict):
                    all_leads.append(l)
                    if on_lead:
                        await on_lead(l)
                    # Auto-expand scope from lead descriptions
                    desc = l.get("description", "") + " " + l.get("title", "")
                    for host in _extract_hosts_from_output(desc):
                        if host not in self._discovered_hosts and host not in (s.lower() for s in self._scope):
                            if any(b in host for b in _KNOWN_BACKEND_PATTERNS):
                                self._discovered_hosts.add(host)
                                logger.info("Scope auto-expanded from lead: %s", host)

        while round_num < _MAX_ROUNDS and not plan.done and not self._aborted:
            round_num += 1

            if not plan.tasks:
                if "JSON parse error" in plan.analysis:
                    recovered = False
                    for attempt in range(1, 4):
                        logger.warning("Round %d: JSON parse error, retry %d/3", round_num, attempt)
                        retry_msg = (
                            "Your last response had invalid JSON. Respond with ONLY the raw JSON object — "
                            "no markdown, no code fences, no commentary. Start with { and end with }."
                        )
                        plan_text = await self._plan_fn(session_id, retry_msg)
                        plan = parse_plan_json(plan_text)
                        await _emit_findings_leads(plan)
                        if plan.tasks or plan.done:
                            recovered = True
                            break
                    if not recovered:
                        logger.info("Round %d: 3 JSON retries failed, ending scan", round_num)
                        break
                else:
                    logger.info("Round %d: no tasks planned, scan complete", round_num)
                    break

            if self._allowed_tools:
                before = len(plan.tasks)
                plan.tasks = [t for t in plan.tasks if t.tool in self._allowed_tools]
                if len(plan.tasks) < before:
                    logger.info("Profile filter: %d/%d tasks kept", len(plan.tasks), before)

            if on_progress:
                await on_progress(ScanProgress(
                    round_num=round_num, total_rounds=_MAX_ROUNDS,
                    phase=plan.phase, tasks_total=len(plan.tasks),
                    tasks_completed=0, message=plan.analysis,
                    task_status="executing",
                ))

            # Group tasks by priority
            priority_groups: dict[int, list[ScanTask]] = {}
            for task in plan.tasks:
                priority_groups.setdefault(task.priority, []).append(task)

            round_results: list[ToolResult] = []

            for priority in sorted(priority_groups.keys()):
                if self._aborted:
                    break

                group = priority_groups[priority]
                # Execute group in parallel (bounded)
                sem = asyncio.Semaphore(_MAX_PARALLEL_TOOLS)

                async def _run_task(task: ScanTask) -> ToolResult | None:
                    async with sem:
                        if self._aborted:
                            return None
                        tool_def = self._registry.get(task.tool)
                        if not tool_def:
                            logger.warning("Unknown tool: %s", task.tool)
                            return ToolResult(
                                tool=task.tool, target=target, success=False,
                                summary=f"Unknown tool: {task.tool}",
                                raw_output="", error="Tool not found in registry",
                            )

                        params = dict(task.params)
                        task_target = params.pop("target", target)
                        if task.tool == "curl" and "url" in params:
                            task_target = params.get("url", task_target)
                        elif task.tool != "exec":
                            task_target = params.pop("url", task_target)

                        # Inject WAF bypass cookies into exec/curl commands
                        if self._waf_cookies and task.tool == "exec":
                            cmd = params.get("command", "")
                            if "curl" in cmd and "-H 'Cookie:" not in cmd and '-H "Cookie:' not in cmd:
                                cookie_flag = f" -H 'Cookie: {self._waf_cookies}'"
                                ua_flag = f" -H 'User-Agent: {self._waf_user_agent}'" if self._waf_user_agent else ""
                                # Insert headers before the URL (last argument)
                                params["command"] = cmd + cookie_flag + ua_flag
                        if self._waf_cookies and task.tool == "curl":
                            if "headers" not in params:
                                params["headers"] = {}
                            params["headers"]["Cookie"] = self._waf_cookies
                            if self._waf_user_agent:
                                params["headers"]["User-Agent"] = self._waf_user_agent

                        # Scope guard: for exec, check that command references in-scope target
                        if task.tool == "exec":
                            cmd = params.get("command", "")
                            scope_ok = self._is_in_scope(cmd, is_exec=True)
                        else:
                            scope_ok = self._is_in_scope(task_target)

                        if not scope_ok:
                            scope_target = params.get("command", task_target) if task.tool == "exec" else task_target
                            logger.warning("Scope violation: %s not in %s + %s", scope_target[:100], self._scope, list(self._discovered_hosts)[:5])
                            return ToolResult(
                                tool=task.tool, target=task_target, success=False,
                                summary=f"BLOCKED: '{scope_target[:80]}' targets a host outside scope. Allowed: {', '.join(self._scope + list(self._discovered_hosts)[:10])}",
                                raw_output="", error="Scope violation",
                            )

                        if task.tool == "exec":
                            cmd = params.get("command", "")
                            destructive_warning, is_mass = check_destructive_scope(cmd)
                            if destructive_warning:
                                if is_mass:
                                    # Auto-block mass operations — no auth modal
                                    logger.warning("Auto-blocking mass destructive command: %s", cmd[:200])
                                    return ToolResult(
                                        tool=task.tool, target=task_target, success=False,
                                        summary=f"BLOCKED: mass destructive operation. Use single-target operations (e.g., add WHERE id=X or LIMIT 1). Command: {cmd[:120]}",
                                        raw_output="", error="Mass destructive operation blocked",
                                    )
                                elif self._on_authorize:
                                    logger.info("Destructive command needs authorization: %s", cmd[:200])
                                    approved = await self._on_authorize(task.tool, cmd, task.reason)
                                    if not approved:
                                        logger.info("User DENIED destructive command: %s", cmd[:100])
                                        return ToolResult(
                                            tool=task.tool, target=task_target, success=False,
                                            summary=f"DENIED by operator: {destructive_warning}",
                                            raw_output="", error="Denied by operator",
                                        )
                                    logger.info("User APPROVED destructive command: %s", cmd[:100])
                                else:
                                    logger.warning("Blocking destructive command (no auth handler): %s", cmd[:200])
                                    return ToolResult(
                                        tool=task.tool, target=task_target, success=False,
                                        summary=f"BLOCKED: {destructive_warning}",
                                        raw_output="", error="Destructive operation blocked",
                                    )

                        if on_progress:
                            await on_progress(ScanProgress(
                                round_num=round_num, total_rounds=_MAX_ROUNDS,
                                phase=plan.phase, tasks_total=len(plan.tasks),
                                tasks_completed=sum(1 for r in round_results if r),
                                task_name=task.tool, task_status="running",
                                message=task.reason,
                            ))

                        # Route HTTP requests through browser when WAF is active
                        browser_routed = False
                        if self._browser and self._browser.active:
                            route_via_browser = False
                            fetch_url = None

                            if task.tool == "curl":
                                route_via_browser = True
                                fetch_url = task_target
                            elif task.tool == "exec":
                                cmd = params.get("command", "")
                                if "curl " in cmd and not any(t in cmd for t in ["api.", "/api/", "supabase", "firebase"]):
                                    # Route page-fetching curls through browser; let API curls try direct
                                    import re as _re
                                    url_match = _re.search(r"https?://[^\s'\"]+", cmd)
                                    if url_match:
                                        route_via_browser = True
                                        fetch_url = url_match.group(0).rstrip("'\")")
                            elif task.tool in ("httpx", "whatweb", "katana"):
                                route_via_browser = True
                                fetch_url = task_target if task_target.startswith("http") else f"https://{task_target}"

                            if route_via_browser and fetch_url:
                                try:
                                    page = await self._browser.fetch(fetch_url)
                                    body = page.get("body", "")
                                    html = page.get("html", "")
                                    output = f"[Fetched via browser bypass]\nURL: {page.get('url', fetch_url)}\nTitle: {page.get('title', '')}\n\n{body[:50000]}"
                                    result = ToolResult(
                                        tool=task.tool, target=task_target, success=True,
                                        summary=f"Browser fetch: {page.get('title', 'OK')} ({len(body)} chars)",
                                        raw_output=output,
                                        exit_code=0,
                                    )
                                    browser_routed = True
                                except Exception as exc:
                                    logger.warning("Browser fetch failed for %s: %s", fetch_url, exc)

                        if not browser_routed:
                            try:
                                result = await tool_def.run(task_target, params)
                            except asyncio.CancelledError:
                                result = ToolResult(
                                    tool=task.tool, target=task_target, success=False,
                                    summary=f"{task.tool}: skipped by user",
                                    raw_output="", error="Skipped",
                                )

                        self._running_tasks.pop(task.tool, None)

                        status = "completed" if result.success else ("skipped" if result.error == "Skipped" else "failed")

                        # Persist command execution to DB
                        if on_command:
                            cmd_str = f"{task.tool} {task_target}"
                            if task.tool == "exec":
                                cmd_str = params.get("command", cmd_str)
                            await on_command({
                                "command": cmd_str,
                                "tool": task.tool,
                                "reason": task.reason,
                                "risk_level": tool_def.risk if hasattr(tool_def, "risk") else "low",
                                "phase": plan.phase,
                                "status": status,
                                "output": result.raw_output[:100_000] if result.raw_output else result.summary[:10_000],
                                "exit_code": result.exit_code,
                            })

                        # Detect WAF/bot protection
                        check_text = (result.raw_output or "").lower() + (result.summary or "").lower()
                        if any(sig in check_text for sig in _WAF_SIGNATURES):
                            nonlocal waf_detected
                            waf_detected = True
                            logger.warning("WAF/bot protection detected in %s output", task.tool)

                        if on_progress:
                            await on_progress(ScanProgress(
                                round_num=round_num, total_rounds=_MAX_ROUNDS,
                                phase=plan.phase, tasks_total=len(plan.tasks),
                                tasks_completed=sum(1 for r in round_results if r) + 1,
                                task_name=task.tool,
                                task_status=status,
                                message=f"{task.tool}: {len(result.findings)} findings in {result.duration:.1f}s" if result.success else f"{task.tool}: {result.error or 'failed'}",
                            ))

                        return result

                # Create tracked asyncio tasks
                async_tasks = []
                for t in group:
                    at = asyncio.create_task(_run_task(t))
                    self._running_tasks[t.tool] = at
                    async_tasks.append(at)

                results = await asyncio.gather(*async_tasks, return_exceptions=True)

                for r in results:
                    if isinstance(r, ToolResult):
                        round_results.append(r)
                    elif isinstance(r, Exception):
                        logger.exception("Task execution error: %s", r)

            all_results.extend(round_results)

            if self._aborted:
                break

            # Auto-expand scope with discovered backend hosts
            self._expand_scope_from_output(round_results)

            # WAF bypass: if detected and no browser yet, launch Xvfb + Chromium
            waf_bypass_info = ""
            if waf_detected and not self._browser:
                logger.info("WAF detected — launching browser bypass for %s", target)
                if on_progress:
                    await on_progress(ScanProgress(
                        round_num=round_num, total_rounds=_MAX_ROUNDS,
                        phase=plan.phase, tasks_total=0, tasks_completed=0,
                        message="WAF detectado — tentando bypass com browser real (Xvfb)...",
                        task_status="thinking",
                    ))
                target_url = target if target.startswith("http") else f"https://{target}"
                browser = BrowserSession()
                bypass_ok = await browser.start(target_url, debug_port=9222 + hash(session_id) % 500)
                if bypass_ok:
                    self._browser = browser
                    page_info = await browser.get_page_info()
                    self._waf_cookies = browser.cookie_header
                    self._waf_user_agent = browser.user_agent

                    # Build recon data from browser
                    recon_lines = ["✅ WAF BYPASS SUCCESSFUL — browser solved the JS challenge."]
                    recon_lines.append(f"Page title: {page_info.get('title', 'N/A')}")
                    recon_lines.append(f"Final URL: {page_info.get('url', 'N/A')}")
                    if page_info.get("forms"):
                        recon_lines.append(f"Forms found: {len(page_info['forms'])}")
                        for f in page_info["forms"][:5]:
                            inputs = ", ".join(i.get("name", i.get("type", "?")) for i in f.get("inputs", []))
                            recon_lines.append(f"  → {f.get('method','GET')} {f.get('action','')} [{inputs}]")
                    if page_info.get("links"):
                        recon_lines.append(f"Links found: {len(page_info['links'])}")
                        for link in page_info["links"][:15]:
                            recon_lines.append(f"  → {link.get('href', '')} ({link.get('text', '')[:30]})")
                    if page_info.get("scripts"):
                        recon_lines.append(f"JS scripts: {len(page_info['scripts'])}")
                        for s in page_info["scripts"][:10]:
                            recon_lines.append(f"  → {s}")
                    if page_info.get("meta"):
                        for m in page_info["meta"][:10]:
                            recon_lines.append(f"  meta[{m.get('name','')}] = {m.get('content','')[:80]}")
                    body_preview = page_info.get("body_text", "")[:2000]
                    if body_preview:
                        recon_lines.append(f"\nPage body preview:\n{body_preview}")
                    recon_lines.append("\nNOTE: Direct curl/tools are BLOCKED by the WAF. The browser bypassed the challenge.")
                    recon_lines.append("Use 'exec' with curl + the cookies below for API endpoints, or analyze the JS/HTML from the browser output.")
                    recon_lines.append(f"Cookie header: {self._waf_cookies[:200]}")
                    recon_lines.append(f"User-Agent: {self._waf_user_agent[:100]}")
                    waf_bypass_info = "\n" + "\n".join(recon_lines)
                    logger.info("WAF bypass OK — page title: %s", page_info.get("title", "?")[:60])
                else:
                    await browser.stop()
                    waf_bypass_info = "\n❌ WAF bypass failed — browser could not solve JS challenge. Use passive recon (DNS, subdomains, OSINT, cached versions)."
                    logger.warning("WAF bypass failed")

            # Build results summary for Claude
            # Round 1 was deterministic — prepend target context for Claude's first message
            if round_num == 1:
                initial_ctx = self._build_initial_message(target, client, catalog)
                results_summary = initial_ctx + "\n\n" + self._build_results_message(
                    round_num, round_results, all_findings, all_leads, target, catalog, waf_detected,
                )
            else:
                results_summary = self._build_results_message(
                    round_num, round_results, all_findings, all_leads, target, catalog, waf_detected,
                )
            if waf_bypass_info:
                results_summary += waf_bypass_info

            if on_progress:
                await on_progress(ScanProgress(
                    round_num=round_num, total_rounds=_MAX_ROUNDS,
                    phase=plan.phase, tasks_total=len(plan.tasks),
                    tasks_completed=len(round_results),
                    message="Coletando resultados...",
                    task_status="collecting",
                ))

            logger.info(
                "Round %d complete: %d tasks, %d results, %d total findings. Asking Claude for next plan.",
                round_num, len(plan.tasks), len(round_results), len(all_findings),
            )

            if on_progress:
                await on_progress(ScanProgress(
                    round_num=round_num, total_rounds=_MAX_ROUNDS,
                    phase=plan.phase, tasks_total=0, tasks_completed=0,
                    message="Analisando resultados e planejando próximo passo...",
                    task_status="thinking",
                ))

            plan_text = await self._plan_fn(session_id, results_summary)
            plan = parse_plan_json(plan_text)

            # Collect findings from analysis and emit immediately
            await _emit_findings_leads(plan)

        if on_progress:
            await on_progress(ScanProgress(
                round_num=round_num, total_rounds=_MAX_ROUNDS,
                phase=plan.phase if plan else "reporting",
                tasks_total=0, tasks_completed=0,
                message=plan.done_reason if plan and plan.done_reason else "Scan complete",
            ))

        # Clean up browser session if used
        if self._browser:
            await self._browser.stop()
            self._browser = None

        logger.info(
            "Scan complete: %d rounds, %d findings, %d leads",
            round_num, len(all_findings), len(all_leads),
        )

        return {
            "findings": all_findings,
            "leads": all_leads,
            "rounds": round_num,
            "tools_run": len(all_results),
            "analysis": plan.analysis if plan else "",
        }

    @staticmethod
    def _compact_catalog(catalog: list[dict]) -> str:
        """Build a token-efficient catalog: one line per tool, params as short keys."""
        lines = []
        for t in catalog:
            params = t.get("params", {})
            req = [k for k, v in params.items() if v.get("required")]
            opt = [k for k, v in params.items() if not v.get("required") and k != "extra_args"]
            parts = [f"{t['name']} ({t.get('category','')})"]
            parts.append(f"— {t['description'][:80]}")
            if req:
                parts.append(f"[required: {','.join(req)}]")
            if opt:
                parts.append(f"[optional: {','.join(opt)}]")
            if t.get("unavailable"):
                parts.append("[NOT INSTALLED — use exec]")
            lines.append(" ".join(parts))
        lines.append("ALL tools accept extra_args param for raw CLI flags.")
        return "\n".join(lines)

    @staticmethod
    def _build_deterministic_round1(target: str) -> ScanPlan:
        """Build a fixed recon plan so Round 1 is always identical."""
        return ScanPlan(
            analysis="Deterministic recon: fixed tool set for consistency.",
            tasks=[
                ScanTask(tool="httpx", params={"target": target}, priority=1, reason="HTTP probe"),
                ScanTask(tool="whatweb", params={"target": target}, priority=1, reason="Technology detection"),
                ScanTask(tool="nmap", params={"target": target, "top_ports": 100}, priority=1, reason="Port scan"),
                ScanTask(tool="curl", params={"url": target}, priority=1, reason="Homepage fetch"),
                ScanTask(tool="katana", params={"target": target}, priority=2, reason="Crawl for JS/endpoints"),
                ScanTask(tool="subfinder", params={"target": target}, priority=2, reason="Subdomain enumeration"),
            ],
            phase="recon",
        )

    def _build_initial_message(
        self, target: str, client: str, catalog: list[dict],
    ) -> str:
        scope_str = ", ".join(self._scope) if self._scope else target
        compact = self._compact_catalog(catalog)

        return f"""TARGET: {target}
CLIENT: {client}
SCOPE: {scope_str}
SCOPE NOTE: Backend APIs discovered during scanning are auto-added to scope. Test them.
STATUS: Authorized engagement — ROE signed, all targets pre-approved.

TOOLS:
{compact}

Round 1: recon. Plan parallel tools.
Priority 1: httpx + whatweb + nmap + curl (homepage)
Priority 2: katana + subfinder
Keep it lean — 4-6 tools max. Save tokens for exploitation rounds."""

    def _build_results_message(
        self,
        round_num: int,
        results: list[ToolResult],
        all_findings: list[dict],
        all_leads: list[dict],
        target: str,
        catalog: list[dict],
        waf_detected: bool = False,
    ) -> str:
        parts = [f"=== ROUND {round_num} RESULTS ===\n"]

        # WAF/bot protection warning
        if waf_detected:
            parts.append("⚠️ WAF / BOT PROTECTION DETECTED on this target.")
            parts.append("RULES WHEN WAF IS ACTIVE:")
            parts.append("- Do NOT create findings based on inference or guesswork.")
            parts.append("- ONLY create findings when you have REAL evidence from tool output (actual response bodies, headers, error messages).")
            parts.append("- If a tool returned a WAF block page instead of real content, that is NOT evidence of a vulnerability.")
            parts.append("- Try bypass techniques: different User-Agent headers, direct IP access, path variations, encoded payloads.")
            parts.append("- Use exec with curl and custom headers to bypass bot protection.")
            parts.append("- If ALL tools are blocked, report the WAF presence as a single info finding and set done=true.")
            parts.append("")

        # Show scope violations so Claude knows what was blocked
        blocked = []
        for r in results:
            parts.append(_summarize_result(r))
            parts.append("")
            if r.error == "Scope violation":
                blocked.append(r.summary)

        if self._discovered_hosts:
            parts.append(f"\nEXPANDED SCOPE (auto-discovered backends): {', '.join(sorted(self._discovered_hosts))}")
            parts.append("You CAN target these hosts — they are in scope.")

        if blocked:
            parts.append(f"\n⚠ {len(blocked)} commands were SCOPE-BLOCKED this round. If the blocked host was discovered from the target's JS/HTML, it will be auto-added to scope next round. Retry the command.")

        if all_findings:
            # Deduplicate findings by title
            seen_f = set()
            unique_findings = []
            for f in all_findings:
                if isinstance(f, dict):
                    key = f.get("title", "").strip().lower()
                    if key and key not in seen_f:
                        seen_f.add(key)
                        unique_findings.append(f)

            confirmed = [f for f in unique_findings if f.get("confidence") != "informational"]
            parts.append(f"\nFINDINGS SO FAR ({len(unique_findings)} unique, {len(confirmed)} confirmed/possible):")
            for f in unique_findings[-15:]:
                sev = f.get("severity", "info")
                conf = f.get("confidence", "possible")
                title = f.get("title", "untitled")
                parts.append(f"  [{sev.upper()}] [{conf}] {title}")

        if all_leads:
            # Deduplicate leads by title
            seen_titles = set()
            unique_leads = []
            for l in all_leads:
                if isinstance(l, dict):
                    title = l.get("title", "untitled").strip().lower()
                    if title not in seen_titles:
                        seen_titles.add(title)
                        unique_leads.append(l)

            high_leads = [l for l in unique_leads if l.get("priority") == "high"]
            other_leads = [l for l in unique_leads if l.get("priority") != "high"]
            parts.append(f"\n=== LEAD BOARD ({len(unique_leads)} unique leads) ===")
            if high_leads:
                parts.append("HIGH PRIORITY — you MUST chain-exploit each of these:")
                for l in high_leads[-10:]:
                    parts.append(f"  🔴 {l.get('title', 'untitled')}: {l.get('description', '')[:150]}")
            if other_leads:
                parts.append("OTHER:")
                for l in other_leads[-8:]:
                    parts.append(f"  → {l.get('title', 'untitled')}: {l.get('description', '')[:100]}")
            parts.append("NEVER set done=true with untested HIGH leads. Each needs MULTIPLE exec commands to fully exploit.")

        if round_num == 1:
            parts.append("\nNEXT: js_analyze on ALL JS files. exec to test first secrets/endpoints found. Start exploiting immediately.")
        elif round_num <= 3:
            parts.append(f"\nNEXT (Round {round_num + 1}): EXPLOITATION REQUIRED. For EACH high-priority lead, run a chain of exec commands — not just one. Example: Supabase key → list tables → read each table → try signup → test storage → test RPC. HubSpot key → list contacts → list companies → test write access.")
        else:
            parts.append(f"\nNEXT (Round {round_num + 1}): DEEP EXPLOITATION. Go deeper into what you found. If a Supabase table returned data, try to read ALL tables. If HubSpot returned contacts, dump more and check for write access. Chain multiple exec commands per lead. Set done=true ONLY when every high lead has been fully exploited.")

        parts.append("\nRespond with ONLY the raw JSON object. No markdown, no code fences, no commentary.")

        return "\n".join(parts)
