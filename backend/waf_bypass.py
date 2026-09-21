"""WAF bypass module — uses Xvfb + Chromium to solve JS challenges.

When a WAF blocks direct tool access, this module:
1. Launches Chromium in Xvfb (virtual display, non-headless) to pass fingerprinting
2. Solves the JS challenge via real browser rendering
3. Extracts cookies and provides a browser_fetch() for direct page access via CDP

Cookie-only bypass doesn't work for Vercel (TLS fingerprint validation),
so we keep the browser alive and route requests through it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger("hades.waf_bypass")

CHROMIUM = (
    shutil.which("chromium")
    or shutil.which("google-chrome")
    or shutil.which("chromium-browser")
)
XVFB_RUN = shutil.which("xvfb-run")

_CHALLENGE_WAIT_MAX = 20
_WAF_SIGNATURES = [
    "security checkpoint", "vercel security", "cloudflare", "captcha",
    "challenge-platform", "checking your browser", "please verify",
    "bot detection", "ddos protection",
]


class BrowserSession:
    """Persistent browser session that can solve WAF challenges and fetch pages."""

    def __init__(self):
        self._proc: asyncio.subprocess.Process | None = None
        self._ws = None
        self._tmpdir: str | None = None
        self._debug_port: int = 0
        self._msg_id: int = 0
        self._cookies: list[dict] = []
        self._user_agent: str = ""
        self.active: bool = False

    async def start(self, target_url: str, debug_port: int = 9222) -> bool:
        """Launch browser, navigate to target, solve challenge. Returns True if bypassed."""
        if not CHROMIUM:
            logger.warning("No Chromium binary — cannot start browser session")
            return False

        self._debug_port = debug_port
        self._tmpdir = tempfile.mkdtemp(prefix="hades_waf_")

        chrome_args = [
            CHROMIUM,
            "--no-sandbox",
            "--disable-dev-shm-usage",
            f"--remote-debugging-port={debug_port}",
            f"--user-data-dir={self._tmpdir}",
            "--window-size=1920,1080",
            "--disable-blink-features=AutomationControlled",
            "--disable-infobars",
            "about:blank",
        ]

        if XVFB_RUN:
            cmd = [XVFB_RUN, "-a", "--server-args=-screen 0 1920x1080x24"] + chrome_args
        else:
            chrome_args.insert(1, "--headless=new")
            cmd = chrome_args

        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        # Connect via CDP
        ws_url = await self._find_ws_url(timeout=10)
        if not ws_url:
            logger.warning("Could not connect to Chromium CDP")
            await self.stop()
            return False

        import websockets
        self._ws = await websockets.connect(ws_url, max_size=10_000_000)

        # Anti-detection
        await self._cdp("Page.enable")
        await self._cdp("Page.addScriptToEvaluateOnNewDocument", {
            "source": 'Object.defineProperty(navigator, "webdriver", {get: () => undefined});'
        })

        # Navigate to target
        await self._cdp("Page.navigate", {"url": target_url})

        # Wait for challenge to resolve
        for _ in range(_CHALLENGE_WAIT_MAX // 2):
            await asyncio.sleep(2)
            title = await self._get_title()
            cookies = await self._get_cookies()

            is_challenge = any(kw in title.lower() for kw in _WAF_SIGNATURES)

            if cookies and not is_challenge:
                self._cookies = cookies
                ua = await self._eval("navigator.userAgent")
                self._user_agent = ua or ""
                self.active = True
                logger.info("WAF bypass OK — title: %s, cookies: %d", title[:60], len(cookies))
                return True

        logger.warning("WAF challenge not solved after %ds", _CHALLENGE_WAIT_MAX)
        await self.stop()
        return False

    async def fetch(self, url: str) -> dict:
        """Fetch a URL through the browser. Returns {status, headers, body, title, url}."""
        if not self.active or not self._ws:
            return {"status": 0, "body": "", "error": "Browser session not active"}

        try:
            await self._cdp("Page.navigate", {"url": url})
            await asyncio.sleep(3)

            title = await self._get_title()
            body = await self._eval("document.body?.innerText?.substring(0, 50000) || ''")
            html = await self._eval("document.documentElement?.outerHTML?.substring(0, 100000) || ''")
            final_url = await self._eval("window.location.href")
            cookies = await self._get_cookies()
            self._cookies = cookies

            return {
                "status": 200,
                "title": title,
                "body": body or "",
                "html": html or "",
                "url": final_url or url,
                "cookies": len(cookies),
            }
        except Exception as exc:
            logger.warning("Browser fetch failed for %s: %s", url, exc)
            return {"status": 0, "body": "", "error": str(exc)}

    async def fetch_multi(self, urls: list[str]) -> list[dict]:
        """Fetch multiple URLs sequentially through the browser."""
        results = []
        for url in urls:
            r = await self.fetch(url)
            results.append(r)
        return results

    async def get_page_info(self) -> dict:
        """Get comprehensive info about the current page."""
        if not self.active or not self._ws:
            return {}

        try:
            info = {}
            info["title"] = await self._get_title()
            info["url"] = await self._eval("window.location.href")
            info["body_text"] = await self._eval("document.body?.innerText?.substring(0, 30000) || ''")

            # Extract all links
            links = await self._eval("""
                JSON.stringify([...document.querySelectorAll('a[href]')].slice(0, 100).map(a => ({
                    href: a.href, text: a.textContent?.trim()?.substring(0, 50)
                })))
            """)
            info["links"] = json.loads(links) if links else []

            # Extract forms
            forms = await self._eval("""
                JSON.stringify([...document.querySelectorAll('form')].slice(0, 20).map(f => ({
                    action: f.action, method: f.method,
                    inputs: [...f.querySelectorAll('input,select,textarea')].map(i => ({
                        name: i.name, type: i.type, id: i.id
                    }))
                })))
            """)
            info["forms"] = json.loads(forms) if forms else []

            # Extract scripts src
            scripts = await self._eval("""
                JSON.stringify([...document.querySelectorAll('script[src]')].slice(0, 50).map(s => s.src))
            """)
            info["scripts"] = json.loads(scripts) if scripts else []

            # Meta tags
            meta = await self._eval("""
                JSON.stringify([...document.querySelectorAll('meta')].map(m => ({
                    name: m.name || m.getAttribute('property') || '', content: m.content || ''
                })).filter(m => m.name && m.content))
            """)
            info["meta"] = json.loads(meta) if meta else []

            # Cookies
            info["cookies"] = await self._get_cookies()

            return info
        except Exception as exc:
            logger.warning("get_page_info failed: %s", exc)
            return {}

    @property
    def cookie_header(self) -> str:
        return "; ".join(f"{c['name']}={c['value']}" for c in self._cookies)

    @property
    def user_agent(self) -> str:
        return self._user_agent

    async def stop(self):
        """Shut down the browser session."""
        self.active = False
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
        if self._proc:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
            self._proc = None
        if self._tmpdir:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

    # ── Internal helpers ────────────────────────────────────────────────

    async def _find_ws_url(self, timeout: float = 10) -> str | None:
        import urllib.request
        end = asyncio.get_event_loop().time() + timeout
        url = f"http://127.0.0.1:{self._debug_port}/json"
        while asyncio.get_event_loop().time() < end:
            try:
                with urllib.request.urlopen(url, timeout=2) as resp:
                    pages = json.loads(resp.read())
                    for p in pages:
                        if p.get("type") == "page" and p.get("webSocketDebuggerUrl"):
                            return p["webSocketDebuggerUrl"]
            except Exception:
                pass
            await asyncio.sleep(0.3)
        return None

    async def _cdp(self, method: str, params: dict | None = None) -> dict:
        self._msg_id += 1
        mid = self._msg_id
        msg = {"id": mid, "method": method}
        if params:
            msg["params"] = params
        await self._ws.send(json.dumps(msg))
        while True:
            raw = await asyncio.wait_for(self._ws.recv(), timeout=15)
            data = json.loads(raw)
            if data.get("id") == mid:
                return data

    async def _eval(self, expression: str) -> str:
        r = await self._cdp("Runtime.evaluate", {"expression": expression})
        return r.get("result", {}).get("result", {}).get("value", "")

    async def _get_title(self) -> str:
        return await self._eval("document.title")

    async def _get_cookies(self) -> list[dict]:
        r = await self._cdp("Network.getAllCookies")
        raw = r.get("result", {}).get("cookies", [])
        return [{"name": c["name"], "value": c["value"], "domain": c.get("domain", "")} for c in raw]


async def solve_and_recon(target_url: str, debug_port: int = 9222) -> tuple[BrowserSession | None, dict]:
    """High-level: start browser, solve WAF, do initial page recon.

    Returns (session, page_info) — caller must session.stop() when done.
    """
    session = BrowserSession()
    ok = await session.start(target_url, debug_port=debug_port)
    if not ok:
        return None, {}

    info = await session.get_page_info()
    return session, info
