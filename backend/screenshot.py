"""Screenshot capture for HADES evidence — URL screenshots via headless Chromium."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from pathlib import Path

logger = logging.getLogger("hades.screenshot")

SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"
CHROMIUM = shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("chromium-browser")
TIMEOUT = 20


def _ensure_dir(session_id: str) -> Path:
    d = SCREENSHOTS_DIR / session_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sanitize_filename(url: str) -> str:
    """Turn a URL into a safe filename."""
    name = re.sub(r'https?://', '', url)
    name = re.sub(r'[^a-zA-Z0-9._-]', '_', name)
    return name[:120]


async def capture_url(url: str, session_id: str, finding_id: str) -> str | None:
    """Screenshot a URL using headless Chromium.

    Returns the file path on success, None on failure.
    """
    if not CHROMIUM:
        logger.warning("No Chromium binary found — skipping screenshot")
        return None

    out_dir = _ensure_dir(session_id)
    filename = f"{finding_id}_{_sanitize_filename(url)}.png"
    out_path = out_dir / filename

    cmd = [
        CHROMIUM,
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-software-rasterizer",
        f"--screenshot={out_path}",
        "--window-size=1280,900",
        "--hide-scrollbars",
        "--ignore-certificate-errors",
        "--virtual-time-budget=5000",
        url,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)

        if out_path.exists() and out_path.stat().st_size > 8000:
            logger.info("Screenshot captured: %s → %s", url, out_path)
            return str(out_path)
        else:
            if out_path.exists():
                out_path.unlink()
            logger.warning("Screenshot too small or blank for %s", url)
            return None

    except asyncio.TimeoutError:
        logger.warning("Screenshot timeout for %s", url)
        return None
    except Exception as exc:
        logger.warning("Screenshot failed for %s: %s", url, exc)
        return None


async def capture_evidence(
    evidence: str,
    target: str,
    session_id: str,
    finding_id: str,
) -> list[str]:
    """Extract URLs from evidence and capture screenshots.

    Returns list of screenshot file paths.
    """
    urls: list[str] = []

    # Extract URLs from evidence text
    found = re.findall(r'https?://[^\s"\'<>]+', evidence)
    for u in found:
        u = u.rstrip(".,;:)}")
        if u not in urls:
            urls.append(u)

    # Always include the target itself
    if target.startswith("http"):
        target_url = target
    else:
        target_url = f"https://{target}"
    if target_url not in urls:
        urls.insert(0, target_url)

    # Limit to 3 most relevant URLs
    urls = urls[:3]

    paths: list[str] = []
    for url in urls:
        path = await capture_url(url, session_id, finding_id)
        if path:
            paths.append(path)

    return paths
