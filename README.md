<p align="center">
  <br/>
  <img src="Assets/HADES.png?raw=true" alt="HADES" width="300"/>
  <br/>
  <br/><br/>
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#tools">Tools</a> &bull;
  <a href="#custom-tools">Custom Tools</a> &bull;
  <a href="#scan-profiles">Scan Profiles</a>
  <br/><br/>
  <img src="https://img.shields.io/badge/python-3.11+-blue?logo=python&logoColor=white" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/node-18+-green?logo=node.js&logoColor=white" alt="Node 18+"/>
  <img src="https://img.shields.io/badge/claude-CLI-orange?logo=anthropic&logoColor=white" alt="Claude CLI"/>
  <img src="https://img.shields.io/badge/license-MIT-gray" alt="MIT License"/>
</p>

---

**HADES** is an AI-powered penetration testing platform that orchestrates 35+ security tools through Claude, Anthropic's AI model. It automates reconnaissance, scanning, enumeration, and exploitation workflows while keeping a human operator in the loop for authorization of destructive actions.

Think of it as an AI red-teamer that knows how to chain tools, follow leads, and build a pentest report -- but always asks before doing anything dangerous.

## Features

- **AI-Orchestrated Scanning** -- Claude plans and executes multi-round scans, chaining tool outputs as context for the next phase
- **35+ Integrated Tools** -- From nmap to sqlmap, organized by category (recon, scanning, enumeration, exploitation)
- **Interactive Chat** -- Talk to Claude mid-scan or post-scan to investigate findings, pivot, or ask questions
- **Operator Authorization** -- Destructive commands (DELETE, mutations, exploitation) require explicit approval via WebSocket modal
- **Scan Profiles** -- Pre-built and custom tool sets (Full Scan, Web App, API Only, Auth & SQLi, Recon Only)
- **Custom Tools** -- Register any CLI binary through the UI with path, args template, and `{target}` placeholder
- **Live Dashboard** -- Real-time scan progress, findings by severity, tool execution status, token usage
- **Findings & Leads** -- Structured vulnerability findings with evidence, plus investigation leads for manual follow-up
- **PDF Reports** -- Auto-generated pentest reports with findings, steps to reproduce, risk scores, and remediation
- **WAF Bypass** -- Built-in browser-based WAF bypass via headless Chromium for targets behind Cloudflare/Vercel
- **Project Management** -- Organize targets into projects with scope, sessions, and cross-session analytics
- **Multi-User Auth** -- JWT-based authentication with admin/operator roles

## Quick Start

### Prerequisites

| Dependency | Purpose |
|---|---|
| **Python 3.11+** | Backend runtime |
| **Node.js 18+** | Frontend build |
| **Claude CLI** | AI engine ([install](https://docs.anthropic.com/en/docs/claude-code)) |
| **Kali Linux** (recommended) | Pre-installed security tools |

### One-liner

```bash
git clone https://github.com/YOUR_USER/HADES.git
cd HADES
chmod +x run.sh
./run.sh
```

`run.sh` handles everything: creates the Python venv, installs pip/npm dependencies, starts backend on `:8000` and frontend on `:5173`.

**Default credentials:** `admin` / `P@ssw0rd`

### Manual Setup

```bash
# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000

# Frontend (another terminal)
cd frontend
npm install
npx vite --host 0.0.0.0
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Frontend (React 19)                    │
│         Vite + Tailwind  ·  WebSocket + REST             │
└──────────────────────┬───────────────────────────────────┘
                       │
              REST API + WebSocket
                       │
┌──────────────────────┴───────────────────────────────────┐
│                  Backend (FastAPI)                        │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Claude      │  │ Orchestrator │  │ Tool Registry  │  │
│  │ Client      │←→│ (Scan Loop)  │←→│ (35+ tools)    │  │
│  │ (CLI wrap)  │  │              │  │                │  │
│  └──────┬──────┘  └──────────────┘  └────────────────┘  │
│         │                                                │
│  ┌──────┴──────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Claude CLI  │  │ SQLite DB    │  │ WAF Bypass     │  │
│  │ subprocess  │  │ (async)      │  │ (Chromium CDP) │  │
│  └─────────────┘  └──────────────┘  └────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### Scan Flow

1. **Operator** creates a session with a target and scan profile
2. **Orchestrator** sends the tool catalog + target to Claude (`--max-turns 0` = plan only)
3. **Claude** returns a structured plan with tool invocations and parameters
4. **Orchestrator** executes tools in parallel, feeds results back to Claude
5. **Claude** analyzes outputs, generates findings/leads, plans the next round
6. Repeat for multiple rounds until Claude determines coverage is sufficient
7. **Operator** can chat with Claude post-scan to investigate, pivot, or ask questions

### Interactive Mode

After a scan (or in a fresh session), the operator chats directly with Claude. Claude has full context of all findings, leads, and command history. It can execute commands with `<cmd>` tags, which go through the authorization flow.

## Tools

35 integrated tools organized by phase:

### Recon
| Tool | Description |
|---|---|
| `nmap` | Port scanner with service/version detection |
| `httpx` | Fast HTTP prober -- status codes, titles, tech detection |
| `subfinder` | Passive subdomain discovery |
| `amass` | Attack surface mapping -- DNS, scraping, APIs, cert transparency |
| `katana` | Web crawler/spider -- endpoints, JS files, API routes, forms |
| `whatweb` | Web technology fingerprinting -- CMS, frameworks, servers |
| `wafw00f` | WAF detection -- identifies WAF/IPS products |
| `whois` | WHOIS lookup -- registrar, dates, nameservers |
| `dig` | DNS record lookup -- A, AAAA, MX, NS, TXT, CNAME, SOA |
| `tech_detect` | HTTP header-based technology detection |
| `gau` | Fetch known URLs from AlienVault, Wayback, Common Crawl |

### Scanning
| Tool | Description |
|---|---|
| `nikto` | Web server scanner -- misconfigs, dangerous files, outdated software |
| `nuclei` | Template-based vulnerability scanner -- CVEs, misconfigs, exposures |
| `testssl` | TLS/SSL scanner -- protocol support, cipher suites, HEARTBLEED/POODLE |
| `wpscan` | WordPress scanner -- users, plugins, themes, known vulns |
| `header_probe` | Security header analysis -- HSTS, CSP, X-Frame-Options |

### Enumeration
| Tool | Description |
|---|---|
| `ffuf` | Fast web fuzzer -- directories, files, vhosts, parameters |
| `gobuster` | Directory/file and DNS subdomain brute-forcer |
| `feroxbuster` | Recursive content discovery with auto-recursion |
| `arjun` | Hidden HTTP parameter discovery |
| `js_analyze` | JavaScript analysis -- secrets, API keys, endpoints |

### Exploitation
| Tool | Description |
|---|---|
| `sqlmap` | Automated SQL injection scanner |
| `commix` | OS command injection scanner and exploiter |
| `dalfox` | XSS scanner -- reflected, stored, DOM-based |
| `hydra` | Brute-force network logins (SSH, FTP, HTTP) |
| `xss_probe` | Custom XSS payload testing |
| `sqli_probe` | SQL injection probe with error/blind/time-based detection |
| `lfi_probe` | Local file inclusion testing |
| `idor_probe` | IDOR testing via sequential ID manipulation |
| `cors_probe` | CORS misconfiguration detection |
| `redirect_probe` | Open redirect testing |
| `takeover_probe` | Subdomain takeover detection |
| `curl` | Flexible HTTP client for manual probing |
| `wfuzz` | Web application fuzzer -- parameters, directories, headers |
| `exec` | Direct command execution (with operator approval) |

## Custom Tools

Register any CLI tool through the web UI:

1. Navigate to **Profiles** > **Custom Tools** tab
2. Click **Nova Tool**
3. Fill in:
   - **Name** (slug): `my-tool`
   - **Binary Path**: `/usr/local/bin/my-tool` or just `my-tool` if it's in PATH
   - **Args Template**: `-u {target} -silent -json` (use `{target}` as placeholder)
   - **Category**, **Risk**, **Timeout**
4. The tool is immediately available in scan profiles and the orchestrator

### Example: Adding httpx from ProjectDiscovery

```
Name:        httpx-pd
Binary Path: /root/go/bin/httpx
Args:        -u {target} -silent -json -status-code -title -tech-detect
Category:    recon
Risk:        low
Timeout:     60
```

Custom tools use the same execution pipeline as built-in tools (subprocess with timeout, output capture, auto-summary for Claude).

## Scan Profiles

Profiles are named sets of allowed tools. When creating a session, select a profile to restrict which tools the orchestrator can use.

### Default Profiles

| Profile | Tools | Use Case |
|---|---|---|
| **Full Scan** | All 35 | Complete assessment |
| **Web App** | 24 tools | Web-focused (no nmap, no network-level) |
| **API Only** | 10 tools | API endpoint testing |
| **Auth & SQLi** | 8 tools | Authentication and injection focus |
| **Recon Only** | 14 tools | Discovery without exploitation |

Create custom profiles through the **Profiles** page -- select tools from the visual catalog and save.

## Configuration

Environment variables in `backend/.env`:

```env
HOST=0.0.0.0
PORT=8000
DB_PATH=./hades.db
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:8000
MAX_COMMAND_TIMEOUT=300
CLAUDE_MODEL=claude-opus-4-6
```

## Project Structure

```
HADES/
├── run.sh                    # One-click launcher
├── backend/
│   ├── main.py               # FastAPI app, REST + WebSocket endpoints
│   ├── claude_client.py       # Claude CLI wrapper (chat + plan modes)
│   ├── orchestrator.py        # Multi-round scan orchestration engine
│   ├── database.py            # Async SQLite (sessions, findings, leads, profiles)
│   ├── models.py              # Pydantic models
│   ├── executor.py            # Safe subprocess execution
│   ├── waf_bypass.py          # Chromium CDP-based WAF bypass
│   ├── report_pdf.py          # PDF report generator
│   ├── auth.py                # JWT authentication
│   ├── config.py              # Environment configuration
│   ├── tools/                 # Tool integrations (one file per tool)
│   │   ├── base.py            # ToolDefinition base class + registry
│   │   ├── nmap_tool.py
│   │   ├── sqlmap_tool.py
│   │   └── ...
│   └── prompts/
│       └── plan_system.md     # System prompt for scan planning
├── frontend/
│   ├── src/
│   │   ├── pages/             # Dashboard, SessionView, Profiles, Analytics, Settings
│   │   ├── components/        # ChatArea, ScanProgress, FindingCard, etc.
│   │   ├── context/           # AppContext, AuthContext
│   │   ├── hooks/             # useWebSocket
│   │   └── api.js             # REST API client
│   └── ...
└── .gitignore
```


## Security Notes

- All destructive actions (exploitation, DELETE requests, mutations) require explicit operator approval through a WebSocket modal
- The `exec` tool allows arbitrary command execution but goes through the authorization flow
- Default credentials should be changed immediately after first login (Settings page)
- HADES is designed to run on a local pentest machine, not exposed to the internet
- Scan data (findings, commands, evidence) is stored in a local SQLite database

## Disclaimer

HADES is intended for **authorized security testing only**. Only use this tool against systems you have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse of this software.

Always obtain proper authorization before conducting any penetration testing activities.

## License

MIT
