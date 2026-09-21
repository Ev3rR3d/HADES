#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"

RED='\033[0;31m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
DIM='\033[2m'
RESET='\033[0m'

echo -e "${CYAN}"
echo "  ██╗  ██╗ █████╗ ██████╗ ███████╗███████╗"
echo "  ██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝"
echo "  ███████║███████║██║  ██║█████╗  ███████╗"
echo "  ██╔══██║██╔══██║██║  ██║██╔══╝  ╚════██║"
echo "  ██║  ██║██║  ██║██████╔╝███████╗███████║"
echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝"
echo -e "${DIM}  AI-Powered Penetration Testing Platform${RESET}"
echo ""

# ── Check dependencies ──────────────────────────────────────────────────────

check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}[!] $1 not found. $2${RESET}"
        exit 1
    fi
}

check_dep python3 "Install Python 3.11+"
check_dep node "Install Node.js 18+"
check_dep claude "Install Claude CLI: https://docs.anthropic.com/en/docs/claude-code"

# ── Setup backend ───────────────────────────────────────────────────────────

echo -e "${CYAN}[*] Setting up backend...${RESET}"

if [ ! -d "$BACKEND/.venv" ]; then
    echo -e "${DIM}    Creating virtual environment...${RESET}"
    python3 -m venv "$BACKEND/.venv"
fi

source "$BACKEND/.venv/bin/activate"

if [ ! -f "$BACKEND/.venv/.deps_installed" ] || [ "$BACKEND/requirements.txt" -nt "$BACKEND/.venv/.deps_installed" ]; then
    echo -e "${DIM}    Installing Python dependencies...${RESET}"
    pip install -q -r "$BACKEND/requirements.txt"
    touch "$BACKEND/.venv/.deps_installed"
fi

if [ ! -f "$BACKEND/.env" ]; then
    cp "$BACKEND/.env.example" "$BACKEND/.env"
    echo -e "${DIM}    Created .env from .env.example${RESET}"
fi

# ── Setup frontend ──────────────────────────────────────────────────────────

echo -e "${CYAN}[*] Setting up frontend...${RESET}"

if [ ! -d "$FRONTEND/node_modules" ]; then
    echo -e "${DIM}    Installing npm dependencies...${RESET}"
    (cd "$FRONTEND" && npm install --silent)
fi

# ── Launch ──────────────────────────────────────────────────────────────────

cleanup() {
    echo -e "\n${CYAN}[*] Shutting down HADES...${RESET}"
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    wait $BACKEND_PID $FRONTEND_PID 2>/dev/null
    echo -e "${GREEN}[+] Done.${RESET}"
}
trap cleanup EXIT INT TERM

echo -e "${CYAN}[*] Starting backend on :8000...${RESET}"
(cd "$BACKEND" && python3 -m uvicorn main:app --host 0.0.0.0 --port 8000) &
BACKEND_PID=$!

echo -e "${CYAN}[*] Starting frontend on :5173...${RESET}"
(cd "$FRONTEND" && npx vite --host 0.0.0.0) &
FRONTEND_PID=$!

sleep 2
echo ""
echo -e "${GREEN}[+] HADES is running!${RESET}"
echo -e "    ${CYAN}Frontend:${RESET} http://localhost:5173"
echo -e "    ${CYAN}Backend:${RESET}  http://localhost:8000"
echo -e "    ${CYAN}Login:${RESET}    admin / P@ssw0rd"
echo -e "${DIM}    Press Ctrl+C to stop${RESET}"
echo ""

wait
