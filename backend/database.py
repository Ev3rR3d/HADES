"""Async SQLite database layer for HADES."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from config import settings
from models import (
    CommandStatus,
    Finding,
    Lead,
    LeadCategory,
    LeadStatus,
    Message,
    MessageRole,
    PendingCommand,
    Phase,
    Project,
    ProjectStatus,
    RiskLevel,
    CustomTool,
    ScanProfile,
    Session,
    SessionStatus,
    Severity,
)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client TEXT DEFAULT '',
    description TEXT DEFAULT '',
    scope TEXT DEFAULT '[]',
    start_date TEXT,
    end_date TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    phase TEXT NOT NULL DEFAULT 'recon',
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    tool_call_id TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS commands (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    command TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk_level TEXT NOT NULL DEFAULT 'medium',
    phase TEXT NOT NULL DEFAULT 'recon',
    status TEXT NOT NULL DEFAULT 'pending',
    output TEXT,
    exit_code INTEGER,
    created_at TEXT NOT NULL,
    tool_use_id TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    description TEXT NOT NULL,
    evidence TEXT,
    remediation TEXT,
    screenshot_paths TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS leads (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'other',
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    tools TEXT NOT NULL DEFAULT '[]',
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS custom_tools (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT DEFAULT '',
    description TEXT DEFAULT '',
    category TEXT NOT NULL DEFAULT 'recon',
    binary_path TEXT NOT NULL,
    args_template TEXT DEFAULT '',
    risk TEXT NOT NULL DEFAULT 'low',
    timeout INTEGER NOT NULL DEFAULT 120,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_leads_session ON leads(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_project ON sessions(project_id);
"""


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_dt(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------

class Database:
    """Async SQLite wrapper with CRUD for all HADES models."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or settings.DB_PATH
        self._db: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.executescript(_SCHEMA)
        # Migrations for existing databases
        try:
            await self._db.execute("ALTER TABLE findings ADD COLUMN screenshot_paths TEXT")
        except Exception:
            pass
        try:
            await self._db.execute("ALTER TABLE sessions ADD COLUMN profile_id TEXT")
        except Exception:
            pass
        await self._db.commit()
        await self._seed_default_profiles()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Database not connected — call connect() first")
        return self._db

    # ------------------------------------------------------------------
    # Projects
    # ------------------------------------------------------------------

    async def create_project(self, project: Project) -> Project:
        await self.db.execute(
            """INSERT INTO projects (id, name, client, description, scope, start_date, end_date, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                project.id, project.name, project.client, project.description,
                json.dumps(project.scope), project.start_date, project.end_date,
                project.status.value, _iso(project.created_at),
            ),
        )
        await self.db.commit()
        return project

    async def get_project(self, project_id: str) -> Optional[Project]:
        async with self.db.execute("SELECT * FROM projects WHERE id = ?", (project_id,)) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return self._row_to_project(row)

    async def list_projects(self) -> list[Project]:
        async with self.db.execute("SELECT * FROM projects ORDER BY created_at DESC") as cur:
            rows = await cur.fetchall()
        return [self._row_to_project(r) for r in rows]

    async def list_projects_with_stats(self) -> list[dict]:
        """List projects enriched with session_count and total_findings."""
        async with self.db.execute("SELECT * FROM projects ORDER BY created_at DESC") as cur:
            rows = await cur.fetchall()

        result = []
        for r in rows:
            p = self._row_to_project(r)
            pid = p.id

            async with self.db.execute(
                "SELECT COUNT(*) FROM sessions WHERE project_id = ?", (pid,)
            ) as cur2:
                session_count = (await cur2.fetchone())[0]

            async with self.db.execute(
                "SELECT COUNT(*) FROM findings WHERE session_id IN (SELECT id FROM sessions WHERE project_id = ?)",
                (pid,),
            ) as cur3:
                total_findings = (await cur3.fetchone())[0]

            d = p.model_dump(mode="json")
            d["session_count"] = session_count
            d["total_findings"] = total_findings
            result.append(d)

        return result

    async def update_project(self, project_id: str, **kwargs: object) -> Optional[Project]:
        """Update project fields. Accepts keyword args matching Project fields."""
        allowed = {"name", "client", "description", "scope", "start_date", "end_date", "status"}
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if not updates:
            return await self.get_project(project_id)

        set_clauses: list[str] = []
        values: list[object] = []
        for key, val in updates.items():
            set_clauses.append(f"{key} = ?")
            if key == "scope":
                values.append(json.dumps(val))
            elif key == "status" and isinstance(val, ProjectStatus):
                values.append(val.value)
            else:
                values.append(val)
        values.append(project_id)

        await self.db.execute(
            f"UPDATE projects SET {', '.join(set_clauses)} WHERE id = ?",
            tuple(values),
        )
        await self.db.commit()
        return await self.get_project(project_id)

    async def delete_project(self, project_id: str) -> bool:
        """Delete a project and all its sessions/data (cascade)."""
        cur = await self.db.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        await self.db.commit()
        return cur.rowcount > 0

    async def get_project_sessions(self, project_id: str) -> list[Session]:
        async with self.db.execute(
            "SELECT * FROM sessions WHERE project_id = ? ORDER BY created_at DESC",
            (project_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [self._row_to_session(r) for r in rows]

    async def get_project_findings_summary(self, project_id: str) -> dict[str, int]:
        """Count findings by severity across all sessions in a project."""
        async with self.db.execute(
            """SELECT f.severity, COUNT(*) as cnt
               FROM findings f
               JOIN sessions s ON f.session_id = s.id
               WHERE s.project_id = ?
               GROUP BY f.severity""",
            (project_id,),
        ) as cur:
            rows = await cur.fetchall()
        return {row["severity"]: row["cnt"] for row in rows}

    def _row_to_project(self, r: aiosqlite.Row) -> Project:
        scope_raw = r["scope"]
        try:
            scope = json.loads(scope_raw) if scope_raw else []
        except (json.JSONDecodeError, TypeError):
            scope = []
        return Project(
            id=r["id"],
            name=r["name"],
            client=r["client"] or "",
            description=r["description"] or "",
            scope=scope,
            start_date=r["start_date"],
            end_date=r["end_date"],
            status=ProjectStatus(r["status"]),
            created_at=_parse_dt(r["created_at"]),
        )

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    async def create_session(self, session: Session) -> Session:
        await self.db.execute(
            "INSERT INTO sessions (id, project_id, name, target, profile_id, created_at, status, phase) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session.id, session.project_id, session.name, session.target, session.profile_id,
             _iso(session.created_at), session.status.value, session.phase.value),
        )
        await self.db.commit()
        return session

    async def get_session(self, session_id: str) -> Optional[Session]:
        async with self.db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return self._row_to_session(row)

    async def list_sessions(self) -> list[Session]:
        async with self.db.execute("SELECT * FROM sessions ORDER BY created_at DESC") as cur:
            rows = await cur.fetchall()
        return [self._row_to_session(r) for r in rows]

    async def update_session_status(self, session_id: str, status: SessionStatus) -> None:
        await self.db.execute("UPDATE sessions SET status = ? WHERE id = ?", (status.value, session_id))
        await self.db.commit()

    async def update_session_phase(self, session_id: str, phase: Phase) -> None:
        await self.db.execute("UPDATE sessions SET phase = ? WHERE id = ?", (phase.value, session_id))
        await self.db.commit()

    async def delete_session(self, session_id: str) -> bool:
        # Foreign key cascade handles child rows
        cur = await self.db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        await self.db.commit()
        return cur.rowcount > 0

    def _row_to_session(self, r: aiosqlite.Row) -> Session:
        profile_id = None
        try:
            profile_id = r["profile_id"]
        except (IndexError, KeyError):
            pass
        return Session(
            id=r["id"],
            project_id=r["project_id"],
            name=r["name"],
            target=r["target"],
            profile_id=profile_id,
            created_at=_parse_dt(r["created_at"]),
            status=SessionStatus(r["status"]),
            phase=Phase(r["phase"]),
        )

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    async def add_message(self, msg: Message) -> Message:
        await self.db.execute(
            "INSERT INTO messages (id, session_id, role, content, tool_call_id, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (msg.id, msg.session_id, msg.role.value, msg.content, msg.tool_call_id, _iso(msg.timestamp)),
        )
        await self.db.commit()
        return msg

    async def get_messages(self, session_id: str) -> list[Message]:
        async with self.db.execute(
            "SELECT * FROM messages WHERE session_id = ? ORDER BY timestamp ASC", (session_id,)
        ) as cur:
            rows = await cur.fetchall()
        return [
            Message(
                id=r["id"],
                session_id=r["session_id"],
                role=MessageRole(r["role"]),
                content=r["content"],
                tool_call_id=r["tool_call_id"],
                timestamp=_parse_dt(r["timestamp"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    async def create_command(self, cmd: PendingCommand) -> PendingCommand:
        await self.db.execute(
            """INSERT INTO commands
               (id, session_id, command, reason, risk_level, phase, status, output, exit_code, created_at, tool_use_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cmd.id, cmd.session_id, cmd.command, cmd.reason,
                cmd.risk_level.value, cmd.phase.value, cmd.status.value,
                cmd.output, cmd.exit_code, _iso(cmd.created_at), cmd.tool_use_id,
            ),
        )
        await self.db.commit()
        return cmd

    async def get_command(self, command_id: str) -> Optional[PendingCommand]:
        async with self.db.execute("SELECT * FROM commands WHERE id = ?", (command_id,)) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return self._row_to_command(row)

    async def get_pending_commands(self, session_id: str) -> list[PendingCommand]:
        async with self.db.execute(
            "SELECT * FROM commands WHERE session_id = ? AND status = 'pending' ORDER BY created_at ASC",
            (session_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [self._row_to_command(r) for r in rows]

    async def get_commands(self, session_id: str) -> list[PendingCommand]:
        async with self.db.execute(
            "SELECT * FROM commands WHERE session_id = ? ORDER BY created_at ASC", (session_id,)
        ) as cur:
            rows = await cur.fetchall()
        return [self._row_to_command(r) for r in rows]

    async def update_command_status(
        self,
        command_id: str,
        status: CommandStatus,
        output: Optional[str] = None,
        exit_code: Optional[int] = None,
    ) -> None:
        if output is not None and exit_code is not None:
            await self.db.execute(
                "UPDATE commands SET status = ?, output = ?, exit_code = ? WHERE id = ?",
                (status.value, output, exit_code, command_id),
            )
        elif output is not None:
            await self.db.execute(
                "UPDATE commands SET status = ?, output = ? WHERE id = ?",
                (status.value, output, command_id),
            )
        else:
            await self.db.execute(
                "UPDATE commands SET status = ? WHERE id = ?",
                (status.value, command_id),
            )
        await self.db.commit()

    def _row_to_command(self, r: aiosqlite.Row) -> PendingCommand:
        return PendingCommand(
            id=r["id"],
            session_id=r["session_id"],
            command=r["command"],
            reason=r["reason"],
            risk_level=RiskLevel(r["risk_level"]),
            phase=Phase(r["phase"]),
            status=CommandStatus(r["status"]),
            output=r["output"],
            exit_code=r["exit_code"],
            created_at=_parse_dt(r["created_at"]),
            tool_use_id=r["tool_use_id"],
        )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    async def create_finding(self, finding: Finding) -> Finding:
        await self.db.execute(
            """INSERT INTO findings
               (id, session_id, title, severity, description, evidence, remediation, screenshot_paths, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.id, finding.session_id, finding.title,
                finding.severity.value, finding.description,
                finding.evidence, finding.remediation,
                finding.screenshot_paths,
                _iso(finding.created_at),
            ),
        )
        await self.db.commit()
        return finding

    async def update_finding_screenshots(self, finding_id: str, paths: str) -> None:
        await self.db.execute(
            "UPDATE findings SET screenshot_paths = ? WHERE id = ?",
            (paths, finding_id),
        )
        await self.db.commit()

    # ------------------------------------------------------------------
    # Leads
    # ------------------------------------------------------------------

    async def create_lead(self, lead: Lead) -> Lead:
        await self.db.execute(
            """INSERT INTO leads
               (id, session_id, title, category, description, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                lead.id, lead.session_id, lead.title,
                lead.category.value, lead.description,
                lead.status.value, _iso(lead.created_at),
            ),
        )
        await self.db.commit()
        return lead

    async def get_leads(self, session_id: str) -> list[Lead]:
        async with self.db.execute(
            "SELECT * FROM leads WHERE session_id = ? ORDER BY created_at ASC", (session_id,)
        ) as cur:
            rows = await cur.fetchall()
        return [
            Lead(
                id=r["id"],
                session_id=r["session_id"],
                title=r["title"],
                category=LeadCategory(r["category"]),
                description=r["description"],
                status=LeadStatus(r["status"]),
                created_at=_parse_dt(r["created_at"]),
            )
            for r in rows
        ]

    async def update_lead_status(self, lead_id: str, status: LeadStatus) -> None:
        await self.db.execute(
            "UPDATE leads SET status = ? WHERE id = ?", (status.value, lead_id)
        )
        await self.db.commit()

    async def get_findings(self, session_id: str) -> list[Finding]:
        async with self.db.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at ASC", (session_id,)
        ) as cur:
            rows = await cur.fetchall()
        return [
            Finding(
                id=r["id"],
                session_id=r["session_id"],
                title=r["title"],
                severity=Severity(r["severity"]),
                description=r["description"],
                evidence=r["evidence"],
                remediation=r["remediation"],
                screenshot_paths=r["screenshot_paths"] if "screenshot_paths" in r.keys() else None,
                created_at=_parse_dt(r["created_at"]),
            )
            for r in rows
        ]

    async def finding_exists(self, session_id: str, title: str) -> bool:
        """Check if a finding with similar title already exists in this session."""
        async with self.db.execute(
            "SELECT 1 FROM findings WHERE session_id = ? AND LOWER(TRIM(title)) = LOWER(TRIM(?)) LIMIT 1",
            (session_id, title),
        ) as cur:
            return await cur.fetchone() is not None

    async def lead_exists(self, session_id: str, title: str) -> bool:
        """Check if a lead with similar title already exists in this session."""
        async with self.db.execute(
            "SELECT 1 FROM leads WHERE session_id = ? AND LOWER(TRIM(title)) = LOWER(TRIM(?)) LIMIT 1",
            (session_id, title),
        ) as cur:
            return await cur.fetchone() is not None

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    async def create_user(self, user: dict) -> dict:
        """Insert a new user. Expects dict with id, username, password_hash, role, created_at."""
        await self.db.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (user["id"], user["username"], user["password_hash"], user["role"], user["created_at"]),
        )
        await self.db.commit()
        return {k: v for k, v in user.items() if k != "password_hash"}

    async def get_user_by_username(self, username: str) -> Optional[dict]:
        """Get a user by username (includes password_hash for login verification)."""
        async with self.db.execute("SELECT * FROM users WHERE username = ?", (username,)) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "password_hash": row["password_hash"],
            "role": row["role"],
            "created_at": row["created_at"],
        }

    async def get_user(self, user_id: str) -> Optional[dict]:
        """Get a user by id (without password_hash)."""
        async with self.db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "created_at": row["created_at"],
        }

    async def list_users(self) -> list[dict]:
        """List all users (without password_hash)."""
        async with self.db.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at ASC") as cur:
            rows = await cur.fetchall()
        return [
            {"id": r["id"], "username": r["username"], "role": r["role"], "created_at": r["created_at"]}
            for r in rows
        ]

    async def update_user_password(self, user_id: str, password_hash: str) -> None:
        """Update a user's password hash."""
        await self.db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
        )
        await self.db.commit()

    async def delete_user(self, user_id: str) -> bool:
        """Delete a user. Returns False if the user is the last admin."""
        # Check if user is an admin
        async with self.db.execute("SELECT role FROM users WHERE id = ?", (user_id,)) as cur:
            row = await cur.fetchone()
        if row is None:
            return False
        if row["role"] == "admin":
            # Count admins
            async with self.db.execute("SELECT COUNT(*) as cnt FROM users WHERE role = 'admin'") as cur:
                count_row = await cur.fetchone()
            if count_row["cnt"] <= 1:
                return False  # Can't delete last admin
        cur = await self.db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await self.db.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    async def get_project_analytics(self, project_id: str, session_id: str | None = None) -> dict:
        """Aggregate KPIs for a project, optionally filtered to a single session."""

        # Build dynamic WHERE clause
        if session_id:
            sess_where = "WHERE id = ? AND project_id = ?"
            sess_params = (session_id, project_id)
            join_where = "WHERE f.session_id = ?"
            join_params = (session_id,)
            cmd_where = "WHERE c.session_id = ?"
            cmd_params = (session_id,)
            lead_where = "WHERE l.session_id = ?"
            lead_params = (session_id,)
        else:
            sess_where = "WHERE project_id = ?"
            sess_params = (project_id,)
            join_where = "WHERE s.project_id = ?"
            join_params = (project_id,)
            cmd_where = "WHERE s.project_id = ?"
            cmd_params = (project_id,)
            lead_where = "WHERE s.project_id = ?"
            lead_params = (project_id,)

        # Sessions by phase and status
        async with self.db.execute(
            f"SELECT phase, status, COUNT(*) as cnt FROM sessions {sess_where} GROUP BY phase, status",
            sess_params,
        ) as cur:
            session_rows = await cur.fetchall()

        sessions_by_phase: dict[str, int] = {}
        sessions_by_status: dict[str, int] = {}
        total_sessions = 0
        for r in session_rows:
            sessions_by_phase[r["phase"]] = sessions_by_phase.get(r["phase"], 0) + r["cnt"]
            sessions_by_status[r["status"]] = sessions_by_status.get(r["status"], 0) + r["cnt"]
            total_sessions += r["cnt"]

        # Findings by severity
        if session_id:
            fq = f"SELECT f.severity, COUNT(*) as cnt FROM findings f {join_where} GROUP BY f.severity"
        else:
            fq = f"SELECT f.severity, COUNT(*) as cnt FROM findings f JOIN sessions s ON f.session_id = s.id {join_where} GROUP BY f.severity"
        async with self.db.execute(fq, join_params) as cur:
            finding_rows = await cur.fetchall()
        findings_by_severity = {r["severity"]: r["cnt"] for r in finding_rows}
        total_findings = sum(findings_by_severity.values())

        # Commands by status + risk
        if session_id:
            cq = f"SELECT c.status, c.risk_level, COUNT(*) as cnt FROM commands c {cmd_where} GROUP BY c.status, c.risk_level"
        else:
            cq = f"SELECT c.status, c.risk_level, COUNT(*) as cnt FROM commands c JOIN sessions s ON c.session_id = s.id {cmd_where} GROUP BY c.status, c.risk_level"
        async with self.db.execute(cq, cmd_params) as cur:
            cmd_rows = await cur.fetchall()

        commands_by_status: dict[str, int] = {}
        commands_by_risk: dict[str, int] = {}
        total_commands = 0
        for r in cmd_rows:
            commands_by_status[r["status"]] = commands_by_status.get(r["status"], 0) + r["cnt"]
            commands_by_risk[r["risk_level"]] = commands_by_risk.get(r["risk_level"], 0) + r["cnt"]
            total_commands += r["cnt"]

        # Leads by status + category
        if session_id:
            lq = f"SELECT l.status, l.category, COUNT(*) as cnt FROM leads l {lead_where} GROUP BY l.status, l.category"
        else:
            lq = f"SELECT l.status, l.category, COUNT(*) as cnt FROM leads l JOIN sessions s ON l.session_id = s.id {lead_where} GROUP BY l.status, l.category"
        async with self.db.execute(lq, lead_params) as cur:
            lead_rows = await cur.fetchall()

        leads_by_status: dict[str, int] = {}
        leads_by_category: dict[str, int] = {}
        total_leads = 0
        for r in lead_rows:
            leads_by_status[r["status"]] = leads_by_status.get(r["status"], 0) + r["cnt"]
            leads_by_category[r["category"]] = leads_by_category.get(r["category"], 0) + r["cnt"]
            total_leads += r["cnt"]

        # Findings timeline (grouped by date)
        if session_id:
            tq = f"SELECT DATE(f.created_at) as day, f.severity, COUNT(*) as cnt FROM findings f {join_where} GROUP BY day, f.severity ORDER BY day"
        else:
            tq = f"SELECT DATE(f.created_at) as day, f.severity, COUNT(*) as cnt FROM findings f JOIN sessions s ON f.session_id = s.id {join_where} GROUP BY day, f.severity ORDER BY day"
        async with self.db.execute(tq, join_params) as cur:
            timeline_rows = await cur.fetchall()

        findings_timeline: list[dict] = []
        day_map: dict[str, dict] = {}
        for r in timeline_rows:
            day = r["day"]
            if day not in day_map:
                day_map[day] = {"date": day, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                findings_timeline.append(day_map[day])
            day_map[day][r["severity"]] = r["cnt"]

        # Top findings (latest 10)
        if session_id:
            rq = f"""SELECT f.title, f.severity, f.created_at, '{session_id}' as target
                     FROM findings f {join_where}
                     ORDER BY f.created_at DESC LIMIT 10"""
        else:
            rq = f"""SELECT f.title, f.severity, f.created_at, s.target
                     FROM findings f JOIN sessions s ON f.session_id = s.id {join_where}
                     ORDER BY f.created_at DESC LIMIT 10"""
        async with self.db.execute(rq, join_params) as cur:
            top_rows = await cur.fetchall()
        recent_findings = [
            {"title": r["title"], "severity": r["severity"], "created_at": r["created_at"], "target": r["target"]}
            for r in top_rows
        ]

        # Weighted risk score
        severity_weights = {"critical": 40, "high": 20, "medium": 5, "low": 1, "info": 0}
        risk_score = sum(findings_by_severity.get(s, 0) * w for s, w in severity_weights.items())

        return {
            "total_sessions": total_sessions,
            "total_findings": total_findings,
            "total_commands": total_commands,
            "total_leads": total_leads,
            "risk_score": risk_score,
            "sessions_by_phase": sessions_by_phase,
            "sessions_by_status": sessions_by_status,
            "findings_by_severity": findings_by_severity,
            "commands_by_status": commands_by_status,
            "commands_by_risk": commands_by_risk,
            "leads_by_status": leads_by_status,
            "leads_by_category": leads_by_category,
            "findings_timeline": findings_timeline,
            "recent_findings": recent_findings,
        }

    # ------------------------------------------------------------------
    # Scan Profiles
    # ------------------------------------------------------------------

    _DEFAULT_PROFILES = [
        {
            "name": "Full Scan",
            "description": "Todas as ferramentas — recon completo, enumeração, exploração e probes",
            "tools": [
                "httpx", "whatweb", "nmap", "curl", "katana", "subfinder",
                "nuclei", "nikto", "ffuf", "gobuster", "feroxbuster",
                "js_analyze", "tech_detect", "wafw00f", "gau", "amass",
                "sqli_probe", "xss_probe", "idor_probe", "cors_probe",
                "lfi_probe", "redirect_probe", "header_probe",
                "sqlmap", "commix", "dalfox", "hydra", "wfuzz", "arjun",
                "testssl", "wpscan", "takeover_probe", "exec",
                "whois", "dig",
            ],
        },
        {
            "name": "Web App",
            "description": "Scan web focado — sem port scan (nmap), sem DNS/subdomain. Ideal para apps web conhecidas",
            "tools": [
                "httpx", "whatweb", "curl", "katana",
                "nuclei", "nikto", "ffuf", "gobuster", "feroxbuster",
                "js_analyze", "tech_detect", "wafw00f", "gau",
                "sqli_probe", "xss_probe", "idor_probe", "cors_probe",
                "lfi_probe", "redirect_probe", "header_probe",
                "sqlmap", "dalfox", "wfuzz", "arjun", "exec",
            ],
        },
        {
            "name": "API Only",
            "description": "Focado em APIs REST/GraphQL — probes de auth, IDOR, injection, sem crawling",
            "tools": [
                "httpx", "curl",
                "nuclei", "js_analyze", "arjun",
                "sqli_probe", "idor_probe", "cors_probe",
                "header_probe", "exec",
            ],
        },
        {
            "name": "Auth & SQLi",
            "description": "Focado em autenticação e SQL injection — login brute, SQLi, IDOR",
            "tools": [
                "httpx", "curl",
                "sqli_probe", "sqlmap", "idor_probe",
                "hydra", "header_probe", "exec",
            ],
        },
        {
            "name": "Recon Only",
            "description": "Apenas reconhecimento passivo — sem exploração, sem probes ativos",
            "tools": [
                "httpx", "whatweb", "nmap", "curl", "katana", "subfinder",
                "js_analyze", "tech_detect", "wafw00f", "gau", "amass",
                "whois", "dig", "testssl",
            ],
        },
    ]

    async def _seed_default_profiles(self) -> None:
        async with self.db.execute("SELECT COUNT(*) FROM scan_profiles") as cur:
            row = await cur.fetchone()
            if row[0] > 0:
                return
        from models import ScanProfile as _SP
        for i, p in enumerate(self._DEFAULT_PROFILES):
            profile = _SP(
                name=p["name"],
                description=p["description"],
                tools=p["tools"],
                is_default=True,
            )
            await self.db.execute(
                """INSERT INTO scan_profiles (id, name, description, tools, is_default, created_at)
                   VALUES (?, ?, ?, ?, 1, ?)""",
                (profile.id, profile.name, profile.description, json.dumps(profile.tools), _iso(profile.created_at)),
            )
        await self.db.commit()

    def _row_to_profile(self, row) -> ScanProfile:
        return ScanProfile(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            tools=json.loads(row["tools"]),
            is_default=bool(row["is_default"]),
            created_at=_parse_dt(row["created_at"]),
        )

    async def get_profiles(self) -> list[ScanProfile]:
        async with self.db.execute("SELECT * FROM scan_profiles ORDER BY is_default DESC, name ASC") as cur:
            rows = await cur.fetchall()
        return [self._row_to_profile(r) for r in rows]

    async def get_profile(self, profile_id: str) -> ScanProfile | None:
        async with self.db.execute("SELECT * FROM scan_profiles WHERE id = ?", (profile_id,)) as cur:
            row = await cur.fetchone()
        return self._row_to_profile(row) if row else None

    async def create_profile(self, profile: ScanProfile) -> None:
        await self.db.execute(
            """INSERT INTO scan_profiles (id, name, description, tools, is_default, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (profile.id, profile.name, profile.description, json.dumps(profile.tools),
             int(profile.is_default), _iso(profile.created_at)),
        )
        await self.db.commit()

    async def update_profile(self, profile_id: str, **kwargs) -> None:
        sets = []
        params = []
        if "name" in kwargs and kwargs["name"] is not None:
            sets.append("name = ?")
            params.append(kwargs["name"])
        if "description" in kwargs and kwargs["description"] is not None:
            sets.append("description = ?")
            params.append(kwargs["description"])
        if "tools" in kwargs and kwargs["tools"] is not None:
            sets.append("tools = ?")
            params.append(json.dumps(kwargs["tools"]))
        if not sets:
            return
        params.append(profile_id)
        await self.db.execute(f"UPDATE scan_profiles SET {', '.join(sets)} WHERE id = ?", params)
        await self.db.commit()

    async def delete_profile(self, profile_id: str) -> bool:
        async with self.db.execute("SELECT is_default FROM scan_profiles WHERE id = ?", (profile_id,)) as cur:
            row = await cur.fetchone()
        if not row:
            return False
        if row["is_default"]:
            return False
        await self.db.execute("DELETE FROM scan_profiles WHERE id = ?", (profile_id,))
        await self.db.commit()
        return True

    # ------------------------------------------------------------------
    # Custom Tools
    # ------------------------------------------------------------------

    def _row_to_custom_tool(self, row: aiosqlite.Row) -> CustomTool:
        return CustomTool(
            id=row["id"],
            name=row["name"],
            display_name=row["display_name"] or "",
            description=row["description"] or "",
            category=row["category"],
            binary_path=row["binary_path"],
            args_template=row["args_template"] or "",
            risk=row["risk"],
            timeout=row["timeout"],
            created_at=_parse_dt(row["created_at"]),
        )

    async def get_custom_tools(self) -> list[CustomTool]:
        async with self.db.execute("SELECT * FROM custom_tools ORDER BY name") as cur:
            return [self._row_to_custom_tool(r) for r in await cur.fetchall()]

    async def get_custom_tool(self, tool_id: str) -> CustomTool | None:
        async with self.db.execute("SELECT * FROM custom_tools WHERE id = ?", (tool_id,)) as cur:
            row = await cur.fetchone()
        return self._row_to_custom_tool(row) if row else None

    async def create_custom_tool(self, tool: CustomTool) -> None:
        await self.db.execute(
            """INSERT INTO custom_tools (id, name, display_name, description, category,
               binary_path, args_template, risk, timeout, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tool.id, tool.name, tool.display_name, tool.description, tool.category,
             tool.binary_path, tool.args_template, tool.risk, tool.timeout,
             _iso(tool.created_at)),
        )
        await self.db.commit()

    async def update_custom_tool(self, tool_id: str, **kwargs) -> None:
        sets, params = [], []
        for col in ("name", "display_name", "description", "category",
                     "binary_path", "args_template", "risk", "timeout"):
            if col in kwargs and kwargs[col] is not None:
                sets.append(f"{col} = ?")
                params.append(kwargs[col])
        if not sets:
            return
        params.append(tool_id)
        await self.db.execute(f"UPDATE custom_tools SET {', '.join(sets)} WHERE id = ?", params)
        await self.db.commit()

    async def delete_custom_tool(self, tool_id: str) -> bool:
        async with self.db.execute("SELECT id FROM custom_tools WHERE id = ?", (tool_id,)) as cur:
            row = await cur.fetchone()
        if not row:
            return False
        await self.db.execute("DELETE FROM custom_tools WHERE id = ?", (tool_id,))
        await self.db.commit()
        return True
