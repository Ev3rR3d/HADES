"""Pydantic models for the HADES backend."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SessionStatus(str, Enum):
    active = "active"
    completed = "completed"


class ProjectStatus(str, Enum):
    active = "active"
    completed = "completed"
    archived = "archived"


class MessageRole(str, Enum):
    user = "user"
    assistant = "assistant"
    system = "system"
    tool_result = "tool_result"


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Phase(str, Enum):
    recon = "recon"
    scanning = "scanning"
    enumeration = "enumeration"
    exploitation = "exploitation"
    post_exploitation = "post_exploitation"
    reporting = "reporting"


class CommandStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    executed = "executed"
    failed = "failed"


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class LeadCategory(str, Enum):
    route = "route"
    technology = "technology"
    config = "config"
    credential = "credential"
    exposure = "exposure"
    other = "other"


class LeadStatus(str, Enum):
    open = "open"
    investigating = "investigating"
    escalated = "escalated"
    dismissed = "dismissed"


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class Project(BaseModel):
    id: str = Field(default_factory=_uuid)
    name: str
    client: str = ""
    description: str = ""
    scope: list[str] = Field(default_factory=list)
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    status: ProjectStatus = ProjectStatus.active
    created_at: datetime = Field(default_factory=_utcnow)


class Session(BaseModel):
    id: str = Field(default_factory=_uuid)
    project_id: str
    name: str
    target: str
    profile_id: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)
    status: SessionStatus = SessionStatus.active
    phase: Phase = Phase.recon


class Message(BaseModel):
    id: str = Field(default_factory=_uuid)
    session_id: str
    role: MessageRole
    content: str
    tool_call_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=_utcnow)


class PendingCommand(BaseModel):
    id: str = Field(default_factory=_uuid)
    session_id: str
    command: str
    reason: str
    risk_level: RiskLevel = RiskLevel.medium
    phase: Phase = Phase.recon
    status: CommandStatus = CommandStatus.pending
    output: Optional[str] = None
    exit_code: Optional[int] = None
    created_at: datetime = Field(default_factory=_utcnow)
    tool_use_id: Optional[str] = None


class Finding(BaseModel):
    id: str = Field(default_factory=_uuid)
    session_id: str
    title: str
    severity: Severity = Severity.info
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    screenshot_paths: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)


class Lead(BaseModel):
    id: str = Field(default_factory=_uuid)
    session_id: str
    title: str
    category: LeadCategory = LeadCategory.other
    description: str
    status: LeadStatus = LeadStatus.open
    created_at: datetime = Field(default_factory=_utcnow)


class TargetInfo(BaseModel):
    ip: Optional[str] = None
    hostname: Optional[str] = None
    ports: list[int] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    os_info: Optional[str] = None
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Request / response helpers
# ---------------------------------------------------------------------------

class CreateProjectRequest(BaseModel):
    name: str
    client: str = ""
    description: str = ""
    scope: list[str] = Field(default_factory=list)
    start_date: Optional[str] = None
    end_date: Optional[str] = None


class ScanProfile(BaseModel):
    id: str = Field(default_factory=_uuid)
    name: str
    description: str = ""
    tools: list[str] = Field(default_factory=list)
    is_default: bool = False
    created_at: datetime = Field(default_factory=_utcnow)


class CreateSessionRequest(BaseModel):
    project_id: str
    name: str
    target: str
    profile_id: Optional[str] = None


class CustomTool(BaseModel):
    id: str = Field(default_factory=_uuid)
    name: str
    display_name: str = ""
    description: str = ""
    category: str = "recon"
    binary_path: str = ""
    args_template: str = ""
    risk: str = "low"
    timeout: int = 120
    created_at: datetime = Field(default_factory=_utcnow)


class CreateCustomToolRequest(BaseModel):
    name: str
    display_name: str = ""
    description: str = ""
    category: str = "recon"
    binary_path: str
    args_template: str = ""
    risk: str = "low"
    timeout: int = 120


class UpdateCustomToolRequest(BaseModel):
    name: Optional[str] = None
    display_name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    binary_path: Optional[str] = None
    args_template: Optional[str] = None
    risk: Optional[str] = None
    timeout: Optional[int] = None


class CreateProfileRequest(BaseModel):
    name: str
    description: str = ""
    tools: list[str] = Field(default_factory=list)


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tools: Optional[list[str]] = None


class SessionResponse(BaseModel):
    session: Session
    messages: list[Message] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    leads: list[Lead] = Field(default_factory=list)
    pending_commands: list[PendingCommand] = Field(default_factory=list)


class ProjectResponse(BaseModel):
    project: Project
    sessions: list[Session] = Field(default_factory=list)
    total_findings: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Auth request models
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "operator"


class ChangePasswordRequest(BaseModel):
    current_password: str = ""
    new_password: str
