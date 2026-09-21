const API_BASE = import.meta.env.VITE_API_URL
  || `${window.location.protocol}//${window.location.host}`;

// ── Auth helpers ─────────────────────────────────────────────────────────────

function getToken() {
  return localStorage.getItem('hades_token');
}

function authHeaders() {
  const token = getToken();
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

function checkAuth(res) {
  if (res.status === 401) {
    localStorage.removeItem('hades_token');
    window.location.href = '/login';
    throw new Error('Session expired');
  }
}

// ── Auth API ─────────────────────────────────────────────────────────────────

export async function login(username, password) {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || 'Login failed');
  }
  return res.json();
}

export async function getMe() {
  const res = await fetch(`${API_BASE}/api/auth/me`, {
    headers: { ...authHeaders() },
  });
  if (!res.ok) throw new Error('Not authenticated');
  return res.json();
}

export async function changePassword(currentPassword, newPassword) {
  const res = await fetch(`${API_BASE}/api/auth/change-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
  checkAuth(res);
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.detail || 'Failed'); }
  return res.json();
}

export async function getUsers() {
  const res = await fetch(`${API_BASE}/api/users`, { headers: { ...authHeaders() } });
  checkAuth(res);
  if (!res.ok) throw new Error('Failed to fetch users');
  return res.json();
}

export async function createUser(username, password, role) {
  const res = await fetch(`${API_BASE}/api/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ username, password, role }),
  });
  checkAuth(res);
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.detail || 'Failed'); }
  return res.json();
}

export async function deleteUser(userId) {
  const res = await fetch(`${API_BASE}/api/users/${userId}`, {
    method: 'DELETE',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.detail || 'Failed'); }
  return res.json();
}

export async function resetUserPassword(userId, newPassword) {
  const res = await fetch(`${API_BASE}/api/users/${userId}/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ new_password: newPassword }),
  });
  checkAuth(res);
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.detail || 'Failed'); }
  return res.json();
}

// ── Projects ────────────────────────────────────────────────────────────────

export async function createProject(data) {
  const res = await fetch(`${API_BASE}/api/projects`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(data),
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to create project: ${res.statusText}`);
  return res.json();
}

export async function getProjects() {
  const res = await fetch(`${API_BASE}/api/projects`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch projects: ${res.statusText}`);
  return res.json();
}

export async function getProject(id) {
  const res = await fetch(`${API_BASE}/api/projects/${id}`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch project: ${res.statusText}`);
  return res.json();
}

export async function updateProject(id, data) {
  const res = await fetch(`${API_BASE}/api/projects/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(data),
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to update project: ${res.statusText}`);
  return res.json();
}

export async function deleteProject(id) {
  const res = await fetch(`${API_BASE}/api/projects/${id}`, {
    method: 'DELETE',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to delete project: ${res.statusText}`);
  return res.json();
}

export async function getProjectAnalytics(id, sessionId) {
  const url = sessionId
    ? `${API_BASE}/api/projects/${id}/analytics?session_id=${sessionId}`
    : `${API_BASE}/api/projects/${id}/analytics`;
  const res = await fetch(url, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch analytics: ${res.statusText}`);
  return res.json();
}

export async function getProjectSessions(id) {
  const res = await fetch(`${API_BASE}/api/projects/${id}/sessions`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch project sessions: ${res.statusText}`);
  return res.json();
}

// ── Sessions ────────────────────────────────────────────────────────────────

export async function createSession(projectId, name, target, profileId) {
  const body = { project_id: projectId, name, target };
  if (profileId) body.profile_id = profileId;
  const res = await fetch(`${API_BASE}/api/sessions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to create session: ${res.statusText}`);
  return res.json();
}

export async function getSessions() {
  const res = await fetch(`${API_BASE}/api/sessions`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch sessions: ${res.statusText}`);
  return res.json();
}

export async function getSession(id) {
  const res = await fetch(`${API_BASE}/api/sessions/${id}`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch session: ${res.statusText}`);
  return res.json();
}

export async function deleteSession(id) {
  const res = await fetch(`${API_BASE}/api/sessions/${id}`, {
    method: 'DELETE',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to delete session: ${res.statusText}`);
  return res.json();
}

export async function getFindings(sessionId) {
  const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/findings`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch findings: ${res.statusText}`);
  return res.json();
}

export async function getReport(sessionId) {
  const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/report`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch report: ${res.statusText}`);
  const data = await res.json();
  return data.report;
}

export async function downloadReportPdf(sessionId) {
  const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/report/pdf`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to generate PDF: ${res.statusText}`);
  const blob = await res.blob();
  const disposition = res.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="?(.+?)"?$/);
  const filename = match ? match[1] : `HADES_Report_${sessionId}.pdf`;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function approveCommand(commandId) {
  const res = await fetch(`${API_BASE}/api/commands/${commandId}/approve`, {
    method: 'POST',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to approve command: ${res.statusText}`);
  return res.json();
}

export async function rejectCommand(commandId) {
  const res = await fetch(`${API_BASE}/api/commands/${commandId}/reject`, {
    method: 'POST',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to reject command: ${res.statusText}`);
  return res.json();
}

export async function getSkills() {
  const res = await fetch(`${API_BASE}/api/skills`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch skills: ${res.statusText}`);
  return res.json();
}

export async function getStatus() {
  const res = await fetch(`${API_BASE}/api/status`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch status: ${res.statusText}`);
  return res.json();
}

export async function pauseSession(sessionId) {
  const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/pause`, {
    method: 'POST',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to pause session: ${res.statusText}`);
  return res.json();
}

export async function resumeSession(sessionId) {
  const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/resume`, {
    method: 'POST',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to resume session: ${res.statusText}`);
  return res.json();
}

export async function stopSession(sessionId) {
  const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/stop`, {
    method: 'POST',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to stop session: ${res.statusText}`);
  return res.json();
}

export async function startScan(sessionId) {
  const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/scan`, {
    method: 'POST',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to start scan: ${res.statusText}`);
  return res.json();
}

export async function abortScan(sessionId) {
  const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/scan/abort`, {
    method: 'POST',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to abort scan: ${res.statusText}`);
  return res.json();
}

export async function skipTool(sessionId, toolName) {
  const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/scan/skip/${toolName}`, {
    method: 'POST',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to skip tool: ${res.statusText}`);
  return res.json();
}

export async function getTools() {
  const res = await fetch(`${API_BASE}/api/tools`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch tools: ${res.statusText}`);
  return res.json();
}

// ── Profiles ────────────────────────────────────────────────────────────────

export async function getProfiles() {
  const res = await fetch(`${API_BASE}/api/profiles`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch profiles: ${res.statusText}`);
  return res.json();
}

export async function createProfile(name, description, tools) {
  const res = await fetch(`${API_BASE}/api/profiles`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ name, description, tools }),
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to create profile: ${res.statusText}`);
  return res.json();
}

export async function updateProfile(id, data) {
  const res = await fetch(`${API_BASE}/api/profiles/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(data),
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to update profile: ${res.statusText}`);
  return res.json();
}

export async function deleteProfile(id) {
  const res = await fetch(`${API_BASE}/api/profiles/${id}`, {
    method: 'DELETE',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to delete profile: ${res.statusText}`);
  return res.json();
}

// ── Custom Tools ───────────────────────────────────────────────────────────

export async function getCustomTools() {
  const res = await fetch(`${API_BASE}/api/custom-tools`, {
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to fetch custom tools: ${res.statusText}`);
  return res.json();
}

export async function createCustomTool(data) {
  const res = await fetch(`${API_BASE}/api/custom-tools`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(data),
  });
  checkAuth(res);
  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    throw new Error(d.detail || `Failed to create custom tool: ${res.statusText}`);
  }
  return res.json();
}

export async function updateCustomTool(id, data) {
  const res = await fetch(`${API_BASE}/api/custom-tools/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(data),
  });
  checkAuth(res);
  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    throw new Error(d.detail || `Failed to update custom tool: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteCustomTool(id) {
  const res = await fetch(`${API_BASE}/api/custom-tools/${id}`, {
    method: 'DELETE',
    headers: { ...authHeaders() },
  });
  checkAuth(res);
  if (!res.ok) throw new Error(`Failed to delete custom tool: ${res.statusText}`);
  return res.json();
}

export function getWebSocketUrl(sessionId) {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = import.meta.env.VITE_API_URL
    ? new URL(import.meta.env.VITE_API_URL).host
    : window.location.host;
  const token = getToken();
  return `${wsProtocol}//${host}/ws/${sessionId}${token ? `?token=${token}` : ''}`;
}
