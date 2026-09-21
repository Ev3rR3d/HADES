import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { getProject, updateProject, createSession, deleteSession, getProfiles } from '../api';

// ── Severity Config ─────────────────────────────────────────────────────────

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30', dot: 'bg-red-500' },
  high: { label: 'High', color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/30', dot: 'bg-orange-500' },
  medium: { label: 'Medium', color: 'text-amber-400', bg: 'bg-amber-400/10', border: 'border-amber-400/30', dot: 'bg-amber-400' },
  low: { label: 'Low', color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/30', dot: 'bg-blue-400' },
  info: { label: 'Info', color: 'text-gray-400', bg: 'bg-gray-400/10', border: 'border-gray-400/30', dot: 'bg-gray-400' },
};

// ── Edit Project Modal ──────────────────────────────────────────────────────

function EditProjectModal({ project, onClose, onSave }) {
  const [name, setName] = useState(project.name || '');
  const [client, setClient] = useState(project.client || '');
  const [description, setDescription] = useState(project.description || '');
  const [scope, setScope] = useState((project.scope || []).join('\n'));
  const [startDate, setStartDate] = useState(project.start_date || '');
  const [endDate, setEndDate] = useState(project.end_date || '');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name.trim()) return;

    setSubmitting(true);
    setError(null);
    try {
      const scopeList = scope
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);

      const data = {
        name: name.trim(),
        client: client.trim() || undefined,
        description: description.trim() || undefined,
        scope: scopeList.length > 0 ? scopeList : [],
        start_date: startDate || undefined,
        end_date: endDate || undefined,
      };

      await onSave(data);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold text-gray-100">Edit Project</h2>
          <button
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-gray-100 transition-colors rounded-lg hover:bg-gray-800"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1.5">
              Project Name <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Pentest Acme Corp Q4"
              className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-100
                         placeholder-gray-500 text-sm focus:outline-none focus:border-cyan-400/50
                         focus:ring-1 focus:ring-cyan-400/20 transition-all duration-200"
              autoFocus
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1.5">Client</label>
            <input
              type="text"
              value={client}
              onChange={(e) => setClient(e.target.value)}
              placeholder="e.g., Acme Corporation"
              className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-100
                         placeholder-gray-500 text-sm focus:outline-none focus:border-cyan-400/50
                         focus:ring-1 focus:ring-cyan-400/20 transition-all duration-200"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1.5">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief description of the engagement..."
              rows={2}
              className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-100
                         placeholder-gray-500 text-sm resize-none focus:outline-none focus:border-cyan-400/50
                         focus:ring-1 focus:ring-cyan-400/20 transition-all duration-200"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1.5">Scope</label>
            <textarea
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              placeholder={"Enter targets, one per line (IPs, ranges, domains)"}
              rows={4}
              className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-100
                         placeholder-gray-500 text-sm font-mono resize-none focus:outline-none
                         focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20 transition-all duration-200"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1.5">Start Date</label>
              <input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-100
                           text-sm focus:outline-none focus:border-cyan-400/50 focus:ring-1
                           focus:ring-cyan-400/20 transition-all duration-200
                           [color-scheme:dark]"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1.5">End Date</label>
              <input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-100
                           text-sm focus:outline-none focus:border-cyan-400/50 focus:ring-1
                           focus:ring-cyan-400/20 transition-all duration-200
                           [color-scheme:dark]"
              />
            </div>
          </div>

          {error && (
            <div className="px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">
              {error}
            </div>
          )}

          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2.5 bg-gray-800 text-gray-400 border border-gray-700
                         rounded-lg text-sm font-medium hover:bg-gray-700 hover:text-gray-200
                         transition-all duration-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!name.trim() || submitting}
              className="flex-1 px-4 py-2.5 bg-cyan-400/20 text-cyan-400 border border-cyan-400/30
                         rounded-lg text-sm font-medium hover:bg-cyan-400/30 hover:border-cyan-400/50
                         transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── New Session Modal ───────────────────────────────────────────────────────

function NewSessionModal({ scopeList, onClose, onCreate }) {
  const [name, setName] = useState('');
  const [target, setTarget] = useState('');
  const [profileId, setProfileId] = useState('');
  const [profiles, setProfiles] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    getProfiles().then(p => {
      setProfiles(p);
      const fullScan = p.find(pr => pr.name === 'Full Scan');
      if (fullScan) setProfileId(fullScan.id);
    }).catch(() => {});
  }, []);

  const handleScopeSelect = (t) => {
    setTarget(t);
    if (!name.trim()) {
      setName(`Recon - ${t}`);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name.trim() || !target.trim()) return;

    setSubmitting(true);
    setError(null);
    try {
      await onCreate(name.trim(), target.trim(), profileId || null);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const selectedProfile = profiles.find(p => p.id === profileId);

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold text-gray-100">New Session</h2>
          <button
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-gray-100 transition-colors rounded-lg hover:bg-gray-800"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          {/* Target from scope */}
          {scopeList && scopeList.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1.5">Select from Scope</label>
              <div className="flex flex-wrap gap-2">
                {scopeList.map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => handleScopeSelect(t)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition-all duration-200 ${
                      target === t
                        ? 'bg-cyan-400/20 text-cyan-400 border-cyan-400/50'
                        : 'bg-gray-800 text-gray-400 border-gray-700 hover:border-gray-500 hover:text-gray-200'
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Session Name */}
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1.5">Session Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Recon - 10.10.10.50"
              className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-100
                         placeholder-gray-500 text-sm focus:outline-none focus:border-cyan-400/50
                         focus:ring-1 focus:ring-cyan-400/20 transition-all duration-200"
              autoFocus
            />
          </div>

          {/* Target (free text) */}
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1.5">Target</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g., 10.10.10.1 or target.com"
              className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-100
                         placeholder-gray-500 text-sm font-mono focus:outline-none focus:border-cyan-400/50
                         focus:ring-1 focus:ring-cyan-400/20 transition-all duration-200"
            />
          </div>

          {/* Scan Profile */}
          {profiles.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1.5">Scan Profile</label>
              <select
                value={profileId}
                onChange={(e) => setProfileId(e.target.value)}
                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-100
                           text-sm focus:outline-none focus:border-cyan-400/50
                           focus:ring-1 focus:ring-cyan-400/20 transition-all duration-200 appearance-none"
              >
                {profiles.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.tools?.length || 0} tools)
                  </option>
                ))}
              </select>
              {selectedProfile && (
                <p className="text-[11px] text-gray-500 mt-1">{selectedProfile.description}</p>
              )}
            </div>
          )}

          {error && (
            <div className="px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">
              {error}
            </div>
          )}

          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2.5 bg-gray-800 text-gray-400 border border-gray-700
                         rounded-lg text-sm font-medium hover:bg-gray-700 hover:text-gray-200
                         transition-all duration-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!name.trim() || !target.trim() || submitting}
              className="flex-1 px-4 py-2.5 bg-cyan-400/20 text-cyan-400 border border-cyan-400/30
                         rounded-lg text-sm font-medium hover:bg-cyan-400/30 hover:border-cyan-400/50
                         transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? 'Creating...' : 'Launch Session'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Session Card ────────────────────────────────────────────────────────────

function SessionCard({ session, onDelete, onNavigate }) {
  const [confirmDelete, setConfirmDelete] = useState(false);

  const statusColor = session.status === 'active'
    ? 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30'
    : 'text-gray-400 bg-gray-400/10 border-gray-400/30';

  const findingCount = session.finding_count || session.findings?.length || 0;

  const handleDelete = async (e) => {
    e.stopPropagation();
    if (!confirmDelete) {
      setConfirmDelete(true);
      setTimeout(() => setConfirmDelete(false), 3000);
      return;
    }
    try {
      await onDelete(session.id);
    } catch (err) {
      console.error('Failed to delete session:', err);
    }
  };

  return (
    <div
      onClick={() => onNavigate(session.id)}
      className="group flex items-center justify-between bg-gray-800 border border-gray-700 rounded-lg p-4 cursor-pointer
                 hover:border-cyan-400/30 hover:bg-gray-800/80 transition-all duration-200"
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-3 mb-1">
          <span className="text-sm font-medium text-gray-100 group-hover:text-cyan-400 transition-colors truncate">
            {session.name}
          </span>
          <span className={`px-2 py-0.5 rounded border text-xs font-medium ${statusColor}`}>
            {session.phase || session.status || 'active'}
          </span>
        </div>
        <div className="flex items-center gap-3 text-xs text-gray-500">
          <span className="font-mono">{session.target}</span>
          {findingCount > 0 && (
            <span className="flex items-center gap-1">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              {findingCount} finding{findingCount !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>
      <button
        onClick={handleDelete}
        className={`flex-shrink-0 p-1.5 rounded-lg transition-all duration-200 ml-3 ${
          confirmDelete
            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
            : 'text-gray-600 hover:text-gray-400 hover:bg-gray-700'
        }`}
        title={confirmDelete ? 'Click again to confirm' : 'Delete session'}
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
        </svg>
      </button>
    </div>
  );
}

// ── ProjectView ─────────────────────────────────────────────────────────────

export default function ProjectView() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [project, setProject] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [totalFindings, setTotalFindings] = useState(0);
  const [findingsBySeverity, setFindingsBySeverity] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [showEditModal, setShowEditModal] = useState(false);
  const [showSessionModal, setShowSessionModal] = useState(false);

  const fetchProject = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getProject(id);
      setProject(data.project || data);
      setSessions(data.sessions || []);
      setTotalFindings(data.total_findings || 0);
      setFindingsBySeverity(data.findings_by_severity || {});
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchProject();
  }, [fetchProject]);

  const handleEditSave = async (data) => {
    const updated = await updateProject(id, data);
    setProject(updated.project || updated);
    if (updated.sessions) setSessions(updated.sessions);
  };

  const handleCreateSession = async (name, target, profileId) => {
    const session = await createSession(id, name, target, profileId);
    navigate(`/session/${session.id}`);
  };

  const handleDeleteSession = async (sessionId) => {
    await deleteSession(sessionId);
    setSessions((prev) => prev.filter((s) => s.id !== sessionId));
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return null;
    return new Date(dateStr).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="flex items-center gap-3 text-gray-400">
          <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
          </svg>
          Loading project...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="text-center">
          <div className="text-red-400 mb-4">{error}</div>
          <button
            onClick={() => navigate('/')}
            className="text-sm text-cyan-400 hover:underline"
          >
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  const status = project?.status || 'active';
  const statusConfig = {
    active: { label: 'Active', classes: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30' },
    completed: { label: 'Completed', classes: 'text-gray-400 bg-gray-400/10 border-gray-400/30' },
    archived: { label: 'Archived', classes: 'text-gray-600 bg-gray-600/10 border-gray-600/30' },
  };
  const statusCfg = statusConfig[status] || statusConfig.active;

  const scopeList = project?.scope || [];
  const startFormatted = formatDate(project?.start_date);
  const endFormatted = formatDate(project?.end_date);

  return (
    <div className="min-h-screen">
      <div className="max-w-6xl mx-auto px-6 py-8">
        {/* Page header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3 min-w-0">
            <button
              onClick={() => navigate('/')}
              className="p-1.5 text-gray-500 hover:text-gray-300 transition-colors rounded-lg hover:bg-gray-800/50 flex-shrink-0"
              title="Back to Dashboard"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
              </svg>
            </button>
            <h1 className="text-xl font-bold text-gray-100 truncate">
              {project?.name}
            </h1>
          </div>
          <button
            onClick={() => setShowEditModal(true)}
            className="p-2 text-gray-500 hover:text-gray-300 transition-colors rounded-lg hover:bg-gray-800/50 flex-shrink-0"
            title="Edit project"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </button>
        </div>

      <div className="space-y-8">
        {/* Project Info */}
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
          <div className="flex flex-wrap items-center gap-3 mb-4">
            <span className={`px-2.5 py-1 rounded border text-xs font-medium ${statusCfg.classes}`}>
              {statusCfg.label}
            </span>
            {(startFormatted || endFormatted) && (
              <span className="text-sm text-gray-400">
                {startFormatted && endFormatted
                  ? `${startFormatted} - ${endFormatted}`
                  : startFormatted
                  ? `Starts ${startFormatted}`
                  : `Ends ${endFormatted}`}
              </span>
            )}
          </div>

          {project?.client && (
            <div className="text-sm text-gray-400 mb-2">
              Client: <span className="text-gray-200">{project.client}</span>
            </div>
          )}

          {project?.description && (
            <p className="text-sm text-gray-400 mb-4">{project.description}</p>
          )}

          {/* Scope */}
          {scopeList.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Scope</h3>
              <div className="flex flex-wrap gap-2">
                {scopeList.map((target) => (
                  <span
                    key={target}
                    className="px-3 py-1 bg-gray-800 border border-gray-700 rounded-lg text-xs font-mono text-gray-300"
                  >
                    {target}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Findings Summary */}
        {totalFindings > 0 && (
          <div>
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
              Findings Summary
            </h2>
            <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
              <div className="flex flex-wrap gap-4">
                {Object.entries(findingsBySeverity).map(([severity, count]) => {
                  const cfg = SEVERITY_CONFIG[severity.toLowerCase()] || SEVERITY_CONFIG.info;
                  return (
                    <div
                      key={severity}
                      className={`flex items-center gap-2 px-4 py-2 rounded-lg border ${cfg.bg} ${cfg.border}`}
                    >
                      <div className={`w-2.5 h-2.5 rounded-full ${cfg.dot}`} />
                      <span className={`text-sm font-semibold ${cfg.color}`}>{count}</span>
                      <span className="text-sm text-gray-400">{cfg.label}</span>
                    </div>
                  );
                })}
                <div className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-700 bg-gray-800">
                  <span className="text-sm font-semibold text-gray-200">{totalFindings}</span>
                  <span className="text-sm text-gray-400">Total</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Sessions Section */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
              Sessions ({sessions.length})
            </h2>
            <button
              onClick={() => setShowSessionModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-400/10 text-cyan-400
                         border border-cyan-400/30 rounded-lg text-sm font-medium
                         hover:bg-cyan-400/20 hover:border-cyan-400/50 hover:shadow-cyan-glow
                         transition-all duration-300"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              New Session
            </button>
          </div>

          {sessions.length === 0 ? (
            <div className="bg-gray-900 border border-gray-700 rounded-xl p-8 text-center">
              <div className="w-14 h-14 mx-auto mb-4 rounded-xl bg-gray-800 border border-gray-700 flex items-center justify-center">
                <svg className="w-7 h-7 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
              <p className="text-sm text-gray-500 mb-4">No sessions yet. Create one to start hacking.</p>
              <button
                onClick={() => setShowSessionModal(true)}
                className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-400/10 text-cyan-400
                           border border-cyan-400/30 rounded-lg text-sm font-medium
                           hover:bg-cyan-400/20 hover:border-cyan-400/50 transition-all duration-200"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
                New Session
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              {sessions.map((session) => (
                <SessionCard
                  key={session.id}
                  session={session}
                  onDelete={handleDeleteSession}
                  onNavigate={(sid) => navigate(`/session/${sid}`)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
      </div>

      {/* Modals */}
      {showEditModal && project && (
        <EditProjectModal
          project={project}
          onClose={() => setShowEditModal(false)}
          onSave={handleEditSave}
        />
      )}

      {showSessionModal && (
        <NewSessionModal
          scopeList={scopeList}
          onClose={() => setShowSessionModal(false)}
          onCreate={handleCreateSession}
        />
      )}
    </div>
  );
}
