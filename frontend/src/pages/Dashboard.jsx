import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import HadesLogo from '../components/HadesLogo';

// ── New Project Modal ───────────────────────────────────────────────────────

function NewProjectModal({ onClose, onCreate }) {
  const [name, setName] = useState('');
  const [client, setClient] = useState('');
  const [description, setDescription] = useState('');
  const [scope, setScope] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
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
        scope: scopeList.length > 0 ? scopeList : undefined,
        start_date: startDate || undefined,
        end_date: endDate || undefined,
      };

      await onCreate(data);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const inputCls = `w-full px-4 py-2.5 bg-gray-800/50 border border-gray-700/60 rounded-xl text-gray-100
                     placeholder-gray-600 text-sm focus:outline-none focus:border-cyan-500/50
                     focus:ring-1 focus:ring-cyan-500/20 focus:bg-gray-800 transition-all duration-200`;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-fade-in">
      <div className="bg-gray-900/95 border border-gray-700/60 rounded-2xl w-full max-w-lg shadow-2xl shadow-black/50">
        <div className="flex items-center justify-between p-5 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-400/10 border border-cyan-400/20 flex items-center justify-center">
              <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-gray-100">Novo Projeto</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-gray-500 hover:text-gray-300 transition-colors rounded-lg hover:bg-gray-800"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wider">
              Nome do Projeto <span className="text-red-400">*</span>
            </label>
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="ex: Pentest Acme Corp Q4" className={inputCls} autoFocus />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wider">Cliente</label>
            <input type="text" value={client} onChange={(e) => setClient(e.target.value)} placeholder="ex: Acme Corporation" className={inputCls} />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wider">Descrição</label>
            <textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Descrição breve do engajamento..." rows={2} className={`${inputCls} resize-none`} />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wider">Escopo</label>
            <textarea value={scope} onChange={(e) => setScope(e.target.value)} placeholder={"Alvos, um por linha\nex: 10.10.10.0/24\n*.acme.com"} rows={4} className={`${inputCls} font-mono resize-none`} />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wider">Data Início</label>
              <input type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} className={`${inputCls} [color-scheme:dark]`} />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wider">Data Fim</label>
              <input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} className={`${inputCls} [color-scheme:dark]`} />
            </div>
          </div>

          {error && (
            <div className="px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">{error}</div>
          )}

          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose}
              className="flex-1 px-4 py-2.5 bg-gray-800 text-gray-400 border border-gray-700 rounded-xl text-sm font-medium hover:bg-gray-700 hover:text-gray-200 transition-all duration-200">
              Cancelar
            </button>
            <button type="submit" disabled={!name.trim() || submitting}
              className="flex-1 px-4 py-2.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-xl text-sm font-semibold hover:bg-cyan-500/30 hover:border-cyan-500/50 hover:shadow-cyan-glow transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed">
              {submitting ? 'Criando...' : 'Criar Projeto'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Stat Card ───────────────────────────────────────────────────────────────

function StatCard({ label, value, icon, accent = 'cyan' }) {
  const accents = {
    cyan: 'text-cyan-400 bg-cyan-400/[0.06] border-cyan-400/10',
    red: 'text-red-400 bg-red-400/[0.06] border-red-400/10',
    amber: 'text-amber-400 bg-amber-400/[0.06] border-amber-400/10',
    emerald: 'text-emerald-400 bg-emerald-400/[0.06] border-emerald-400/10',
  };

  return (
    <div className={`rounded-xl border px-4 py-3.5 ${accents[accent]}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-semibold uppercase tracking-wider opacity-60">{label}</span>
        <span className="opacity-40">{icon}</span>
      </div>
      <p className="text-2xl font-bold tabular-nums">{value}</p>
    </div>
  );
}

// ── Project Card ────────────────────────────────────────────────────────────

function ProjectCard({ project, onDelete, onNavigate }) {
  const [confirmDelete, setConfirmDelete] = useState(false);

  const status = project.status || 'active';
  const statusConfig = {
    active: { label: 'Ativo', dot: 'bg-emerald-400', text: 'text-emerald-400' },
    completed: { label: 'Concluído', dot: 'bg-gray-400', text: 'text-gray-400' },
    archived: { label: 'Arquivado', dot: 'bg-gray-600', text: 'text-gray-600' },
  };
  const statusCfg = statusConfig[status] || statusConfig.active;

  const scopeList = project.scope || [];
  const sessionCount = project.session_count || 0;
  const findingCount = project.total_findings || 0;

  const handleDelete = async (e) => {
    e.stopPropagation();
    if (!confirmDelete) {
      setConfirmDelete(true);
      setTimeout(() => setConfirmDelete(false), 3000);
      return;
    }
    try {
      await onDelete(project.id);
    } catch (err) {
      console.error('Failed to delete project:', err);
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return null;
    return new Date(dateStr).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  return (
    <div
      onClick={() => onNavigate(project.id)}
      className="group relative bg-gray-900/60 border border-gray-800/60 rounded-2xl p-5 cursor-pointer
                 hover:border-cyan-500/20 hover:bg-gray-900/80 transition-all duration-300 animate-fade-in"
    >
      <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-cyan-500/[0.02] to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />

      <div className="relative">
        <div className="flex items-start justify-between mb-3">
          <h3 className="text-sm font-semibold text-gray-200 group-hover:text-cyan-400 transition-colors truncate pr-3 flex-1">
            {project.name}
          </h3>
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className={`flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider ${statusCfg.text}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${statusCfg.dot}`} />
              {statusCfg.label}
            </span>
            <button
              onClick={handleDelete}
              className={`p-1.5 rounded-lg transition-all duration-200 ${
                confirmDelete
                  ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                  : 'text-gray-700 hover:text-gray-400 hover:bg-gray-800 opacity-0 group-hover:opacity-100'
              }`}
              title={confirmDelete ? 'Click again to confirm' : 'Delete project'}
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
          </div>
        </div>

        {project.client && (
          <p className="text-xs text-gray-500 mb-3">{project.client}</p>
        )}

        {scopeList.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-3">
            {scopeList.slice(0, 3).map((t) => (
              <span key={t} className="px-2 py-0.5 bg-gray-800/80 border border-gray-700/40 rounded-md text-[11px] font-mono text-gray-500">
                {t}
              </span>
            ))}
            {scopeList.length > 3 && (
              <span className="px-2 py-0.5 text-[11px] text-gray-600">+{scopeList.length - 3}</span>
            )}
          </div>
        )}

        <div className="flex items-center gap-4 text-[11px] text-gray-600 pt-3 border-t border-gray-800/40">
          <span className="flex items-center gap-1.5">
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            {sessionCount} {sessionCount !== 1 ? 'sessões' : 'sessão'}
          </span>
          {findingCount > 0 && (
            <span className="flex items-center gap-1.5 text-cyan-500/60">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              {findingCount} finding{findingCount !== 1 ? 's' : ''}
            </span>
          )}
          {(formatDate(project.start_date) || formatDate(project.end_date)) && (
            <span className="ml-auto text-gray-700">
              {formatDate(project.start_date)}
              {project.start_date && project.end_date && ' — '}
              {formatDate(project.end_date)}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Dashboard ───────────────────────────────────────────────────────────────

export default function Dashboard() {
  const { projects, projectsLoading, projectsError, createProject, removeProject } = useApp();
  const [showModal, setShowModal] = useState(false);
  const navigate = useNavigate();

  const stats = useMemo(() => {
    let totalSessions = 0;
    let totalFindings = 0;
    let activeProjects = 0;
    let totalScope = 0;

    for (const p of projects) {
      totalSessions += p.session_count || 0;
      totalFindings += p.total_findings || 0;
      totalScope += (p.scope || []).length;
      if ((p.status || 'active') === 'active') activeProjects++;
    }

    return { totalSessions, totalFindings, activeProjects, totalScope };
  }, [projects]);

  const handleCreate = async (data) => {
    const project = await createProject(data);
    navigate(`/project/${project.id}`);
  };

  return (
    <div className="min-h-screen bg-grid">
      <div className="max-w-5xl mx-auto px-6 py-8">

        {/* Hero area */}
        <div className="mb-10">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-3 mb-1">
                <HadesLogo size={24} className="text-cyan-400 opacity-60" />
                <h1 className="text-xl font-bold text-gray-100">Dashboard</h1>
              </div>
              <p className="text-sm text-gray-500">
                {projects.length > 0
                  ? `${stats.activeProjects} projeto${stats.activeProjects !== 1 ? 's' : ''} ativo${stats.activeProjects !== 1 ? 's' : ''}, ${stats.totalFindings} findings no total`
                  : 'Crie seu primeiro projeto de pentest para começar'
                }
              </p>
            </div>
            <button
              onClick={() => setShowModal(true)}
              className="flex items-center gap-2 px-5 py-2.5 bg-cyan-500/10 text-cyan-400
                         border border-cyan-500/25 rounded-xl text-sm font-semibold
                         hover:bg-cyan-500/20 hover:border-cyan-500/40 hover:shadow-cyan-glow
                         transition-all duration-300"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Novo Projeto
            </button>
          </div>
        </div>

        {/* Stats row */}
        {projects.length > 0 && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-8 animate-fade-in">
            <StatCard
              label="Projetos"
              value={projects.length}
              accent="cyan"
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
                </svg>
              }
            />
            <StatCard
              label="Sessões"
              value={stats.totalSessions}
              accent="emerald"
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
                </svg>
              }
            />
            <StatCard
              label="Findings"
              value={stats.totalFindings}
              accent="amber"
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
                </svg>
              }
            />
            <StatCard
              label="Alvos"
              value={stats.totalScope}
              accent="red"
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7.5 3.75H6A2.25 2.25 0 003.75 6v1.5M16.5 3.75H18A2.25 2.25 0 0120.25 6v1.5m0 9V18A2.25 2.25 0 0118 20.25h-1.5m-9 0H6A2.25 2.25 0 013.75 18v-1.5" />
                </svg>
              }
            />
          </div>
        )}

        {/* Loading state */}
        {projectsLoading && (
          <div className="flex items-center justify-center py-20">
            <div className="flex items-center gap-3 text-gray-500">
              <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              <span className="text-sm">Carregando projetos...</span>
            </div>
          </div>
        )}

        {/* Error state */}
        {projectsError && (
          <div className="mb-6 px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-xl text-sm text-red-400 flex items-center gap-2">
            <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            {projectsError}
          </div>
        )}

        {/* Empty state */}
        {!projectsLoading && projects.length === 0 && (
          <div className="text-center py-24 animate-fade-in">
            <div className="relative w-20 h-20 mx-auto mb-6">
              <div className="absolute inset-0 rounded-2xl bg-cyan-400/5 border border-cyan-400/10 flex items-center justify-center">
                <HadesLogo size={40} className="text-cyan-400/40" />
              </div>
              <div className="absolute inset-0 rounded-2xl blur-xl bg-cyan-400/5" />
            </div>
            <h2 className="text-lg font-semibold text-gray-300 mb-2">Nenhum projeto ainda</h2>
            <p className="text-sm text-gray-500 mb-8 max-w-sm mx-auto leading-relaxed">
              Crie seu primeiro projeto de pentest para definir escopo, iniciar sessões e deixar o HADES descobrir e explorar.
            </p>
            <button
              onClick={() => setShowModal(true)}
              className="inline-flex items-center gap-2 px-6 py-3 bg-cyan-500/10 text-cyan-400
                         border border-cyan-500/25 rounded-xl text-sm font-semibold
                         hover:bg-cyan-500/20 hover:border-cyan-500/40 hover:shadow-cyan-glow
                         transition-all duration-300"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Criar Primeiro Projeto
            </button>
          </div>
        )}

        {/* Projects section */}
        {!projectsLoading && projects.length > 0 && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-500">
                Projetos
              </h2>
              <span className="text-[11px] text-gray-600 tabular-nums">{projects.length} total</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {projects.map((project) => (
                <ProjectCard
                  key={project.id}
                  project={project}
                  onDelete={removeProject}
                  onNavigate={(id) => navigate(`/project/${id}`)}
                />
              ))}
            </div>
          </div>
        )}
      </div>

      {showModal && (
        <NewProjectModal
          onClose={() => setShowModal(false)}
          onCreate={handleCreate}
        />
      )}
    </div>
  );
}
