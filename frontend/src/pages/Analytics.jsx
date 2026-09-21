import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getProjects, getProjectAnalytics, getProjectSessions } from '../api';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_COLORS = {
  critical: { bar: 'bg-red-500', text: 'text-red-400', bg: 'bg-red-500/10' },
  high: { bar: 'bg-orange-500', text: 'text-orange-400', bg: 'bg-orange-500/10' },
  medium: { bar: 'bg-amber-400', text: 'text-amber-400', bg: 'bg-amber-400/10' },
  low: { bar: 'bg-blue-400', text: 'text-blue-400', bg: 'bg-blue-400/10' },
  info: { bar: 'bg-gray-500', text: 'text-gray-400', bg: 'bg-gray-500/10' },
};

const PHASE_LABELS = {
  recon: 'Recon',
  scanning: 'Scanning',
  enumeration: 'Enumeration',
  exploitation: 'Exploitation',
  post_exploitation: 'Post-Exploit',
  reporting: 'Reporting',
};

const CMD_STATUS_COLORS = {
  executed: { bar: 'bg-emerald-500', text: 'text-emerald-400' },
  failed: { bar: 'bg-red-500', text: 'text-red-400' },
  approved: { bar: 'bg-cyan-500', text: 'text-cyan-400' },
  pending: { bar: 'bg-amber-400', text: 'text-amber-400' },
  rejected: { bar: 'bg-gray-500', text: 'text-gray-400' },
};

const LEAD_STATUS_COLORS = {
  open: { bar: 'bg-purple-500', text: 'text-purple-400' },
  investigating: { bar: 'bg-cyan-500', text: 'text-cyan-400' },
  escalated: { bar: 'bg-orange-500', text: 'text-orange-400' },
  dismissed: { bar: 'bg-gray-500', text: 'text-gray-400' },
};

const LEAD_CAT_COLORS = {
  route: { bar: 'bg-blue-500', text: 'text-blue-400' },
  technology: { bar: 'bg-cyan-500', text: 'text-cyan-400' },
  config: { bar: 'bg-amber-400', text: 'text-amber-400' },
  credential: { bar: 'bg-red-500', text: 'text-red-400' },
  exposure: { bar: 'bg-orange-500', text: 'text-orange-400' },
  other: { bar: 'bg-gray-500', text: 'text-gray-400' },
};

function getRiskGrade(score) {
  if (score === 0) return { letter: '-', color: 'text-gray-600', border: 'border-gray-700', bg: 'bg-gray-900' };
  if (score <= 5) return { letter: 'A', color: 'text-emerald-400', border: 'border-emerald-400/40', bg: 'bg-emerald-400/5' };
  if (score <= 15) return { letter: 'B', color: 'text-blue-400', border: 'border-blue-400/40', bg: 'bg-blue-400/5' };
  if (score <= 30) return { letter: 'C', color: 'text-amber-400', border: 'border-amber-400/40', bg: 'bg-amber-400/5' };
  if (score <= 60) return { letter: 'D', color: 'text-orange-500', border: 'border-orange-500/40', bg: 'bg-orange-500/5' };
  return { letter: 'F', color: 'text-red-500', border: 'border-red-500/40', bg: 'bg-red-500/5' };
}

function KpiCard({ label, value, icon, accent = 'cyan' }) {
  const accents = {
    cyan: 'border-cyan-400/20 text-cyan-400',
    red: 'border-red-400/20 text-red-400',
    amber: 'border-amber-400/20 text-amber-400',
    purple: 'border-purple-400/20 text-purple-400',
    emerald: 'border-emerald-400/20 text-emerald-400',
  };
  return (
    <div className={`bg-gray-900 border ${accents[accent]?.split(' ')[0] || 'border-gray-700'} rounded-xl p-5`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-semibold uppercase tracking-wider text-gray-500">{label}</span>
        <span className={`${accents[accent]?.split(' ')[1] || 'text-gray-400'}`}>{icon}</span>
      </div>
      <div className="text-3xl font-bold text-gray-100 tabular-nums">{value}</div>
    </div>
  );
}

function HBar({ items, colorMap, maxVal }) {
  const max = maxVal || Math.max(...items.map((i) => i.value), 1);
  return (
    <div className="space-y-2.5">
      {items.map((item) => {
        const colors = colorMap[item.key] || { bar: 'bg-gray-600', text: 'text-gray-400' };
        const pct = max > 0 ? (item.value / max) * 100 : 0;
        return (
          <div key={item.key}>
            <div className="flex items-center justify-between mb-1">
              <span className={`text-xs font-medium capitalize ${colors.text}`}>{item.label || item.key}</span>
              <span className="text-xs font-bold text-gray-300 tabular-nums">{item.value}</span>
            </div>
            <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${colors.bar} transition-all duration-500`}
                style={{ width: `${Math.max(pct, pct > 0 ? 2 : 0)}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Panel({ title, children, className = '' }) {
  return (
    <div className={`bg-gray-900 border border-gray-800 rounded-xl p-5 ${className}`}>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">{title}</h3>
      {children}
    </div>
  );
}

export default function Analytics() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState([]);
  const [selectedId, setSelectedId] = useState('');
  const [sessions, setSessions] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState('');
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingProjects, setLoadingProjects] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    getProjects()
      .then((data) => {
        setProjects(data);
        if (data.length > 0) setSelectedId(data[0].id);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoadingProjects(false));
  }, []);

  useEffect(() => {
    if (!selectedId) {
      setSessions([]);
      setSelectedSessionId('');
      return;
    }
    setSelectedSessionId('');
    getProjectSessions(selectedId)
      .then(setSessions)
      .catch(() => setSessions([]));
  }, [selectedId]);

  useEffect(() => {
    if (!selectedId) {
      setAnalytics(null);
      return;
    }
    setLoading(true);
    setError(null);
    getProjectAnalytics(selectedId, selectedSessionId || undefined)
      .then(setAnalytics)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [selectedId, selectedSessionId]);

  const grade = useMemo(() => getRiskGrade(analytics?.risk_score || 0), [analytics]);

  const cmdSuccessRate = useMemo(() => {
    if (!analytics) return null;
    const executed = analytics.commands_by_status?.executed || 0;
    const failed = analytics.commands_by_status?.failed || 0;
    const total = executed + failed;
    if (total === 0) return null;
    return Math.round((executed / total) * 100);
  }, [analytics]);

  const severityItems = useMemo(() => {
    if (!analytics) return [];
    return SEVERITY_ORDER.map((s) => ({ key: s, value: analytics.findings_by_severity?.[s] || 0 }));
  }, [analytics]);

  const phaseItems = useMemo(() => {
    if (!analytics) return [];
    return Object.keys(PHASE_LABELS).map((p) => ({
      key: p,
      label: PHASE_LABELS[p],
      value: analytics.sessions_by_phase?.[p] || 0,
    }));
  }, [analytics]);

  const cmdItems = useMemo(() => {
    if (!analytics) return [];
    return ['executed', 'failed', 'pending', 'approved', 'rejected']
      .map((s) => ({ key: s, value: analytics.commands_by_status?.[s] || 0 }))
      .filter((i) => i.value > 0);
  }, [analytics]);

  const leadStatusItems = useMemo(() => {
    if (!analytics) return [];
    return ['open', 'investigating', 'escalated', 'dismissed']
      .map((s) => ({ key: s, value: analytics.leads_by_status?.[s] || 0 }))
      .filter((i) => i.value > 0);
  }, [analytics]);

  const leadCatItems = useMemo(() => {
    if (!analytics) return [];
    return ['credential', 'exposure', 'config', 'technology', 'route', 'other']
      .map((c) => ({ key: c, value: analytics.leads_by_category?.[c] || 0 }))
      .filter((i) => i.value > 0);
  }, [analytics]);

  const hasData = analytics && analytics.total_sessions > 0;

  return (
    <div className="min-h-screen">
      <div className="max-w-6xl mx-auto px-6 py-8">
        <div className="mb-8">
          <h1 className="text-xl font-bold text-gray-100">Analytics</h1>
          <p className="text-sm text-gray-500 mt-1">Performance metrics and vulnerability insights</p>
        </div>
        {/* Filters */}
        <div className="flex flex-wrap gap-4 mb-8">
          <div className="flex-1 min-w-[200px] max-w-md">
            <label className="block text-sm font-medium text-gray-400 mb-2">Projeto</label>
            {loadingProjects ? (
              <div className="h-11 bg-gray-800 rounded-xl animate-pulse" />
            ) : projects.length === 0 ? (
              <p className="text-sm text-gray-500">Nenhum projeto encontrado.</p>
            ) : (
              <select
                value={selectedId}
                onChange={(e) => setSelectedId(e.target.value)}
                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-xl text-gray-100
                           text-sm focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                           transition-all duration-200 appearance-none cursor-pointer
                           bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20fill%3D%22none%22%20viewBox%3D%220%200%2020%2020%22%3E%3Cpath%20stroke%3D%22%236b7280%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%20stroke-width%3D%221.5%22%20d%3D%22m6%208%204%204%204-4%22%2F%3E%3C%2Fsvg%3E')]
                           bg-[length:1.25rem_1.25rem] bg-[right_0.5rem_center] bg-no-repeat pr-10"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}{p.client ? ` — ${p.client}` : ''}
                  </option>
                ))}
              </select>
            )}
          </div>

          {sessions.length > 0 && (
            <div className="flex-1 min-w-[200px] max-w-md">
              <label className="block text-sm font-medium text-gray-400 mb-2">Session</label>
              <select
                value={selectedSessionId}
                onChange={(e) => setSelectedSessionId(e.target.value)}
                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-xl text-gray-100
                           text-sm focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                           transition-all duration-200 appearance-none cursor-pointer
                           bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20fill%3D%22none%22%20viewBox%3D%220%200%2020%2020%22%3E%3Cpath%20stroke%3D%22%236b7280%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%20stroke-width%3D%221.5%22%20d%3D%22m6%208%204%204%204-4%22%2F%3E%3C%2Fsvg%3E')]
                           bg-[length:1.25rem_1.25rem] bg-[right_0.5rem_center] bg-no-repeat pr-10"
              >
                <option value="">Todas as sessions</option>
                {sessions.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} — {s.target}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        {error && (
          <div className="mb-6 px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">
            {error}
          </div>
        )}

        {loading && (
          <div className="flex items-center justify-center py-20">
            <div className="flex items-center gap-3 text-gray-400">
              <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              Loading analytics...
            </div>
          </div>
        )}

        {!loading && analytics && !hasData && (
          <div className="text-center py-20">
            <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gray-800 border border-gray-700 flex items-center justify-center">
              <svg className="w-8 h-8 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-gray-300 mb-2">No data yet</h2>
            <p className="text-sm text-gray-500">Start a session in this project to see analytics here.</p>
          </div>
        )}

        {!loading && hasData && (
          <>
            {/* KPI row */}
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
              <KpiCard
                label="Sessions"
                value={analytics.total_sessions}
                accent="cyan"
                icon={
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                  </svg>
                }
              />
              <KpiCard
                label="Findings"
                value={analytics.total_findings}
                accent="red"
                icon={
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                }
              />
              <KpiCard
                label="Commands"
                value={analytics.total_commands}
                accent="emerald"
                icon={
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                  </svg>
                }
              />
              <KpiCard
                label="Leads"
                value={analytics.total_leads}
                accent="purple"
                icon={
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                  </svg>
                }
              />

              {/* Risk grade card */}
              <div className={`bg-gray-900 border ${grade.border} rounded-xl p-5`}>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-semibold uppercase tracking-wider text-gray-500">Risk</span>
                  {cmdSuccessRate !== null && (
                    <span className="text-xs text-gray-500">{cmdSuccessRate}% success</span>
                  )}
                </div>
                <div className="flex items-center gap-3">
                  <div className={`flex items-center justify-center w-10 h-10 rounded-lg border-2 ${grade.border} ${grade.bg}`}>
                    <span className={`text-2xl font-black ${grade.color}`}>{grade.letter}</span>
                  </div>
                  <span className={`text-2xl font-bold tabular-nums ${grade.color}`}>{analytics.risk_score}</span>
                </div>
              </div>
            </div>

            {/* Charts row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
              <Panel title="Findings by Severity">
                {severityItems.some((i) => i.value > 0) ? (
                  <HBar items={severityItems} colorMap={SEVERITY_COLORS} />
                ) : (
                  <p className="text-sm text-gray-600">No findings recorded.</p>
                )}
              </Panel>

              <Panel title="Sessions by Phase">
                {phaseItems.some((i) => i.value > 0) ? (
                  <HBar
                    items={phaseItems}
                    colorMap={{
                      recon: { bar: 'bg-cyan-500', text: 'text-cyan-400' },
                      scanning: { bar: 'bg-blue-500', text: 'text-blue-400' },
                      enumeration: { bar: 'bg-purple-500', text: 'text-purple-400' },
                      exploitation: { bar: 'bg-orange-500', text: 'text-orange-400' },
                      post_exploitation: { bar: 'bg-red-500', text: 'text-red-400' },
                      reporting: { bar: 'bg-emerald-500', text: 'text-emerald-400' },
                    }}
                  />
                ) : (
                  <p className="text-sm text-gray-600">No sessions yet.</p>
                )}
              </Panel>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
              <Panel title="Commands by Status">
                {cmdItems.length > 0 ? (
                  <HBar items={cmdItems} colorMap={CMD_STATUS_COLORS} />
                ) : (
                  <p className="text-sm text-gray-600">No commands recorded.</p>
                )}
              </Panel>

              <Panel title="Leads by Status">
                {leadStatusItems.length > 0 ? (
                  <HBar items={leadStatusItems} colorMap={LEAD_STATUS_COLORS} />
                ) : (
                  <p className="text-sm text-gray-600">No leads recorded.</p>
                )}
              </Panel>

              <Panel title="Leads by Category">
                {leadCatItems.length > 0 ? (
                  <HBar items={leadCatItems} colorMap={LEAD_CAT_COLORS} />
                ) : (
                  <p className="text-sm text-gray-600">No leads recorded.</p>
                )}
              </Panel>
            </div>

            {/* Findings timeline */}
            {analytics.findings_timeline?.length > 0 && (
              <Panel title="Findings Timeline" className="mb-6">
                <div className="overflow-x-auto">
                  <div className="flex items-end gap-1.5 min-w-0" style={{ minHeight: 120 }}>
                    {analytics.findings_timeline.map((day) => {
                      const total = SEVERITY_ORDER.reduce((s, sev) => s + (day[sev] || 0), 0);
                      const maxDay = Math.max(
                        ...analytics.findings_timeline.map((d) =>
                          SEVERITY_ORDER.reduce((s, sev) => s + (d[sev] || 0), 0)
                        ),
                        1
                      );
                      return (
                        <div key={day.date} className="flex-1 min-w-[28px] flex flex-col items-center gap-1">
                          <div className="w-full flex flex-col-reverse gap-px" style={{ height: 80 }}>
                            {SEVERITY_ORDER.map((sev) => {
                              const count = day[sev] || 0;
                              if (count === 0) return null;
                              const h = (count / maxDay) * 80;
                              return (
                                <div
                                  key={sev}
                                  className={`w-full rounded-sm ${SEVERITY_COLORS[sev].bar}`}
                                  style={{ height: h }}
                                  title={`${sev}: ${count}`}
                                />
                              );
                            })}
                          </div>
                          <span className="text-[9px] text-gray-600 tabular-nums whitespace-nowrap">
                            {day.date.slice(5)}
                          </span>
                          <span className="text-[10px] text-gray-400 font-bold tabular-nums">{total}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </Panel>
            )}

            {/* Recent findings */}
            {analytics.recent_findings?.length > 0 && (
              <Panel title="Recent Findings">
                <div className="space-y-2">
                  {analytics.recent_findings.map((f, i) => {
                    const colors = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info;
                    return (
                      <div key={i} className="flex items-center gap-3 py-2 border-b border-gray-800/50 last:border-0">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${colors.text} ${colors.bg}`}>
                          {f.severity}
                        </span>
                        <span className="text-sm text-gray-200 flex-1 truncate">{f.title}</span>
                        <span className="text-xs text-gray-500 font-mono flex-shrink-0">{f.target}</span>
                        <span className="text-xs text-gray-600 flex-shrink-0">{f.created_at?.slice(0, 10)}</span>
                      </div>
                    );
                  })}
                </div>
              </Panel>
            )}
          </>
        )}
      </div>
    </div>
  );
}
