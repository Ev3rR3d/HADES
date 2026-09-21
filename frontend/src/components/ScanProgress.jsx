const STATUS_COLORS = {
  running: 'text-cyan-400',
  completed: 'text-emerald-400',
  failed: 'text-red-400',
  skipped: 'text-yellow-400',
  starting: 'text-yellow-400',
  thinking: 'text-purple-400',
  collecting: 'text-amber-400',
};

const PHASE_LABELS = {
  recon: 'Recon',
  scanning: 'Scanning',
  enumeration: 'Enumeration',
  exploitation: 'Exploitation',
  post_exploitation: 'Post-Exploit',
  reporting: 'Reporting',
};

function ToolBadge({ name, status, onSkip }) {
  const color = STATUS_COLORS[status] || 'text-gray-400';
  const bgMap = {
    running: 'bg-cyan-500/10 border-cyan-500/20',
    completed: 'bg-emerald-500/10 border-emerald-500/20',
    failed: 'bg-red-500/10 border-red-500/20',
    skipped: 'bg-yellow-500/10 border-yellow-500/20',
  };
  const bg = bgMap[status] || 'bg-gray-800/50 border-gray-700/50';

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-mono border ${bg} transition-all duration-200`}>
      {status === 'running' && (
        <svg className="w-3 h-3 animate-spin text-cyan-400" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
      )}
      {status === 'completed' && (
        <svg className="w-3 h-3 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
      )}
      {status === 'failed' && (
        <svg className="w-3 h-3 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      )}
      <span className={color}>{name}</span>
      {status === 'running' && onSkip && (
        <button
          onClick={(e) => { e.stopPropagation(); onSkip(name); }}
          className="ml-0.5 p-0.5 rounded hover:bg-gray-600/50 text-gray-600 hover:text-yellow-400 transition-colors"
          title={`Skip ${name}`}
        >
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}
    </span>
  );
}

export default function ScanProgress({ scanState, onSkipTool }) {
  if (!scanState) return null;

  const { status, round, totalRounds, phase, tasksTotal, tasksCompleted, tasks, message, taskStatus } = scanState;

  if (status === 'completed') {
    return (
      <div className="mx-4 my-3 px-4 py-3 bg-emerald-500/5 border border-emerald-500/20 rounded-xl animate-fade-in">
        <div className="flex items-center gap-2">
          <svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span className="text-sm font-semibold text-emerald-400">Scan Complete</span>
        </div>
        {message && <p className="text-xs text-gray-500 mt-1 ml-7">{message}</p>}
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="mx-4 my-3 px-4 py-3 bg-red-500/5 border border-red-500/20 rounded-xl">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span className="text-sm text-red-400">{message || 'Scan failed'}</span>
        </div>
      </div>
    );
  }

  const pct = tasksTotal > 0 ? Math.round((tasksCompleted / tasksTotal) * 100) : 0;
  const phaseLabel = PHASE_LABELS[phase] || phase;

  return (
    <div className="mx-4 my-3 px-4 py-3 bg-gray-900/50 border border-gray-800 rounded-xl relative overflow-hidden">
      {/* Subtle animated gradient */}
      <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/[0.02] via-transparent to-cyan-500/[0.02] pointer-events-none" />

      <div className="relative">
        <div className="flex items-center justify-between mb-2.5">
          <div className="flex items-center gap-2.5">
            <div className="relative">
              {taskStatus === 'thinking' ? (
                <svg className="w-4 h-4 text-purple-400 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
              ) : (
                <svg className="w-4 h-4 text-cyan-400 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
              )}
            </div>
            <span className="text-sm font-semibold text-gray-200">
              Round {round || 1}
              <span className="text-gray-600 font-normal">/{totalRounds || 15}</span>
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-semibold uppercase tracking-wider">
              {phaseLabel}
            </span>
          </div>
          <span className="text-[11px] text-gray-500 font-mono tabular-nums">
            {tasksCompleted}/{tasksTotal}
          </span>
        </div>

        {/* Progress bar */}
        <div className="w-full bg-gray-800 rounded-full h-1 mb-2.5 overflow-hidden">
          <div
            className="bg-gradient-to-r from-cyan-500 to-cyan-400 h-1 rounded-full transition-all duration-700 ease-out"
            style={{ width: `${pct}%` }}
          />
        </div>

        {/* Active tools */}
        {tasks && tasks.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {tasks.map((t, i) => (
              <ToolBadge key={`${t.name}-${i}`} name={t.name} status={t.status} onSkip={onSkipTool} />
            ))}
          </div>
        )}

        {message && (
          <p className={`mt-2 truncate ${
            message.includes('planejando') || message.includes('Analisando')
              ? 'text-xs text-purple-400 font-medium'
              : message.includes('Coletando')
                ? 'text-xs text-amber-400 font-medium'
                : 'text-[11px] text-gray-500'
          }`}>{message}</p>
        )}
      </div>
    </div>
  );
}
