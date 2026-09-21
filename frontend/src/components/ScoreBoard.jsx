import { useMemo } from 'react';

const SEVERITY_CONFIG = [
  { key: 'critical', label: 'CRIT', color: 'text-red-500', bg: 'bg-red-500', weight: 40 },
  { key: 'high', label: 'HIGH', color: 'text-orange-500', bg: 'bg-orange-500', weight: 20 },
  { key: 'medium', label: 'MED', color: 'text-amber-400', bg: 'bg-amber-400', weight: 5 },
  { key: 'low', label: 'LOW', color: 'text-blue-400', bg: 'bg-blue-400', weight: 1 },
  { key: 'info', label: 'INFO', color: 'text-gray-500', bg: 'bg-gray-500', weight: 0 },
];

function getRiskGrade(score) {
  if (score === 0) return { letter: '-', color: 'text-gray-700', border: 'border-gray-800' };
  if (score <= 5) return { letter: 'A', color: 'text-emerald-400', border: 'border-emerald-500/30' };
  if (score <= 15) return { letter: 'B', color: 'text-blue-400', border: 'border-blue-500/30' };
  if (score <= 30) return { letter: 'C', color: 'text-amber-400', border: 'border-amber-500/30' };
  if (score <= 60) return { letter: 'D', color: 'text-orange-500', border: 'border-orange-500/30' };
  return { letter: 'F', color: 'text-red-500', border: 'border-red-500/30' };
}

export default function ScoreBoard({ findings, leads }) {
  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const sev = f.severity?.toLowerCase() || 'info';
      if (sev in c) c[sev]++;
    }
    return c;
  }, [findings]);

  const riskScore = useMemo(() => {
    return SEVERITY_CONFIG.reduce((sum, s) => sum + counts[s.key] * s.weight, 0);
  }, [counts]);

  const grade = useMemo(() => getRiskGrade(riskScore), [riskScore]);

  const totalFindings = findings.length;
  const totalLeads = (leads || []).filter((l) => l.status !== 'dismissed').length;

  if (totalFindings === 0 && totalLeads === 0) return null;

  return (
    <div className="flex-shrink-0 bg-gray-900/60 border-b border-gray-800/60 px-4 py-2">
      <div className="flex items-center gap-4">
        {/* Risk Grade */}
        <div className={`flex items-center justify-center w-9 h-9 rounded-lg border ${grade.border} bg-gray-900 transition-all duration-500`}>
          <span className={`text-lg font-black ${grade.color} transition-colors duration-500`}>
            {grade.letter}
          </span>
        </div>

        {/* Severity counters */}
        <div className="flex items-center gap-2.5">
          {SEVERITY_CONFIG.map((sev) => {
            const count = counts[sev.key];
            return (
              <div key={sev.key} className="flex items-center gap-1">
                <span className={`text-sm font-bold tabular-nums transition-all duration-300 ${
                  count > 0 ? sev.color : 'text-gray-700'
                }`}>
                  {count}
                </span>
                <span className={`text-[9px] font-semibold tracking-wider ${
                  count > 0 ? 'text-gray-500' : 'text-gray-700'
                }`}>
                  {sev.label}
                </span>
              </div>
            );
          })}
        </div>

        <div className="w-px h-5 bg-gray-800" />

        {/* Risk score */}
        <div className="flex items-center gap-1.5">
          <span className="text-[9px] font-semibold text-gray-600 uppercase tracking-wider">Score</span>
          <span className={`text-sm font-bold tabular-nums ${grade.color}`}>
            {riskScore}
          </span>
        </div>

        {/* Leads counter */}
        {totalLeads > 0 && (
          <>
            <div className="w-px h-5 bg-gray-800" />
            <div className="flex items-center gap-1.5">
              <span className="text-[9px] font-semibold text-gray-600 uppercase tracking-wider">Leads</span>
              <span className="text-sm font-bold tabular-nums text-purple-400">{totalLeads}</span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
