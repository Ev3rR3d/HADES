import { useMemo } from 'react';

function formatTokens(n) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

export default function TokenMeter({ usage }) {
  const { total = 0, budget = 0, budget_pct, budget_status } = usage || {};

  const barColor = useMemo(() => {
    if (budget_status === 'paused') return 'bg-red-500';
    if (budget_status === 'warning') return 'bg-yellow-500';
    return 'bg-cyan-500';
  }, [budget_status]);

  const textColor = useMemo(() => {
    if (budget_status === 'paused') return 'text-red-400';
    if (budget_status === 'warning') return 'text-yellow-400';
    return 'text-gray-400';
  }, [budget_status]);

  if (!total) return null;

  return (
    <div className="flex items-center gap-2 px-3 py-1" title={`Input: ${formatTokens(usage.total_input || 0)} | Output: ${formatTokens(usage.total_output || 0)}`}>
      <svg className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
      <span className={`text-xs font-mono ${textColor}`}>
        {formatTokens(total)}
        {budget > 0 && ` / ${formatTokens(budget)}`}
      </span>
      {budget > 0 && (
        <div className="w-16 h-1.5 bg-gray-700 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${barColor}`}
            style={{ width: `${Math.min(budget_pct || 0, 100)}%` }}
          />
        </div>
      )}
      {budget_status === 'paused' && (
        <span className="text-xs text-red-400 font-medium">PAUSED</span>
      )}
    </div>
  );
}
