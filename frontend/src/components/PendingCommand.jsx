import { useState } from 'react';
import { approveCommand, rejectCommand } from '../api';

const RISK_CONFIG = {
  high: { color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/30', label: 'HIGH RISK' },
  critical: { color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30', label: 'CRITICAL' },
};

export default function PendingCommand({ command, onAction }) {
  const [acting, setActing] = useState(false);

  const risk = command.risk_level?.toLowerCase() || 'high';
  const riskCfg = RISK_CONFIG[risk] || RISK_CONFIG.high;

  // If already acted on, show a muted confirmation
  if (command._acted) {
    return (
      <div className="mx-4 my-2 px-3 py-2 rounded-lg bg-gray-800/50 border border-gray-700/50">
        <div className="flex items-center gap-2 text-sm">
          <span className={`font-mono ${command._action === 'approved' ? 'text-emerald-400' : 'text-red-400'}`}>
            {command._action === 'approved' ? 'Approved' : 'Rejected'}:
          </span>
          <code className="text-gray-400 font-mono text-xs truncate">{command.command}</code>
        </div>
      </div>
    );
  }

  const handleApprove = async () => {
    setActing(true);
    try {
      await approveCommand(command.id);
      onAction?.('approved', command.id);
    } catch (err) {
      console.error('Failed to approve:', err);
    } finally {
      setActing(false);
    }
  };

  const handleReject = async () => {
    setActing(true);
    try {
      await rejectCommand(command.id);
      onAction?.('rejected', command.id);
    } catch (err) {
      console.error('Failed to reject:', err);
    } finally {
      setActing(false);
    }
  };

  return (
    <div className={`mx-4 my-2 rounded-lg border ${riskCfg.border} ${riskCfg.bg} transition-all duration-200`}>
      <div className="flex items-center gap-3 px-3 py-2">
        {/* Warning icon */}
        <svg className={`w-4 h-4 flex-shrink-0 ${riskCfg.color}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>

        {/* Risk badge */}
        <span className={`text-xs font-bold uppercase px-1.5 py-0.5 rounded ${riskCfg.bg} ${riskCfg.color} border ${riskCfg.border} flex-shrink-0`}>
          {riskCfg.label}
        </span>

        {/* Command */}
        <code className="text-sm text-gray-100 font-mono truncate flex-1 min-w-0">
          {command.command}
        </code>

        {/* Action buttons */}
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <button
            onClick={handleApprove}
            disabled={acting}
            className="px-3 py-1 bg-emerald-500/20 text-emerald-400 border border-emerald-500/40
                       rounded text-xs font-medium hover:bg-emerald-500/30 hover:border-emerald-500/60
                       transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Approve
          </button>
          <button
            onClick={handleReject}
            disabled={acting}
            className="px-3 py-1 bg-red-500/20 text-red-400 border border-red-500/40
                       rounded text-xs font-medium hover:bg-red-500/30 hover:border-red-500/60
                       transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Reject
          </button>
        </div>
      </div>

      {/* Reason (below, smaller) */}
      {command.reason && (
        <div className="px-3 pb-2 -mt-0.5">
          <p className="text-xs text-gray-400 pl-7">{command.reason}</p>
        </div>
      )}
    </div>
  );
}
