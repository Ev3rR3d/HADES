import { useState } from 'react';

const SEVERITY_CONFIG = {
  critical: { color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30', dot: 'bg-red-500', glow: 'shadow-red-500/20' },
  high: { color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/30', dot: 'bg-orange-500', glow: 'shadow-orange-500/20' },
  medium: { color: 'text-amber-400', bg: 'bg-amber-400/10', border: 'border-amber-400/30', dot: 'bg-amber-400', glow: 'shadow-amber-400/20' },
  low: { color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/30', dot: 'bg-blue-400', glow: 'shadow-blue-400/20' },
  info: { color: 'text-gray-400', bg: 'bg-gray-400/10', border: 'border-gray-400/30', dot: 'bg-gray-500', glow: '' },
};

const CONFIDENCE_BADGE = {
  confirmed: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30',
  possible: 'text-amber-400 bg-amber-400/10 border-amber-400/30',
  informational: 'text-gray-400 bg-gray-400/10 border-gray-400/30',
};

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <button
      onClick={handleCopy}
      className={`absolute top-2 right-2 p-1.5 rounded-md transition-all duration-200 ${
        copied
          ? 'bg-emerald-400/20 text-emerald-400'
          : 'bg-gray-700/60 text-gray-500 hover:text-gray-300 hover:bg-gray-600/60 opacity-0 group-hover/code:opacity-100'
      }`}
      title={copied ? 'Copied!' : 'Copy to clipboard'}
    >
      {copied ? (
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
      ) : (
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
      )}
    </button>
  );
}

export default function FindingCard({ finding, isExpanded, onToggle }) {
  const severity = finding.severity?.toLowerCase() || 'info';
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
  const confidence = finding.confidence?.toLowerCase();
  const confidenceCls = CONFIDENCE_BADGE[confidence];

  return (
    <div
      className={`rounded-lg border ${config.border} ${config.bg} transition-all duration-200 cursor-pointer hover:shadow-lg ${config.glow}`}
      onClick={onToggle}
    >
      <div className="flex items-center gap-2 px-3 py-2.5">
        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${config.dot} ${severity !== 'info' ? 'animate-pulse' : ''}`} />
        <span className={`text-[10px] font-bold uppercase tracking-wider ${config.color}`}>
          {severity}
        </span>
        {confidenceCls && (
          <span className={`text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded border ${confidenceCls}`}>
            {confidence}
          </span>
        )}
        <span className="text-sm text-gray-200 truncate flex-1">{finding.title}</span>
        <svg
          className={`w-4 h-4 text-gray-500 transition-transform duration-200 flex-shrink-0 ${
            isExpanded ? 'rotate-180' : ''
          }`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>

      {isExpanded && (
        <div className="px-3 pb-3 space-y-3 border-t border-gray-700/50 mt-1 pt-3">
          {finding.description && (
            <div>
              <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1">Descrição</p>
              <p className="text-sm text-gray-300 leading-relaxed">{finding.description}</p>
            </div>
          )}
          {finding.evidence && (
            <div>
              <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1">Evidência</p>
              <div className="relative group/code">
                <div className={`rounded-lg border ${config.border} overflow-hidden`}>
                  <div className={`flex items-center gap-2 px-3 py-1.5 ${config.bg} border-b ${config.border}`}>
                    <svg className="w-3 h-3 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                    </svg>
                    <span className="text-[9px] text-gray-500 font-medium">Output</span>
                  </div>
                  <pre className="text-xs text-emerald-400 bg-black/40 p-3 overflow-x-auto font-mono whitespace-pre-wrap leading-relaxed max-h-[400px] overflow-y-auto">
                    {finding.evidence}
                  </pre>
                </div>
                <CopyButton text={finding.evidence} />
              </div>
            </div>
          )}
          {finding.remediation && (
            <div>
              <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1">Correção</p>
              <p className="text-sm text-gray-300 leading-relaxed">{finding.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
