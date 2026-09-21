import { useState, useEffect, useRef } from 'react';

const RISK_BADGE = {
  low: { color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/20' },
  medium: { color: 'text-amber-400', bg: 'bg-amber-400/10', border: 'border-amber-400/20' },
  high: { color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
  critical: { color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/20' },
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
      className={`p-1 rounded transition-all duration-200 ${
        copied
          ? 'bg-emerald-400/20 text-emerald-400'
          : 'text-gray-600 hover:text-gray-400 hover:bg-gray-700/50'
      }`}
      title={copied ? 'Copied!' : 'Copy output'}
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

export default function TerminalOutput({ command, output, exitCode, isStreaming, riskLevel }) {
  const outputRef = useRef(null);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    if (outputRef.current && !collapsed) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [output, collapsed]);

  const riskCfg = riskLevel ? RISK_BADGE[riskLevel.toLowerCase()] : null;

  return (
    <div className="mx-4 my-2 rounded-xl border border-gray-800 bg-[#0a0e17] overflow-hidden animate-fade-in">
      {/* Title bar */}
      <div
        className="flex items-center gap-2 px-3 py-1.5 bg-gray-900/80 border-b border-gray-800 cursor-pointer select-none"
        onClick={() => setCollapsed(!collapsed)}
      >
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 rounded-full bg-red-500/70" />
          <div className="w-2 h-2 rounded-full bg-amber-400/70" />
          <div className="w-2 h-2 rounded-full bg-emerald-400/70" />
        </div>
        <span className="text-[10px] text-gray-600 font-mono ml-1.5">terminal</span>
        {riskCfg && (
          <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded-md ${riskCfg.bg} ${riskCfg.color} border ${riskCfg.border}`}>
            {riskLevel}
          </span>
        )}

        <div className="flex-1" />

        {output && <CopyButton text={output} />}

        {exitCode !== undefined && exitCode !== null && (
          <span className={`text-[10px] font-mono ${exitCode === 0 ? 'text-emerald-500' : 'text-red-400'}`}>
            exit:{exitCode}
          </span>
        )}
        {isStreaming && (
          <span className="text-[10px] text-cyan-400 animate-pulse font-mono">running</span>
        )}

        <svg className={`w-3 h-3 text-gray-600 transition-transform ${collapsed ? '' : 'rotate-180'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>

      {/* Output */}
      {!collapsed && (
        <div ref={outputRef} className="p-3 max-h-72 overflow-y-auto">
          {command && (
            <div className="mb-2 font-mono text-xs">
              <span className="text-cyan-500 select-none">$ </span>
              <span className="text-gray-300">{command}</span>
            </div>
          )}
          {output && (
            <pre className="text-xs text-emerald-400/80 font-mono whitespace-pre-wrap break-all leading-relaxed">
              {output}
            </pre>
          )}
          {!output && isStreaming && (
            <div className="text-xs text-gray-600 font-mono">Waiting for output...</div>
          )}
        </div>
      )}
    </div>
  );
}
