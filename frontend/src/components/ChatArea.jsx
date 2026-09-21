import { useState, useEffect, useRef } from 'react';
import PendingCommand from './PendingCommand';
import ScanProgress from './ScanProgress';
import TerminalOutput from './TerminalOutput';

const SEVERITY_DOT = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-amber-400',
  low: 'bg-blue-400',
  info: 'bg-gray-400',
};

const SEVERITY_BORDER = {
  critical: 'border-red-500/30 bg-red-500/5',
  high: 'border-orange-500/30 bg-orange-500/5',
  medium: 'border-amber-400/30 bg-amber-400/5',
  low: 'border-blue-400/30 bg-blue-400/5',
  info: 'border-gray-600/30 bg-gray-500/5',
};

function parseFormattedText(text) {
  if (!text) return [];
  const parts = [];
  const regex = /(\*\*.*?\*\*|`[^`]+`|\n)/g;
  let lastIndex = 0;
  let match;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push({ type: 'text', value: text.slice(lastIndex, match.index) });
    }
    const token = match[0];
    if (token === '\n') {
      parts.push({ type: 'br' });
    } else if (token.startsWith('**') && token.endsWith('**')) {
      parts.push({ type: 'bold', value: token.slice(2, -2) });
    } else if (token.startsWith('`') && token.endsWith('`')) {
      parts.push({ type: 'code', value: token.slice(1, -1) });
    }
    lastIndex = match.index + token.length;
  }
  if (lastIndex < text.length) {
    parts.push({ type: 'text', value: text.slice(lastIndex) });
  }
  return parts;
}

function FormattedText({ text }) {
  const parts = parseFormattedText(text);
  return parts.map((part, i) => {
    switch (part.type) {
      case 'bold':
        return <strong key={i} className="text-gray-100 font-semibold">{part.value}</strong>;
      case 'code':
        return <code key={i} className="px-1.5 py-0.5 bg-cyan-500/10 border border-cyan-500/20 rounded text-cyan-300 text-xs font-mono">{part.value}</code>;
      case 'br':
        return <br key={i} />;
      default:
        return <span key={i}>{part.value}</span>;
    }
  });
}

function AssistantMessage({ content }) {
  return (
    <div className="flex items-start gap-3 px-4 py-3 animate-fade-in">
      <div className="flex-shrink-0 w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-500/20 to-cyan-500/5 border border-cyan-500/20 flex items-center justify-center mt-0.5">
        <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-[10px] text-cyan-500 font-semibold uppercase tracking-wider mb-1">HADES</p>
        <div className="text-sm text-gray-300 leading-relaxed">
          <FormattedText text={content} />
        </div>
      </div>
    </div>
  );
}

function UserMessage({ content }) {
  return (
    <div className="flex items-start gap-3 px-4 py-3 justify-end animate-fade-in">
      <div className="flex-1 min-w-0 flex justify-end">
        <div className="max-w-[80%]">
          <p className="text-[10px] text-gray-500 font-semibold uppercase tracking-wider mb-1 text-right">You</p>
          <div className="bg-gray-800/80 border border-gray-700/50 rounded-xl rounded-tr-sm px-4 py-2.5">
            <p className="text-sm text-gray-100 leading-relaxed whitespace-pre-wrap">{content}</p>
          </div>
        </div>
      </div>
    </div>
  );
}

function PhaseChange({ phase, reason }) {
  const phaseLabels = {
    recon: 'Reconnaissance',
    enumeration: 'Enumeration',
    exploitation: 'Exploitation',
    post_exploitation: 'Post-Exploitation',
  };
  return (
    <div className="flex justify-center py-3 px-4">
      <div className="inline-flex items-center gap-2 px-4 py-1.5 bg-cyan-500/5 border border-cyan-500/15 rounded-full">
        <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse-glow" />
        <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider">
          {phaseLabels[phase] || phase}
        </span>
        {reason && (
          <span className="text-[11px] text-gray-500">— {reason}</span>
        )}
      </div>
    </div>
  );
}

function FindingNotification({ finding }) {
  const severity = finding.severity?.toLowerCase() || 'info';
  const dotColor = SEVERITY_DOT[severity] || SEVERITY_DOT.info;
  const borderStyle = SEVERITY_BORDER[severity] || SEVERITY_BORDER.info;

  return (
    <div className="flex justify-center py-2 px-4 animate-fade-in">
      <div className={`inline-flex items-center gap-2.5 px-4 py-2 border rounded-lg ${borderStyle}`}>
        <div className={`w-2 h-2 rounded-full ${dotColor} ${severity !== 'info' ? 'animate-pulse' : ''}`} />
        <span className="text-[10px] font-bold uppercase tracking-wider text-gray-500">{severity}</span>
        <span className="text-sm text-gray-200">{finding.title}</span>
      </div>
    </div>
  );
}

const CATEGORY_ICON = {
  route: '/',
  technology: '#',
  config: '*',
  credential: '@',
  exposure: '!',
  other: '?',
};

function LeadNotification({ lead }) {
  const category = lead.category?.toLowerCase() || 'other';
  const icon = CATEGORY_ICON[category] || '?';

  return (
    <div className="flex justify-center py-2 px-4 animate-fade-in">
      <div className="inline-flex items-center gap-2.5 px-4 py-2 bg-purple-500/5 border border-purple-500/15 rounded-lg">
        <span className="w-5 h-5 flex items-center justify-center rounded text-[10px] font-bold text-purple-400 bg-purple-400/10 border border-purple-400/20">
          {icon}
        </span>
        <span className="text-[10px] font-bold uppercase tracking-wider text-purple-400/70">{category}</span>
        <span className="text-sm text-gray-300">{lead.title}</span>
      </div>
    </div>
  );
}

function ErrorMessage({ message }) {
  return (
    <div className="mx-4 my-2 px-4 py-3 bg-red-500/5 border border-red-500/20 rounded-xl animate-fade-in">
      <div className="flex items-center gap-2">
        <svg className="w-4 h-4 text-red-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span className="text-sm text-red-400">{message}</span>
      </div>
    </div>
  );
}

export default function ChatArea({ chatItems, onCommandAction, isStreaming, isReconStarting, onSkipTool }) {
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [chatItems]);

  if (chatItems.length === 0) {
    return (
      <div ref={scrollRef} className="flex-1 overflow-y-auto flex items-center justify-center bg-grid">
        <div className="text-center py-12 px-4 animate-fade-in">
          <div className="w-16 h-16 mx-auto mb-5 rounded-2xl bg-gradient-to-br from-cyan-500/15 to-cyan-500/5 border border-cyan-500/20 flex items-center justify-center shadow-cyan-glow">
            {isReconStarting ? (
              <svg className="w-7 h-7 text-cyan-400 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
            ) : (
              <svg className="w-7 h-7 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            )}
          </div>
          <h3 className="text-lg font-semibold text-gray-200 mb-2">
            {isReconStarting ? 'Launching Scan...' : 'Awaiting Orders'}
          </h3>
          <p className="text-sm text-gray-500 max-w-sm leading-relaxed">
            {isReconStarting
              ? 'HADES is planning and launching parallel scans. Findings appear as tools complete.'
              : 'Start by describing your target or launch an automated scan.'}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div ref={scrollRef} className="flex-1 overflow-y-auto bg-grid">
      <div className="divide-y divide-gray-800/30">
        {chatItems.map((item, i) => {
          switch (item.type) {
            case 'user_message':
              return <UserMessage key={i} content={item.content} />;

            case 'assistant_message':
              return <AssistantMessage key={i} content={item.content} />;

            case 'command_pending':
              return (
                <PendingCommand
                  key={`cmd-${item.command?.id || i}`}
                  command={item.command}
                  onAction={onCommandAction}
                />
              );

            case 'terminal_output':
              return (
                <TerminalOutput
                  key={`term-${item.commandId || i}`}
                  command={item.commandText}
                  output={item.output}
                  exitCode={item.exitCode}
                  isStreaming={item.isStreaming}
                  riskLevel={item.riskLevel}
                />
              );

            case 'phase_change':
              return <PhaseChange key={`phase-${i}`} phase={item.phase} reason={item.reason} />;

            case 'finding':
              return <FindingNotification key={`finding-${item.finding?.id || i}`} finding={item.finding} />;

            case 'lead':
              return <LeadNotification key={`lead-${item.lead?.id || i}`} lead={item.lead} />;

            case 'scan_progress':
              return <ScanProgress key={`scan-${i}`} scanState={item.scanState} onSkipTool={onSkipTool} />;

            case 'error':
              return <ErrorMessage key={`err-${i}`} message={item.message} />;

            case 'system_message':
              return (
                <div key={`sys-${i}`} className="flex justify-center py-2 px-4">
                  <span className="text-[11px] text-gray-600 font-mono">{item.content}</span>
                </div>
              );

            default:
              return null;
          }
        })}

        {isStreaming && (
          <div className="flex items-start gap-3 px-4 py-3 animate-fade-in">
            <div className="flex-shrink-0 w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-500/20 to-cyan-500/5 border border-cyan-500/20 flex items-center justify-center">
              <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <div className="flex-1">
              <p className="text-[10px] text-cyan-500 font-semibold uppercase tracking-wider mb-2">HADES</p>
              <div className="typing-indicator flex items-center gap-1.5">
                <span />
                <span />
                <span />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
