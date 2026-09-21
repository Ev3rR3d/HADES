import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { getSession, pauseSession, resumeSession, stopSession, skipTool } from '../api';
import ChatArea from '../components/ChatArea';
import MessageInput from '../components/MessageInput';
import ScoreBoard from '../components/ScoreBoard';
import Sidebar from '../components/Sidebar';
import TokenMeter from '../components/TokenMeter';
import useWebSocket from '../hooks/useWebSocket';

export default function SessionView() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Chat state
  const [chatItems, setChatItems] = useState([]);
  const [findings, setFindings] = useState([]);
  const [leads, setLeads] = useState([]);
  const [isAiThinking, setIsAiThinking] = useState(false);
  const [tokenUsage, setTokenUsage] = useState(null);
  const [sessionState, setSessionState] = useState('running'); // running | paused | stopped
  const [pendingAuth, setPendingAuth] = useState(null); // { auth_id, tool, command, reason, message }

  // Track streaming state for assistant messages and terminal outputs
  const streamingMessage = useRef('');
  const terminalOutputs = useRef({});
  const thinkingTimeout = useRef(null);
  const MAX_CHAT_ITEMS = 200;
  const MAX_TERMINAL_OUTPUT = 100_000; // 100 KB per terminal

  // Prune old chat items to prevent unbounded memory growth
  const pruneChat = useCallback((items) => {
    if (items.length <= MAX_CHAT_ITEMS) return items;
    const pruned = items.slice(-MAX_CHAT_ITEMS);
    if (pruned[0]?.type !== 'system_message' || pruned[0]?.content !== '[Earlier messages pruned]') {
      pruned.unshift({ type: 'system_message', content: '[Earlier messages pruned]' });
    }
    return pruned;
  }, [MAX_CHAT_ITEMS]);

  // Process each WebSocket message immediately via callback (no React batching issues)
  const handleWsMessage = useCallback((msg) => {
    switch (msg.type) {
      case 'message': {
        if (msg.role === 'assistant') {
          if (msg.streaming) {
            streamingMessage.current += msg.content || '';
            setIsAiThinking(false);
            const accumulated = streamingMessage.current;
            setChatItems((prev) => {
              const last = prev[prev.length - 1];
              if (last && last.type === 'assistant_message' && last._streaming) {
                return [
                  ...prev.slice(0, -1),
                  { type: 'assistant_message', content: accumulated, _streaming: true },
                ];
              }
              return [
                ...prev,
                { type: 'assistant_message', content: accumulated, _streaming: true },
              ];
            });
          } else {
            const content = msg.content || '';
            setIsAiThinking(false);
            streamingMessage.current = '';
            setChatItems((prev) => {
              const last = prev[prev.length - 1];
              if (last && last.type === 'assistant_message' && last._streaming) {
                if (!content) {
                  // Empty final content — remove the streaming placeholder
                  return prev.slice(0, -1);
                }
                // Replace streaming message with final version
                return [
                  ...prev.slice(0, -1),
                  { type: 'assistant_message', content },
                ];
              }
              if (last && last.type === 'assistant_message' && !last._streaming && last.content === content) {
                return prev;
              }
              if (!content) return prev;
              return [...prev, { type: 'assistant_message', content }];
            });
          }
        }
        break;
      }

      case 'command_pending': {
        setIsAiThinking(false);
        setChatItems((prev) => [
          ...prev,
          { type: 'command_pending', command: msg.command },
        ]);
        break;
      }

      case 'command_auto_executed': {
        setChatItems((prev) => [...prev, {
          type: 'terminal_output',
          commandId: msg.command.id,
          commandText: msg.command.command,
          riskLevel: msg.command.risk_level,
          output: '',
          isStreaming: true,
          exitCode: undefined,
        }]);
        break;
      }

      case 'command_output': {
        const cmdId = msg.id;
        if (msg.streaming) {
          const current = terminalOutputs.current[cmdId] || '';
          if (current.length < MAX_TERMINAL_OUTPUT) {
            terminalOutputs.current[cmdId] = current + (msg.output || '');
          }
        } else {
          terminalOutputs.current[cmdId] = msg.output || '';
        }

        setChatItems((prev) => {
          const idx = prev.findIndex(
            (item) => item.type === 'terminal_output' && item.commandId === cmdId
          );
          const output = terminalOutputs.current[cmdId] || '';

          if (idx >= 0) {
            const updated = [...prev];
            updated[idx] = { ...updated[idx], output };
            return updated;
          }
          return [...prev, {
            type: 'terminal_output',
            commandId: cmdId,
            commandText: msg.command || '',
            output,
            isStreaming: true,
            exitCode: undefined,
          }];
        });
        break;
      }

      case 'command_complete': {
        const cmdId = msg.id;
        setChatItems((prev) => {
          const idx = prev.findIndex(
            (item) => item.type === 'terminal_output' && item.commandId === cmdId
          );
          if (idx >= 0) {
            const updated = [...prev];
            updated[idx] = {
              ...updated[idx],
              isStreaming: false,
              exitCode: msg.exit_code,
            };
            return updated;
          }
          return prev;
        });
        delete terminalOutputs.current[cmdId];
        break;
      }

      case 'finding': {
        if (msg.finding) {
          setFindings((prev) => {
            if (prev.some((f) => f.id === msg.finding.id)) return prev;
            return [...prev, msg.finding];
          });
          setChatItems((prev) => [...prev, { type: 'finding', finding: msg.finding }]);
        }
        break;
      }

      case 'lead': {
        if (msg.lead) {
          setLeads((prev) => {
            if (prev.some((l) => l.id === msg.lead.id)) return prev;
            return [...prev, msg.lead];
          });
          setChatItems((prev) => [...prev, { type: 'lead', lead: msg.lead }]);
        }
        break;
      }

      case 'phase_change': {
        setChatItems((prev) => [
          ...prev,
          { type: 'phase_change', phase: msg.phase, reason: msg.reason },
        ]);
        break;
      }

      case 'token_usage': {
        setTokenUsage(msg);
        if (msg.budget_status === 'paused') {
          setIsAiThinking(false);
          setChatItems((prev) => [
            ...prev,
            { type: 'error', message: msg.budget_message || 'Token budget exceeded — session paused.' },
          ]);
        }
        break;
      }

      case 'scan_progress': {
        setIsAiThinking(false);
        const scanState = {
          status: 'running',
          round: msg.round,
          totalRounds: msg.total_rounds,
          phase: msg.phase,
          tasksTotal: msg.tasks_total,
          tasksCompleted: msg.tasks_completed,
          message: msg.message,
          tasks: [],
        };

        setChatItems((prev) => {
          // Update existing scan_progress item or add new one
          const idx = prev.findLastIndex((item) => item.type === 'scan_progress');
          if (idx >= 0) {
            const existing = prev[idx].scanState;
            // Accumulate tool statuses
            const tasks = [...(existing.tasks || [])];
            if (msg.task_name) {
              const existingTask = tasks.find((t) => t.name === msg.task_name);
              if (existingTask) {
                existingTask.status = msg.task_status || 'running';
              } else {
                tasks.push({ name: msg.task_name, status: msg.task_status || 'running' });
              }
            }
            // Reset tasks list on new round
            if (msg.round > (existing.round || 0)) {
              tasks.length = 0;
              if (msg.task_name) {
                tasks.push({ name: msg.task_name, status: msg.task_status || 'running' });
              }
            }
            scanState.tasks = tasks;
            const updated = [...prev];
            updated[idx] = { type: 'scan_progress', scanState };
            return updated;
          }
          if (msg.task_name) {
            scanState.tasks = [{ name: msg.task_name, status: msg.task_status || 'running' }];
          }
          return [...prev, { type: 'scan_progress', scanState }];
        });
        break;
      }

      case 'scan_status': {
        if (msg.status === 'starting') {
          setIsAiThinking(true);
          setChatItems((prev) => [
            ...prev,
            { type: 'system_message', content: msg.message },
          ]);
        } else if (msg.status === 'completed') {
          setIsAiThinking(false);
          setChatItems((prev) => {
            const idx = prev.findLastIndex((item) => item.type === 'scan_progress');
            if (idx >= 0) {
              const updated = [...prev];
              updated[idx] = {
                type: 'scan_progress',
                scanState: { ...updated[idx].scanState, status: 'completed', message: msg.message },
              };
              return updated;
            }
            return prev;
          });
        } else if (msg.status === 'error') {
          setIsAiThinking(false);
          setChatItems((prev) => {
            const idx = prev.findLastIndex((item) => item.type === 'scan_progress');
            if (idx >= 0) {
              const updated = [...prev];
              updated[idx] = {
                type: 'scan_progress',
                scanState: { ...updated[idx].scanState, status: 'error', message: msg.message },
              };
              return updated;
            }
            return [...prev, { type: 'error', message: msg.message }];
          });
        }
        break;
      }

      case 'session_state': {
        setSessionState(msg.state);
        if (msg.state === 'stopped' || msg.state === 'paused') {
          setIsAiThinking(false);
        }
        if (msg.message) {
          setChatItems((prev) => [
            ...prev,
            { type: 'system_message', content: msg.message },
          ]);
        }
        break;
      }

      case 'authorization_request': {
        setPendingAuth({
          auth_id: msg.auth_id,
          tool: msg.tool,
          command: msg.command,
          reason: msg.reason,
          message: msg.message,
        });
        setChatItems((prev) => [
          ...prev,
          { type: 'system_message', content: `⚠ Destructive operation detected — waiting for your authorization...` },
        ]);
        break;
      }

      case 'authorization_timeout': {
        setPendingAuth(null);
        setChatItems((prev) => [
          ...prev,
          { type: 'system_message', content: `Authorization timed out — command skipped.` },
        ]);
        break;
      }

      case 'error': {
        setIsAiThinking(false);
        setChatItems((prev) => [
          ...prev,
          { type: 'error', message: msg.message },
        ]);
        break;
      }

      default:
        break;
    }

    // Periodically prune to keep memory bounded
    setChatItems((prev) => pruneChat(prev));
  }, [pruneChat]);

  const { sendMessage, sendRaw, isConnected } = useWebSocket(id, handleWsMessage);

  // Fetch session details on mount
  useEffect(() => {
    let cancelled = false;

    async function fetchSession() {
      try {
        setLoading(true);
        const data = await getSession(id);
        if (cancelled) return;

        setSession(data.session || data);

        if (data.findings) {
          setFindings(data.findings);
        }
        if (data.leads) {
          setLeads(data.leads);
        }

        // Load pending commands into chat
        if (data.pending_commands && data.pending_commands.length > 0) {
          for (const cmd of data.pending_commands) {
            setChatItems((prev) => [...prev, { type: 'command_pending', command: cmd }]);
          }
        }

        // Load existing messages
        const msgs = data.messages || [];
        if (msgs.length > 0) {
          const items = msgs
            .filter((msg) => msg.role === 'user' || msg.role === 'assistant')
            .map((msg) => ({
              type: msg.role === 'user' ? 'user_message' : 'assistant_message',
              content: msg.content,
            }));
          setChatItems(items);
        }

        setError(null);
      } catch (err) {
        if (!cancelled) setError(err.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchSession();
    return () => { cancelled = true; };
  }, [id]);

  const handleSendMessage = useCallback(
    (content) => {
      setChatItems((prev) => [...prev, { type: 'user_message', content }]);
      const sent = sendMessage(content);
      if (sent) {
        setIsAiThinking(true);
        // Safety timeout — reset thinking state if no response in 60s
        clearTimeout(thinkingTimeout.current);
        thinkingTimeout.current = setTimeout(() => {
          setIsAiThinking((current) => {
            if (current) {
              setChatItems((prev) => [
                ...prev,
                { type: 'error', message: 'No response from AI — try again or check the connection.' },
              ]);
            }
            return false;
          });
        }, 180000);
      } else {
        setChatItems((prev) => [
          ...prev,
          { type: 'error', message: 'Failed to send — WebSocket disconnected.' },
        ]);
      }
    },
    [sendMessage]
  );

  // Clear thinking timeout when AI responds
  useEffect(() => {
    if (!isAiThinking) {
      clearTimeout(thinkingTimeout.current);
    }
  }, [isAiThinking]);

  const handleCommandAction = useCallback((action, commandId) => {
    setChatItems((prev) =>
      prev.map((item) => {
        if (
          item.type === 'command_pending' &&
          item.command?.id === commandId
        ) {
          return {
            ...item,
            command: { ...item.command, _acted: true, _action: action },
          };
        }
        return item;
      })
    );
  }, []);

  const showThinking = useMemo(() => {
    if (!isAiThinking) return false;
    const last = chatItems[chatItems.length - 1];
    if (last && last.type === 'assistant_message' && last._streaming) return false;
    return true;
  }, [isAiThinking, chatItems]);

  const showContinue = useMemo(() => {
    if (isAiThinking || !isConnected || chatItems.length === 0) return false;
    const last = chatItems[chatItems.length - 1];
    if (last?._streaming) return false;
    if (last?.type === 'assistant_message') {
      const hasPending = chatItems.some(
        (item) => item.type === 'command_pending' && !item.command?._acted
      );
      return !hasPending;
    }
    return false;
  }, [isAiThinking, isConnected, chatItems]);

  const handleContinue = useCallback(() => {
    handleSendMessage('Continue. Execute the next steps you outlined.');
  }, [handleSendMessage]);

  const handleAuthorize = useCallback((approved) => {
    if (!pendingAuth) return;
    sendRaw({
      type: 'authorization_response',
      auth_id: pendingAuth.auth_id,
      approved,
    });
    setChatItems((prev) => [
      ...prev,
      { type: 'system_message', content: approved
        ? `Command APPROVED by operator.`
        : `Command DENIED by operator.`
      },
    ]);
    setPendingAuth(null);
  }, [pendingAuth, sendRaw]);

  const handlePause = useCallback(async () => {
    try {
      await pauseSession(id);
    } catch (err) {
      console.error('Failed to pause:', err);
    }
  }, [id]);

  const handleStop = useCallback(async () => {
    try {
      await stopSession(id);
    } catch (err) {
      console.error('Failed to stop:', err);
    }
  }, [id]);

  const handleResume = useCallback(async () => {
    try {
      await resumeSession(id);
    } catch (err) {
      console.error('Failed to resume:', err);
    }
  }, [id]);

  const handleSkipTool = useCallback(async (toolName) => {
    try {
      await skipTool(id, toolName);
    } catch (err) {
      console.error('Failed to skip tool:', err);
    }
  }, [id]);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="flex items-center gap-3 text-gray-400">
          <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
          </svg>
          Loading session...
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

  return (
    <div className="h-screen flex flex-col overflow-hidden">
      {/* Header Bar */}
      <header className="flex-shrink-0 bg-gray-900/80 backdrop-blur-md border-b border-gray-800/60 px-4 py-2.5 flex items-center gap-3">
        <button
          onClick={() => setSidebarOpen(true)}
          className="lg:hidden p-1.5 text-gray-500 hover:text-gray-300 transition-colors rounded-lg hover:bg-gray-800/50"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>

        {session?.project_id && (
          <button
            onClick={() => navigate(`/project/${session.project_id}`)}
            className="p-1.5 text-gray-500 hover:text-gray-300 transition-colors rounded-lg hover:bg-gray-800/50"
            title="Back to Project"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
          </button>
        )}

        <span className="text-xs text-gray-200 font-mono bg-gray-800/50 px-2.5 py-1 rounded-lg border border-gray-700/30">{session?.target}</span>

        <div className="flex-1" />

        <TokenMeter usage={tokenUsage} />

        {/* Flow control buttons */}
        <div className="flex items-center gap-1">
          {sessionState === 'running' ? (
            <>
              <button
                onClick={handlePause}
                className="p-1.5 text-gray-500 hover:text-yellow-400 transition-colors rounded-lg hover:bg-gray-800/50"
                title="Pause"
              >
                <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
                  <rect x="6" y="4" width="4" height="16" rx="1" />
                  <rect x="14" y="4" width="4" height="16" rx="1" />
                </svg>
              </button>
              <button
                onClick={handleStop}
                className="p-1.5 text-gray-500 hover:text-red-400 transition-colors rounded-lg hover:bg-gray-800/50"
                title="Stop"
              >
                <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
                  <rect x="5" y="5" width="14" height="14" rx="2" />
                </svg>
              </button>
            </>
          ) : (
            <button
              onClick={handleResume}
              className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-emerald-400 hover:text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 rounded-lg transition-colors"
              title="Resume session"
            >
              <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24">
                <path d="M8 5v14l11-7z" />
              </svg>
              Resume
            </button>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          <div
            className={`w-1.5 h-1.5 rounded-full ${
              isConnected
                ? sessionState === 'paused'
                  ? 'bg-yellow-400'
                  : sessionState === 'stopped'
                  ? 'bg-red-500'
                  : 'bg-emerald-400 animate-pulse-glow'
                : 'bg-red-500'
            }`}
          />
          <span className="text-[10px] text-gray-600 hidden sm:inline font-mono">
            {!isConnected
              ? 'offline'
              : sessionState === 'paused'
              ? 'paused'
              : sessionState === 'stopped'
              ? 'stopped'
              : 'live'}
          </span>
        </div>
      </header>

      <ScoreBoard findings={findings} leads={leads} />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          findings={findings}
          leads={leads}
          sessionId={id}
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
        />

        <div className="flex-1 flex flex-col min-w-0">
          <ChatArea
            chatItems={chatItems}
            onCommandAction={handleCommandAction}
            isStreaming={showThinking}
            isReconStarting={chatItems.length === 0 && isConnected}
            onSkipTool={handleSkipTool}
          />
          <MessageInput
            onSend={handleSendMessage}
            showContinue={showContinue}
            onContinue={handleContinue}
            disabled={isAiThinking || !isConnected || sessionState !== 'running'}
          />
        </div>
      </div>

      {/* Authorization Modal */}
      {pendingAuth && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-gray-900 border border-red-500/50 rounded-2xl shadow-2xl shadow-red-500/10 max-w-xl w-full overflow-hidden">
            <div className="bg-red-500/10 border-b border-red-500/30 px-6 py-4 flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-red-500/20 flex items-center justify-center flex-shrink-0">
                <svg className="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
              </div>
              <div>
                <h3 className="text-red-400 font-bold text-sm uppercase tracking-wider">Destructive Operation</h3>
                <p className="text-gray-400 text-xs mt-0.5">This command may modify or delete data. Authorize?</p>
              </div>
            </div>

            <div className="px-6 py-4 space-y-3">
              {pendingAuth.reason && (
                <div>
                  <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Reason</span>
                  <p className="text-gray-300 text-sm mt-1">{pendingAuth.reason}</p>
                </div>
              )}
              <div>
                <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Command</span>
                <pre className="mt-1 bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs text-red-300 font-mono overflow-x-auto max-h-40 whitespace-pre-wrap break-all">
                  {pendingAuth.command}
                </pre>
              </div>
            </div>

            <div className="px-6 py-4 border-t border-gray-800 flex gap-3 justify-end">
              <button
                onClick={() => handleAuthorize(false)}
                className="px-5 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-xl text-sm font-semibold transition-colors"
              >
                Deny
              </button>
              <button
                onClick={() => handleAuthorize(true)}
                className="px-5 py-2.5 bg-red-600 hover:bg-red-500 text-white rounded-xl text-sm font-bold transition-colors shadow-lg shadow-red-500/20"
              >
                Approve Execution
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
