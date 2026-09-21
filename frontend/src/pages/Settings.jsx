import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getStatus, getUsers, createUser, deleteUser, resetUserPassword, changePassword } from '../api';
import { useAuth } from '../context/AuthContext';

export default function Settings() {
  const navigate = useNavigate();
  const { user: currentUser } = useAuth();
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const checkStatus = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getStatus();
      setStatus(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkStatus();
  }, [checkStatus]);

  const isOk = status?.authenticated;
  const cliFound = status?.claude_found;

  return (
    <div className="min-h-screen">
      <div className="max-w-3xl mx-auto px-6 py-8">
        <div className="mb-8">
          <h1 className="text-xl font-bold text-gray-100">Settings</h1>
          <p className="text-sm text-gray-500 mt-1">Configure HADES AI connection</p>
        </div>

        <div className="space-y-6">
        {/* Connection Status Card */}
        <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between p-5 border-b border-gray-800">
            <h2 className="text-base font-semibold text-gray-200">Claude CLI Status</h2>
            <button
              onClick={checkStatus}
              disabled={loading}
              className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 text-gray-300 border border-gray-700
                         rounded-lg text-xs font-medium hover:bg-gray-700 hover:text-gray-100
                         transition-all duration-200 disabled:opacity-50"
            >
              <svg className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {loading ? 'Testing...' : 'Re-test'}
            </button>
          </div>

          <div className="p-5 space-y-4">
            {error && (
              <div className="px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">
                {error}
              </div>
            )}

            {status && (
              <>
                {/* Overall status indicator */}
                <div className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${
                  isOk
                    ? 'bg-emerald-500/10 border-emerald-500/30'
                    : 'bg-red-500/10 border-red-500/30'
                }`}>
                  <div className={`w-3 h-3 rounded-full flex-shrink-0 ${
                    isOk ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'
                  }`} />
                  <div>
                    <p className={`text-sm font-semibold ${isOk ? 'text-emerald-400' : 'text-red-400'}`}>
                      {isOk ? 'Connected & Authenticated' : 'Not Connected'}
                    </p>
                    <p className="text-xs text-gray-400 mt-0.5">
                      {isOk
                        ? 'HADES AI is ready to assist with penetration testing'
                        : 'Claude CLI needs to be configured before HADES can work'}
                    </p>
                  </div>
                </div>

                {/* Detail rows */}
                <div className="space-y-1">
                  <DetailRow
                    label="CLI Found"
                    value={cliFound ? 'Yes' : 'No'}
                    ok={cliFound}
                  />
                  {status.claude_path && (
                    <DetailRow
                      label="Path"
                      value={status.claude_path}
                      mono
                    />
                  )}
                  <DetailRow
                    label="Authenticated"
                    value={status.authenticated ? 'Yes' : 'No'}
                    ok={status.authenticated}
                  />
                  {status.model && (
                    <DetailRow
                      label="Model"
                      value={status.model}
                    />
                  )}
                </div>

                {/* Error details */}
                {status.error && (
                  <div className="px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
                    <p className="text-xs font-medium text-gray-400 mb-1">Error Details</p>
                    <p className="text-sm text-gray-300 font-mono break-all">{status.error}</p>
                  </div>
                )}
              </>
            )}
          </div>
        </div>

        {/* Setup Instructions */}
        {status && !isOk && (
          <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
            <div className="p-5 border-b border-gray-800">
              <h2 className="text-base font-semibold text-gray-200">Setup Instructions</h2>
            </div>

            <div className="p-5 space-y-4">
              {!cliFound ? (
                <>
                  <StepCard
                    step={1}
                    title="Install Claude Code CLI"
                    description="HADES uses the Claude Code CLI as its AI backend. Install it globally via npm:"
                    command="npm install -g @anthropic-ai/claude-code"
                  />
                  <StepCard
                    step={2}
                    title="Authenticate"
                    description="Log in with your Anthropic account (uses your existing subscription — no separate API key needed):"
                    command="claude login"
                  />
                  <StepCard
                    step={3}
                    title="Verify"
                    description="Test that it works:"
                    command='claude -p "say hello"'
                  />
                </>
              ) : (
                <>
                  <StepCard
                    step={1}
                    title="Authenticate the CLI"
                    description="The Claude CLI is installed but not authenticated. Run this in your terminal:"
                    command="claude login"
                  />
                  <StepCard
                    step={2}
                    title="Follow the browser flow"
                    description="A browser window will open. Log in with your Anthropic account. This uses your existing Claude subscription — no separate API costs."
                  />
                  <StepCard
                    step={3}
                    title="Come back and re-test"
                    description='After authenticating, click "Re-test" above to verify the connection.'
                  />
                </>
              )}

              <div className="px-4 py-3 bg-cyan-400/5 border border-cyan-400/20 rounded-lg">
                <p className="text-xs text-cyan-400 font-medium mb-1">Why CLI instead of API key?</p>
                <p className="text-xs text-gray-400">
                  HADES wraps the Claude Code CLI so you use your existing subscription.
                  No separate API billing — same account, same plan, zero extra cost.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Successful connection info */}
        {isOk && (
          <div className="bg-gray-900 border border-gray-700 rounded-xl p-5">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-emerald-400/10 border border-emerald-400/30 flex items-center justify-center flex-shrink-0">
                <svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-semibold text-gray-200">All set!</p>
                <p className="text-xs text-gray-400 mt-1">
                  HADES AI is connected and ready. Go to the dashboard, create a project,
                  define your scope, and launch a session — recon starts automatically.
                </p>
                <button
                  onClick={() => navigate('/')}
                  className="mt-3 inline-flex items-center gap-2 px-4 py-2 bg-cyan-400/10 text-cyan-400
                             border border-cyan-400/30 rounded-lg text-sm font-medium
                             hover:bg-cyan-400/20 hover:border-cyan-400/50 transition-all duration-200"
                >
                  Go to Dashboard
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Change Password */}
        <ChangePasswordSection />

        {/* User Management — admin only */}
        {currentUser?.role === 'admin' && <UserManagementSection />}
        </div>
      </div>
    </div>
  );
}

// ── Change Password ──────────────────────────────────────────────────────────

function ChangePasswordSection() {
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [msg, setMsg] = useState(null);
  const [err, setErr] = useState(null);
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMsg(null);
    setErr(null);

    if (newPw !== confirmPw) {
      setErr('As senhas nao coincidem');
      return;
    }
    if (newPw.length < 6) {
      setErr('A nova senha deve ter pelo menos 6 caracteres');
      return;
    }

    setSaving(true);
    try {
      await changePassword(currentPw, newPw);
      setMsg('Senha alterada com sucesso');
      setCurrentPw('');
      setNewPw('');
      setConfirmPw('');
    } catch (error) {
      setErr(error.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
      <div className="p-5 border-b border-gray-800">
        <h2 className="text-base font-semibold text-gray-200">Alterar Senha</h2>
      </div>
      <form onSubmit={handleSubmit} className="p-5 space-y-4">
        {msg && (
          <div className="px-4 py-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-sm text-emerald-400">
            {msg}
          </div>
        )}
        {err && (
          <div className="px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">
            {err}
          </div>
        )}
        <div>
          <label className="block text-xs font-medium text-gray-400 mb-1.5">Senha Atual</label>
          <input
            type="password"
            value={currentPw}
            onChange={(e) => setCurrentPw(e.target.value)}
            required
            className="w-full px-3.5 py-2.5 bg-gray-950 border border-gray-700 rounded-lg text-sm text-gray-100
                       placeholder-gray-600 focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                       transition-all duration-200"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-400 mb-1.5">Nova Senha</label>
          <input
            type="password"
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
            required
            className="w-full px-3.5 py-2.5 bg-gray-950 border border-gray-700 rounded-lg text-sm text-gray-100
                       placeholder-gray-600 focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                       transition-all duration-200"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-400 mb-1.5">Confirmar Nova Senha</label>
          <input
            type="password"
            value={confirmPw}
            onChange={(e) => setConfirmPw(e.target.value)}
            required
            className="w-full px-3.5 py-2.5 bg-gray-950 border border-gray-700 rounded-lg text-sm text-gray-100
                       placeholder-gray-600 focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                       transition-all duration-200"
          />
        </div>
        <button
          type="submit"
          disabled={saving || !currentPw || !newPw || !confirmPw}
          className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-400/10 text-cyan-400
                     border border-cyan-400/30 rounded-lg text-sm font-medium
                     hover:bg-cyan-400/20 hover:border-cyan-400/50
                     disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200"
        >
          {saving ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
              Salvando...
            </>
          ) : 'Alterar Senha'}
        </button>
      </form>
    </div>
  );
}

// ── User Management (admin only) ─────────────────────────────────────────────

function UserManagementSection() {
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [err, setErr] = useState(null);
  const [showCreate, setShowCreate] = useState(false);

  // Create form
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('operator');
  const [creating, setCreating] = useState(false);

  // Reset password
  const [resetId, setResetId] = useState(null);
  const [resetPw, setResetPw] = useState('');
  const [resetting, setResetting] = useState(false);

  // Delete confirmation
  const [deleteId, setDeleteId] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const fetchUsers = useCallback(async () => {
    try {
      setLoadingUsers(true);
      setErr(null);
      const data = await getUsers();
      setUsers(data);
    } catch (error) {
      setErr(error.message);
    } finally {
      setLoadingUsers(false);
    }
  }, []);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  const handleCreate = async (e) => {
    e.preventDefault();
    setCreating(true);
    setErr(null);
    try {
      await createUser(newUsername, newPassword, newRole);
      setNewUsername('');
      setNewPassword('');
      setNewRole('operator');
      setShowCreate(false);
      await fetchUsers();
    } catch (error) {
      setErr(error.message);
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id) => {
    setDeleting(true);
    setErr(null);
    try {
      await deleteUser(id);
      setDeleteId(null);
      await fetchUsers();
    } catch (error) {
      setErr(error.message);
    } finally {
      setDeleting(false);
    }
  };

  const handleReset = async (id) => {
    if (!resetPw) return;
    setResetting(true);
    setErr(null);
    try {
      await resetUserPassword(id, resetPw);
      setResetId(null);
      setResetPw('');
    } catch (error) {
      setErr(error.message);
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between p-5 border-b border-gray-800">
        <h2 className="text-base font-semibold text-gray-200">Gerenciamento de Usuarios</h2>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="flex items-center gap-2 px-3 py-1.5 bg-cyan-400/10 text-cyan-400
                     border border-cyan-400/30 rounded-lg text-xs font-medium
                     hover:bg-cyan-400/20 hover:border-cyan-400/50 transition-all duration-200"
        >
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Criar Usuario
        </button>
      </div>

      <div className="p-5 space-y-4">
        {err && (
          <div className="px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">
            {err}
          </div>
        )}

        {/* Create user form */}
        {showCreate && (
          <form onSubmit={handleCreate} className="p-4 bg-gray-800/50 border border-gray-700 rounded-lg space-y-3">
            <p className="text-sm font-medium text-gray-300">Novo Usuario</p>
            <div className="grid grid-cols-2 gap-3">
              <input
                type="text"
                placeholder="Utilizador"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                required
                className="px-3 py-2 bg-gray-950 border border-gray-700 rounded-lg text-sm text-gray-100
                           placeholder-gray-600 focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                           transition-all duration-200"
              />
              <input
                type="password"
                placeholder="Senha"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                className="px-3 py-2 bg-gray-950 border border-gray-700 rounded-lg text-sm text-gray-100
                           placeholder-gray-600 focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                           transition-all duration-200"
              />
            </div>
            <div className="flex items-center gap-3">
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value)}
                className="px-3 py-2 bg-gray-950 border border-gray-700 rounded-lg text-sm text-gray-100
                           focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                           transition-all duration-200"
              >
                <option value="operator">Operador</option>
                <option value="admin">Admin</option>
              </select>
              <button
                type="submit"
                disabled={creating || !newUsername || !newPassword}
                className="px-4 py-2 bg-cyan-400/10 text-cyan-400 border border-cyan-400/30 rounded-lg text-sm font-medium
                           hover:bg-cyan-400/20 hover:border-cyan-400/50
                           disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200"
              >
                {creating ? 'Criando...' : 'Criar'}
              </button>
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                className="px-4 py-2 bg-gray-800 text-gray-400 border border-gray-700 rounded-lg text-sm
                           hover:text-gray-200 hover:bg-gray-700 transition-all duration-200"
              >
                Cancelar
              </button>
            </div>
          </form>
        )}

        {/* User list */}
        {loadingUsers ? (
          <div className="flex items-center justify-center py-8">
            <div className="w-5 h-5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : users.length === 0 ? (
          <p className="text-sm text-gray-500 text-center py-4">Nenhum usuario encontrado</p>
        ) : (
          <div className="space-y-2">
            {users.map((u) => (
              <div key={u.id} className="flex items-center justify-between px-4 py-3 bg-gray-800/50 border border-gray-700/50 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-gray-700/50 flex items-center justify-center">
                    <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z" />
                    </svg>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-200">{u.username}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                        u.role === 'admin'
                          ? 'bg-amber-400/10 text-amber-400 border border-amber-400/20'
                          : 'bg-gray-700/50 text-gray-400 border border-gray-600/50'
                      }`}>
                        {u.role}
                      </span>
                      {u.created_at && (
                        <span className="text-[10px] text-gray-600">
                          {new Date(u.created_at).toLocaleDateString('pt-BR')}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {/* Reset password */}
                  {resetId === u.id ? (
                    <div className="flex items-center gap-1.5">
                      <input
                        type="password"
                        placeholder="Nova senha"
                        value={resetPw}
                        onChange={(e) => setResetPw(e.target.value)}
                        className="px-2 py-1 bg-gray-950 border border-gray-700 rounded text-xs text-gray-100 w-28
                                   focus:outline-none focus:border-cyan-400/50 transition-all duration-200"
                      />
                      <button
                        onClick={() => handleReset(u.id)}
                        disabled={resetting || !resetPw}
                        className="px-2 py-1 bg-cyan-400/10 text-cyan-400 border border-cyan-400/30 rounded text-xs
                                   hover:bg-cyan-400/20 disabled:opacity-40 transition-all duration-200"
                      >
                        {resetting ? '...' : 'OK'}
                      </button>
                      <button
                        onClick={() => { setResetId(null); setResetPw(''); }}
                        className="px-2 py-1 bg-gray-800 text-gray-400 border border-gray-700 rounded text-xs
                                   hover:text-gray-200 transition-all duration-200"
                      >
                        X
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => { setResetId(u.id); setResetPw(''); setDeleteId(null); }}
                      title="Redefinir senha"
                      className="p-1.5 text-gray-500 hover:text-cyan-400 hover:bg-gray-700/50 rounded-lg transition-all duration-200"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
                      </svg>
                    </button>
                  )}

                  {/* Delete */}
                  {deleteId === u.id ? (
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs text-red-400">Confirmar?</span>
                      <button
                        onClick={() => handleDelete(u.id)}
                        disabled={deleting}
                        className="px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/30 rounded text-xs
                                   hover:bg-red-500/20 disabled:opacity-40 transition-all duration-200"
                      >
                        {deleting ? '...' : 'Sim'}
                      </button>
                      <button
                        onClick={() => setDeleteId(null)}
                        className="px-2 py-1 bg-gray-800 text-gray-400 border border-gray-700 rounded text-xs
                                   hover:text-gray-200 transition-all duration-200"
                      >
                        Nao
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => { setDeleteId(u.id); setResetId(null); }}
                      title="Excluir usuario"
                      className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-gray-700/50 rounded-lg transition-all duration-200"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
                      </svg>
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Shared UI components ─────────────────────────────────────────────────────

function DetailRow({ label, value, ok, mono }) {
  return (
    <div className="flex items-center justify-between px-4 py-2 rounded-lg hover:bg-gray-800/50 transition-colors">
      <span className="text-sm text-gray-400">{label}</span>
      <span className={`text-sm ${
        ok === true ? 'text-emerald-400' : ok === false ? 'text-red-400' : 'text-gray-200'
      } ${mono ? 'font-mono text-xs' : ''}`}>
        {value}
      </span>
    </div>
  );
}

function StepCard({ step, title, description, command }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (command) {
      navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="flex gap-4">
      <div className="flex-shrink-0 w-7 h-7 rounded-full bg-cyan-400/10 border border-cyan-400/30 flex items-center justify-center">
        <span className="text-xs font-bold text-cyan-400">{step}</span>
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-200">{title}</p>
        <p className="text-xs text-gray-400 mt-0.5">{description}</p>
        {command && (
          <div className="mt-2 flex items-center gap-2">
            <code className="flex-1 px-3 py-2 bg-gray-950 border border-gray-700 rounded-lg text-xs text-cyan-300 font-mono">
              {command}
            </code>
            <button
              onClick={handleCopy}
              className="flex-shrink-0 p-2 text-gray-400 hover:text-gray-100 transition-colors rounded-lg hover:bg-gray-800"
              title="Copy command"
            >
              {copied ? (
                <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              ) : (
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              )}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
