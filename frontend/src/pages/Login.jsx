import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import HadesLogo from '../components/HadesLogo';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(username, password);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center px-4">
      {/* Background grid effect */}
      <div className="fixed inset-0 bg-[linear-gradient(rgba(6,182,212,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.03)_1px,transparent_1px)] bg-[size:60px_60px] pointer-events-none" />

      <div className="relative w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="relative">
            <HadesLogo size={48} className="text-cyan-400" />
            <div className="absolute inset-0 blur-xl opacity-40">
              <HadesLogo size={48} className="text-cyan-400" />
            </div>
          </div>
          <h1 className="mt-4 text-lg font-bold tracking-[0.3em] text-cyan-400">HADES</h1>
          <p className="text-[10px] text-gray-600 tracking-widest mt-1">PENTEST PLATFORM</p>
        </div>

        {/* Login card */}
        <div className="bg-gray-900/80 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-6 shadow-2xl shadow-black/50">
          <h2 className="text-base font-semibold text-gray-200 mb-5 text-center">Entrar</h2>

          {error && (
            <div className="mb-4 px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-xs font-medium text-gray-400 mb-1.5">
                Utilizador
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
                autoComplete="username"
                className="w-full px-3.5 py-2.5 bg-gray-950 border border-gray-700 rounded-lg text-sm text-gray-100
                           placeholder-gray-600 focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                           transition-all duration-200"
                placeholder="nome de utilizador"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-xs font-medium text-gray-400 mb-1.5">
                Senha
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
                className="w-full px-3.5 py-2.5 bg-gray-950 border border-gray-700 rounded-lg text-sm text-gray-100
                           placeholder-gray-600 focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                           transition-all duration-200"
                placeholder="senha"
              />
            </div>

            <button
              type="submit"
              disabled={loading || !username || !password}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-cyan-400/10 text-cyan-400
                         border border-cyan-400/30 rounded-lg text-sm font-semibold
                         hover:bg-cyan-400/20 hover:border-cyan-400/50
                         disabled:opacity-40 disabled:cursor-not-allowed
                         transition-all duration-200 mt-6"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                  Entrando...
                </>
              ) : (
                'Entrar'
              )}
            </button>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-[10px] text-gray-700 mt-6 font-mono">HADES v3.0</p>
      </div>
    </div>
  );
}
