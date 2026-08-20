import React, { useState } from 'react';
import { Shield, Key, User, Cpu, AlertCircle } from 'lucide-react';

interface LoginProps {
  onLogin: () => void;
}

export const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('operator_admin');
  const [password, setPassword] = useState('sentinel_key_2026');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg(null);

    // Simulate auth check (200ms delay)
    setTimeout(() => {
      if (username.trim() && password.length >= 6) {
        onLogin();
      } else {
        setErrorMsg('Authentication failed: Invalid credentials or key length.');
        setLoading(false);
      }
    }, 400);
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-[#030712] text-slate-100 px-6">
      {/* BRAND HEADER */}
      <div className="flex items-center gap-3 mb-8">
        <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-cyan-600/20 text-cyan-400 border border-cyan-500/30">
          <Cpu size={24} className="animate-pulse" />
        </div>
        <div>
          <h1 className="font-bold text-xl tracking-wider text-white">IOTShield</h1>
          <p className="text-[10px] text-slate-400 font-mono tracking-wider uppercase">Intelligent IoT Threat Detection Platform</p>
        </div>
      </div>

      {/* LOGIN CARD */}
      <div className="w-full max-w-sm p-8 bg-[#0b0f19] border border-slate-800 rounded-lg shadow-2xl">
        <form onSubmit={handleSubmit} className="space-y-5">
          <h2 className="text-sm font-semibold text-slate-300 font-mono uppercase tracking-widest border-b border-slate-800 pb-3 mb-4">
            Security Gateway
          </h2>

          {errorMsg && (
            <div className="flex items-center gap-2 p-3 bg-rose-500/10 border border-rose-900/30 rounded text-rose-400 text-xs font-mono">
              <AlertCircle size={14} className="shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Username */}
          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-500 font-mono">OPERATOR USERNAME:</label>
            <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs focus-within:border-cyan-500">
              <User size={14} className="text-slate-500" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username..."
                required
                className="bg-transparent border-none focus:outline-none w-full text-white"
              />
            </div>
          </div>

          {/* Password */}
          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-500 font-mono">SECURITY PIN / PASSKEY:</label>
            <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs focus-within:border-cyan-500">
              <Key size={14} className="text-slate-500" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Passkey..."
                required
                className="bg-transparent border-none focus:outline-none w-full text-white"
              />
            </div>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs disabled:opacity-50 disabled:cursor-not-allowed transition-all font-mono tracking-wider"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 rounded-full border-2 border-slate-800 border-t-white animate-spin" />
                <span>AUTHORIZING...</span>
              </>
            ) : (
              <>
                <Shield size={14} />
                <span>AUTHORIZE TERMINAL</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* FOOTER */}
      <div className="mt-12 text-center text-[10px] font-mono text-slate-600">
        <p>CONSOLE SECURED BY TLS v1.3 | SHA256 INTEGRITY VALIDATION</p>
        <p className="mt-1">LOCAL OPERATING IP: 127.0.0.1</p>
      </div>
    </div>
  );
};
