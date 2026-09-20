import React, { useState, useEffect } from 'react';
import { Shield, Mail, Lock, Eye, EyeOff, AlertCircle, ArrowRight, Activity, CheckCircle, BarChart3, ShieldCheck, Share2 } from 'lucide-react';

interface LoginProps {
  onLogin: () => void;
}

const mapRange = (value: number, inMin: number, inMax: number, outMin: number, outMax: number) => {
  if (value <= inMin) return outMin;
  if (value >= inMax) return outMax;
  return outMin + ((value - inMin) / (inMax - inMin)) * (outMax - outMin);
};

const PARTICLES = Array.from({ length: 150 }, (_, i) => ({
  id: i,
  angle: (i * 137.508) % 360,
  distance: 30 + (i % 60) * 1.5,
  size: 1 + (i % 3) * 0.5,
  baseOpacity: 0.2 + (i % 5) * 0.15,
}));

export const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('operator_admin');
  const [password, setPassword] = useState('sentinel_key_2026');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  
  const [scrollProgress, setScrollProgress] = useState(0);

  useEffect(() => {
    const handleScroll = () => {
      const scrollHeight = window.innerHeight * 4; 
      const progress = Math.min(1, Math.max(0, window.scrollY / scrollHeight));
      setScrollProgress(progress);
    };
    handleScroll();
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg(null);
    setTimeout(() => {
      if (username.trim() && password.length >= 6) {
        onLogin();
      } else {
        setErrorMsg('Authentication failed. Please check your credentials.');
        setLoading(false);
      }
    }, 600);
  };

  const particlesOpacity = mapRange(scrollProgress, 0.0, 0.10, 0, 1);
  const particlesGather = mapRange(scrollProgress, 0.10, 0.20, 1, 0.2); 
  
  const earthOpacity = mapRange(scrollProgress, 0.10, 0.25, 0, 1);
  const earthScale = mapRange(scrollProgress, 0.15, 0.30, 0.5, 1);
  
  const ringsOpacity = mapRange(scrollProgress, 0.25, 0.40, 0, 1);
  const ringsScale = mapRange(scrollProgress, 0.25, 0.40, 0.6, 1);
  
  const shieldDraw = mapRange(scrollProgress, 0.40, 0.55, 1200, 0); 
  const shieldOpacity = mapRange(scrollProgress, 0.40, 0.55, 0, 1);
  
  const pulseOpacity = mapRange(scrollProgress, 0.55, 0.65, 0, 1) - mapRange(scrollProgress, 0.65, 0.70, 0, 1);
  const pulseScale = mapRange(scrollProgress, 0.55, 0.70, 1, 1.3);
  
  const textOpacity = mapRange(scrollProgress, 0.65, 0.75, 0, 1);
  const textBlur = mapRange(scrollProgress, 0.65, 0.75, 10, 0);
  const streakLeft = mapRange(scrollProgress, 0.65, 0.75, -50, 150);
  const streakOpacity = mapRange(scrollProgress, 0.65, 0.70, 0, 1) - mapRange(scrollProgress, 0.70, 0.75, 0, 1);
  
  const subOpacity = mapRange(scrollProgress, 0.75, 0.85, 0, 1);
  const subY = mapRange(scrollProgress, 0.75, 0.85, 20, 0);

  const rotation = scrollProgress * 360;

  return (
    <>
      <style>{`
        body { background-color: #01030a; color: white; overflow-x: hidden; }
        
        .glass-panel {
          background: rgba(10, 15, 26, 0.6);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid rgba(59, 130, 246, 0.2);
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5), inset 0 0 20px rgba(59, 130, 246, 0.05);
        }

        .scroll-indicator {
          animation: bounce 2s infinite;
        }
        @keyframes bounce {
          0%, 100% { transform: translateY(0); opacity: 0.5; }
          50% { transform: translateY(10px); opacity: 1; }
        }
      `}</style>

      <div className="relative w-full" style={{ height: '500vh' }}>
        
        <div className="sticky top-0 left-0 w-full h-screen overflow-hidden bg-[#01030a] flex items-center">
          
          <div className="absolute top-[-20%] right-[-10%] w-[600px] h-[600px] rounded-full bg-blue-900/10 blur-[120px] pointer-events-none" />
          
          <div className="w-full max-w-[1400px] mx-auto px-10 flex items-center h-full">
            
            {/* SCROLL-DRIVEN LEFT TEXT AREA */}
            <div className="w-1/2 relative z-20 flex flex-col justify-center">
              
              <div 
                className="flex items-center gap-3 mb-6"
                style={{ opacity: textOpacity, transform: `translateY(${mapRange(scrollProgress, 0.65, 0.75, 20, 0)}px)` }}
              >
                <div className="w-10 h-10 flex items-center justify-center rounded-lg border border-blue-500/50 bg-blue-500/10 shadow-[0_0_15px_rgba(37,99,235,0.4)]">
                  <Shield className="text-blue-400" size={24} />
                </div>
              </div>

              <div className="relative inline-block" style={{ opacity: textOpacity, filter: `blur(${textBlur}px)` }}>
                <h1 className="text-7xl md:text-[5.5rem] font-bold text-transparent bg-clip-text bg-gradient-to-r from-white via-blue-100 to-cyan-300 tracking-tight leading-none drop-shadow-[0_0_20px_rgba(37,99,235,0.5)]">
                  IOT SHIELD
                </h1>
                
                <div 
                  className="absolute top-1/2 -translate-y-1/2 w-[50%] h-[2px] bg-white shadow-[0_0_25px_4px_#fff] mix-blend-overlay pointer-events-none"
                  style={{ left: `${streakLeft}%`, opacity: streakOpacity }}
                />
              </div>

              <div 
                className="w-full max-w-[400px] h-[2px] bg-gradient-to-r from-cyan-400 via-blue-600 to-transparent mt-2 mb-6"
                style={{ opacity: textOpacity, transform: `scaleX(${textOpacity})`, transformOrigin: 'left' }}
              />

              <h2 
                className="text-cyan-400 text-xl md:text-2xl font-bold uppercase tracking-[0.2em] drop-shadow-[0_0_10px_rgba(14,165,233,0.5)]"
                style={{ opacity: subOpacity, transform: `translateY(${subY}px)` }}
              >
                Secure
              </h2>

            </div>

            {/* SCROLL-DRIVEN RIGHT EARTH & EFFECTS */}
            <div className="w-1/2 relative h-full flex items-center justify-center pointer-events-none perspective-[1200px]">
              
              <div className="relative flex items-center justify-center" style={{ width: 600, height: 600 }}>
                
                <div 
                  className="absolute inset-0"
                  style={{ opacity: particlesOpacity, transform: `scale(${particlesGather}) rotate(${rotation * 0.2}deg)` }}
                >
                  {PARTICLES.map((p) => {
                    const rad = (p.angle * Math.PI) / 180;
                    const x = 50 + Math.cos(rad) * p.distance;
                    const y = 50 + Math.sin(rad) * p.distance;
                    return (
                      <div key={p.id} className="absolute rounded-full bg-cyan-300 shadow-[0_0_8px_#0ea5e9]"
                        style={{
                          left: `${x}%`, top: `${y}%`,
                          width: `${p.size}px`, height: `${p.size}px`,
                          opacity: p.baseOpacity
                        }} 
                      />
                    );
                  })}
                </div>

                <div 
                  className="absolute inset-0 flex items-center justify-center"
                  style={{ opacity: earthOpacity, transform: `scale(${earthScale})` }}
                >
                  <img 
                    src="/globe.jpg" 
                    alt="Earth" 
                    className="w-[450px] h-[450px] object-cover rounded-full" 
                    style={{ 
                      maskImage: 'radial-gradient(circle, rgba(0,0,0,1) 58%, rgba(0,0,0,0) 70%)',
                      WebkitMaskImage: 'radial-gradient(circle, rgba(0,0,0,1) 58%, rgba(0,0,0,0) 70%)',
                      filter: 'drop-shadow(0 0 50px rgba(14,165,233,0.4))'
                    }} 
                  />
                </div>

                <div 
                  className="absolute inset-0 flex items-center justify-center"
                  style={{ opacity: ringsOpacity, transform: `scale(${ringsScale})` }}
                >
                  <div className="absolute w-[500px] h-[500px] rounded-full border border-cyan-400/30" style={{ transform: `rotateX(70deg) rotateZ(${rotation}deg)` }} />
                  <div className="absolute w-[560px] h-[560px] rounded-full border border-blue-500/20" style={{ transform: `rotateX(60deg) rotateY(20deg) rotateZ(${-rotation}deg)` }} />
                  <div className="absolute w-[640px] h-[640px] rounded-full border border-cyan-300/10" style={{ transform: `rotateX(80deg) rotateY(-20deg) rotateZ(${rotation * 1.5}deg)` }} />
                </div>

                <div 
                  className="absolute inset-0 z-30 flex items-center justify-center"
                  style={{ opacity: shieldOpacity, transform: `scale(${earthScale * 1.05})` }}
                >
                  <svg width="450" height="450" viewBox="0 0 100 100">
                    <path 
                      d="M50 5 L90 20 L90 50 C90 75 50 95 50 95 C50 95 10 75 10 50 L10 20 Z" 
                      fill="none" 
                      stroke="#0ea5e9" 
                      strokeWidth="1.5" 
                      strokeLinecap="round" 
                      strokeLinejoin="round" 
                      style={{ strokeDasharray: 1200, strokeDashoffset: shieldDraw, filter: 'drop-shadow(0 0 10px #0ea5e9)' }}
                    />
                  </svg>
                </div>

                <div 
                  className="absolute inset-0 z-20 flex items-center justify-center pointer-events-none"
                  style={{ opacity: pulseOpacity, transform: `scale(${pulseScale})` }}
                >
                   <svg width="450" height="450" viewBox="0 0 100 100">
                    <path 
                      d="M50 5 L90 20 L90 50 C90 75 50 95 50 95 C50 95 10 75 10 50 L10 20 Z" 
                      fill="rgba(14,165,233,0.3)" 
                      stroke="#0ea5e9" 
                      strokeWidth="2" 
                      style={{ filter: 'drop-shadow(0 0 20px #0ea5e9) blur(4px)' }}
                    />
                  </svg>
                </div>

              </div>
            </div>

          </div>

          <div 
            className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 pointer-events-none"
            style={{ opacity: Math.max(0, 1 - scrollProgress * 5) }}
          >
            <span className="text-xs tracking-[0.2em] text-cyan-500/80 uppercase">Scroll Down</span>
            <div className="scroll-indicator w-6 h-10 rounded-full border border-cyan-500/40 flex justify-center pt-2 bg-slate-900/50 backdrop-blur-sm">
              <div className="w-1 h-2 bg-cyan-400 rounded-full" />
            </div>
          </div>
        </div>
      </div>

      <div className="relative z-10 w-full min-h-screen flex items-center justify-center py-20 px-6 bg-[#01030a] border-t border-blue-900/30">
        
        <div className="flex w-full max-w-[1200px] mx-auto gap-16 items-center">
          
          {/* STATIC LEFT INFO AREA (UPDATED) */}
          <div className="w-[45%]">
            <p className="text-blue-500 text-[11px] font-bold tracking-[0.25em] uppercase mb-4">
              Next-Gen IoT Security Platform
            </p>

            <h2 className="text-5xl font-bold text-white mb-6 leading-[1.2]">
              Intelligent defense<br />for a <span className="text-blue-500">connected</span> world
            </h2>
            
            <div className="w-10 h-0.5 bg-blue-600 mb-6" />

            <p className="text-slate-400 text-[15px] leading-relaxed mb-16">
              AI-powered intrusion detection system<br />to secure your IoT ecosystem in real time.
            </p>
            
            <div className="flex gap-6 md:gap-10">
              <div className="flex flex-col items-center gap-3 text-center">
                <div className="w-12 h-12 flex items-center justify-center text-blue-500 border border-blue-500/30 rounded-xl bg-blue-500/5">
                  <Activity size={24} strokeWidth={1.5} />
                </div>
                <div>
                  <p className="text-slate-300 text-xs font-medium">Real-time</p>
                  <p className="text-slate-500 text-[11px]">Threat Detection</p>
                </div>
              </div>

              <div className="flex flex-col items-center gap-3 text-center">
                <div className="w-12 h-12 flex items-center justify-center text-blue-500 border border-blue-500/30 rounded-xl bg-blue-500/5">
                  <Share2 size={24} strokeWidth={1.5} />
                </div>
                <div>
                  <p className="text-slate-300 text-xs font-medium">AI-driven</p>
                  <p className="text-slate-500 text-[11px]">Analysis</p>
                </div>
              </div>

              <div className="flex flex-col items-center gap-3 text-center">
                <div className="w-12 h-12 flex items-center justify-center text-blue-500 border border-blue-500/30 rounded-xl bg-blue-500/5">
                  <BarChart3 size={24} strokeWidth={1.5} />
                </div>
                <div>
                  <p className="text-slate-300 text-xs font-medium">Actionable</p>
                  <p className="text-slate-500 text-[11px]">Intelligence</p>
                </div>
              </div>

              <div className="flex flex-col items-center gap-3 text-center">
                <div className="w-12 h-12 flex items-center justify-center text-blue-500 border border-blue-500/30 rounded-xl bg-blue-500/5">
                  <ShieldCheck size={24} strokeWidth={1.5} />
                </div>
                <div>
                  <p className="text-slate-300 text-xs font-medium">Smarter</p>
                  <p className="text-slate-500 text-[11px]">Response</p>
                </div>
              </div>
            </div>
          </div>

          {/* STATIC RIGHT SIGN IN FORM */}
          <div className="w-[55%] flex justify-center">
            <div className="glass-panel w-full max-w-[420px] rounded-3xl p-10 relative overflow-hidden group">
              <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/10 rounded-full blur-[80px] -translate-y-1/2 translate-x-1/2 group-hover:bg-cyan-400/20 transition-colors duration-700 pointer-events-none" />
              
              <div className="text-center mb-8 relative z-10">
                <h3 className="text-2xl font-bold text-white mb-2">Welcome back</h3>
                <p className="text-slate-400 text-xs mt-2">Sign in to access your IoT Shield workspace</p>
                <div className="w-10 h-0.5 mx-auto mt-4" style={{ background: 'linear-gradient(90deg,#3b82f6,#38bdf8)' }} />
              </div>

              <form onSubmit={handleSubmit} className="space-y-4 relative z-10">
                {errorMsg && (
                  <div className="flex items-center gap-2 p-3 rounded-lg text-rose-400 text-xs bg-rose-500/10 border border-rose-500/20">
                    <AlertCircle size={14} className="shrink-0" /> {errorMsg}
                  </div>
                )}

                <div className="space-y-1.5">
                  <label className="text-slate-300 text-xs font-semibold">Email address</label>
                  <div className="flex items-center gap-3 px-4 py-3 rounded-xl text-sm transition-all bg-[#050a14]/80 border border-slate-700/60 focus-within:border-cyan-500/60 focus-within:shadow-[0_0_15px_rgba(14,165,233,0.15)]">
                    <Mail size={16} className="text-slate-500 shrink-0" />
                    <input type="text" value={username} onChange={e => setUsername(e.target.value)}
                      placeholder="Enter your email" required
                      className="bg-transparent border-none outline-none w-full text-white placeholder-slate-600 text-sm" />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-slate-300 text-xs font-semibold">Password</label>
                  <div className="flex items-center gap-3 px-4 py-3 rounded-xl text-sm transition-all bg-[#050a14]/80 border border-slate-700/60 focus-within:border-cyan-500/60 focus-within:shadow-[0_0_15px_rgba(14,165,233,0.15)]">
                    <Lock size={16} className="text-slate-500 shrink-0" />
                    <input type={showPassword ? 'text' : 'password'} value={password}
                      onChange={e => setPassword(e.target.value)} placeholder="Enter your password" required
                      className="bg-transparent border-none outline-none w-full text-white placeholder-slate-600 text-sm" />
                    <button type="button" onClick={() => setShowPassword(!showPassword)}
                            className="text-slate-500 hover:text-slate-300 transition-colors shrink-0">
                      {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs pt-2">
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <div onClick={() => setRememberMe(!rememberMe)}
                         className="w-4 h-4 rounded flex items-center justify-center border transition-all cursor-pointer"
                         style={{ background: rememberMe ? '#3b82f6' : 'transparent', borderColor: rememberMe ? '#3b82f6' : '#475569' }}>
                      {rememberMe && <CheckCircle size={10} className="text-white" />}
                    </div>
                    <span className="text-slate-300 font-medium">Remember me</span>
                  </label>
                  <button type="button" className="text-blue-400 hover:text-blue-300 transition-colors font-medium">Forgot password?</button>
                </div>

                <button type="submit" disabled={loading}
                  className="w-full mt-4 flex items-center justify-center gap-2 py-3.5 rounded-xl text-white font-bold text-sm transition-all overflow-hidden relative group"
                  style={{ background: 'linear-gradient(90deg, #3b82f6, #1d4ed8)', boxShadow: '0 8px 25px rgba(29,78,216,0.3)' }}>
                  <div className="absolute inset-0 w-full h-full bg-white/10 -translate-x-full group-hover:translate-x-full transition-transform duration-700 ease-in-out" />
                  {loading ? (
                    <div className="w-5 h-5 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  ) : (
                    <><span>Sign In</span> <ArrowRight size={16} /></>
                  )}
                </button>
              </form>

              <div className="flex items-center gap-3 my-6 relative z-10">
                <div className="flex-1 h-px bg-slate-700/50" />
                <span className="text-slate-500 text-[11px]">or continue with</span>
                <div className="flex-1 h-px bg-slate-700/50" />
              </div>

              <div className="flex gap-4 relative z-10">
                {[
                  <svg key="g" width="18" height="18" viewBox="0 0 24 24"><path fill="#EA4335" d="M5.26 9.77A7.2 7.2 0 0 1 12 4.8c1.73 0 3.27.62 4.5 1.62l3.35-3.35A12 12 0 0 0 0 12c0 1.99.49 3.87 1.35 5.52l4.05-3.14A7.2 7.2 0 0 1 4.8 12c0-.78.16-1.53.46-2.23z"/><path fill="#FBBC05" d="M1.35 17.52A12 12 0 0 0 12 24c3.12 0 5.95-1.13 8.12-2.97l-3.96-3.08A7.2 7.2 0 0 1 4.8 12c0-.78.16-1.53.46-2.23L1.21 6.63A11.97 11.97 0 0 0 0 12c0 1.99.49 3.87 1.35 5.52z"/><path fill="#4285F4" d="M23.76 12.27c0-.87-.08-1.72-.22-2.54H12v4.82h6.6a5.65 5.65 0 0 1-2.44 3.7l3.96 3.08C22.24 19.44 23.76 16.07 23.76 12.27z"/><path fill="#34A853" d="M12 24a12 12 0 0 0 8.12-2.97l-3.96-3.08A7.2 7.2 0 0 1 4.8 12H1.35A12 12 0 0 0 12 24z"/></svg>,
                  <svg key="gh" width="18" height="18" viewBox="0 0 24 24" fill="white"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.2 11.38.6.1.82-.26.82-.58v-2.04c-3.34.72-4.04-1.61-4.04-1.61-.54-1.38-1.33-1.75-1.33-1.75-1.09-.74.08-.73.08-.73 1.2.09 1.84 1.24 1.84 1.24 1.07 1.83 2.8 1.3 3.49 1 .1-.78.42-1.31.76-1.61-2.66-.3-5.46-1.33-5.46-5.93 0-1.31.47-2.38 1.24-3.22-.13-.3-.54-1.52.12-3.17 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 3-.4c1.02 0 2.04.14 3 .4 2.28-1.55 3.29-1.23 3.29-1.23.66 1.65.24 2.87.12 3.17.77.84 1.23 1.91 1.23 3.22 0 4.61-2.8 5.63-5.48 5.92.43.37.81 1.1.81 2.22v3.29c0 .32.22.69.83.57C20.57 21.8 24 17.3 24 12 24 5.37 18.63 0 12 0z"/></svg>,
                  <svg key="ms" width="18" height="18" viewBox="0 0 24 24"><path fill="#F25022" d="M0 0h11.5v11.5H0z"/><path fill="#7FBA00" d="M12.5 0H24v11.5H12.5z"/><path fill="#00A4EF" d="M0 12.5h11.5V24H0z"/><path fill="#FFB900" d="M12.5 12.5H24V24H12.5z"/></svg>,
                ].map((icon, i) => (
                  <button key={i} className="flex-1 flex items-center justify-center py-2.5 rounded-xl bg-[#050a14]/80 border border-slate-700/60 transition-all hover:bg-slate-800">
                    {icon}
                  </button>
                ))}
              </div>

              <p className="text-center text-slate-500 text-[10px] mt-6 flex items-center justify-center gap-1.5 relative z-10">
                <Lock size={10} /> Your data is encrypted and secure
              </p>
            </div>
          </div>
        </div>
        
        <div className="absolute bottom-6 w-full text-center">
          <p className="text-slate-600 text-[10px] uppercase tracking-widest font-mono">© 2026 IOTShield Cybersecurity Network</p>
        </div>
      </div>
    </>
  );
};
