import React, { useState, lazy, Suspense } from 'react';
import { 
  Sliders, 
  Cpu, 
  Bluetooth, 
  Globe, 
  ArrowRight,
  ToggleLeft,
  LogOut,
  User,
  Shield,
  AlertTriangle
} from 'lucide-react';
import { SystemStatus } from '../types';

const GearSceneLazy = lazy(() => import('../components/3d/GearScene').then(m => ({ default: m.GearScene })));

interface SettingsProps {
  systemStatus: SystemStatus | null;
  onLogout: () => void;
}

export const Settings: React.FC<SettingsProps> = ({ systemStatus, onLogout }) => {
  const [confirmLogout, setConfirmLogout] = useState(false);
  return (
    <div className="flex gap-6">
      {/* ── Existing settings content ── */}
      <div className="flex-1 space-y-8 max-w-4xl">

      {/* PIPELINE ARCHITECTURE CONCEPT CHART */}
      <div className="dark-panel p-6 space-y-4 bg-slate-900/10">
        <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">Future-Ready Platform Architecture Flow</h3>
        
        {/* Schema block */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 text-center items-center font-mono text-[10px] text-slate-300">
          <div className="p-3 bg-slate-900 border border-slate-800 rounded">
            <p className="font-semibold text-white">DATA SOURCE</p>
            <div className="mt-2 space-y-1 text-slate-500">
              <p className="text-cyan-400 font-semibold">• CSV Uploader</p>
              <p>• ESP32 WiFi (Future)</p>
              <p>• Bluetooth LE (Future)</p>
              <p>• IoT Gateway (Future)</p>
            </div>
          </div>
          
          <ArrowRight size={16} className="mx-auto text-slate-600 rotate-90 md:rotate-0" />
          
          <div className="p-3 bg-slate-900 border border-slate-800 rounded">
            <p className="font-semibold text-white">INGESTION LAYER</p>
            <div className="mt-2 text-slate-500">
              <p>• Data Validation</p>
              <p>• Stream Buffer</p>
              <p>• Identifier Parser</p>
            </div>
          </div>
          
          <ArrowRight size={16} className="mx-auto text-slate-600 rotate-90 md:rotate-0" />
          
          <div className="p-3 bg-slate-900 border border-slate-800 rounded">
            <p className="font-semibold text-white">THREAT CORE</p>
            <div className="mt-2 text-slate-500">
              <p>• Preprocessing</p>
              <p>• ML Classifiers</p>
              <p>• Severity Rating</p>
              <p>• Recommendations</p>
            </div>
          </div>
        </div>
      </div>

      {/* CORE PIPELINE SETTINGS */}
      <div className="dark-panel p-6 space-y-6">
        <div>
          <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider flex items-center gap-1.5">
            <Sliders size={14} className="text-cyan-500" />
            Core Analytics Configurations
          </h3>
          <p className="text-xs text-slate-400 mt-1">Configure thresholds for threat classifications and pipeline behaviors.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs font-mono">
          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-500">DETECTION CONFIDENCE THRESHOLD:</label>
            <div className="flex gap-4 items-center">
              <input 
                type="range" 
                min={0.5} 
                max={0.99} 
                step={0.01} 
                defaultValue={0.7} 
                className="w-full accent-cyan-500 bg-slate-900 border border-slate-800 rounded h-1 cursor-pointer"
              />
              <span className="text-white font-semibold">70%</span>
            </div>
            <p className="text-[9px] text-slate-500 font-sans">Lower thresholds increase sensitivity (more alerts), higher values reduce false alerts.</p>
          </div>

          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-500">SEVERITY CALIBRATION CONSTANT:</label>
            <div className="flex gap-4 items-center">
              <input 
                type="range" 
                min={0.1} 
                max={1.0} 
                step={0.1} 
                defaultValue={0.8} 
                className="w-full accent-cyan-500 bg-slate-900 border border-slate-800 rounded h-1 cursor-pointer"
              />
              <span className="text-white font-semibold">0.8</span>
            </div>
            <p className="text-[9px] text-slate-500 font-sans">Modifies confidence multipliers used inside the rule-based severity engine.</p>
          </div>
        </div>
      </div>

      {/* CONCEPT HARDWARE ADAPTERS */}
      <div className="space-y-4">
        <h3 className="text-xs font-semibold text-slate-400 font-mono uppercase tracking-wider">Conceptual Hardware Adapters</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Adapter 1 */}
          <div className="dark-panel p-5 space-y-3 opacity-60 border-dashed border-slate-700/60">
            <div className="flex justify-between items-start">
              <div className="p-2 bg-slate-800 rounded text-slate-400">
                <Cpu size={16} />
              </div>
              <span className="text-[9px] font-mono text-slate-500 uppercase px-1.5 py-0.5 bg-slate-950 rounded border border-slate-900">
                DISCONNECTED
              </span>
            </div>
            <div>
              <h4 className="text-xs font-bold text-slate-300">ESP32 IoT Ingestion</h4>
              <p className="text-[10px] text-slate-400 leading-relaxed font-light mt-1">
                Ingest telemetry packages from micro-controller smart sensors in real-time. Fits the Ingestion API.
              </p>
            </div>
            <div className="pt-2 flex items-center justify-between text-[10px] font-mono text-slate-500">
              <span>PROTOCOL: UDP-Socket</span>
              <ToggleLeft size={18} className="text-slate-600 cursor-not-allowed" />
            </div>
          </div>

          {/* Adapter 2 */}
          <div className="dark-panel p-5 space-y-3 opacity-60 border-dashed border-slate-700/60">
            <div className="flex justify-between items-start">
              <div className="p-2 bg-slate-800 rounded text-slate-400">
                <Bluetooth size={16} />
              </div>
              <span className="text-[9px] font-mono text-slate-500 uppercase px-1.5 py-0.5 bg-slate-950 rounded border border-slate-900">
                DISCONNECTED
              </span>
            </div>
            <div>
              <h4 className="text-xs font-bold text-slate-300">Bluetooth Device Sync</h4>
              <p className="text-[10px] text-slate-400 leading-relaxed font-light mt-1">
                Scan and sync packets from local wearable devices and low energy beacon sensors.
              </p>
            </div>
            <div className="pt-2 flex items-center justify-between text-[10px] font-mono text-slate-500">
              <span>PROTOCOL: BLE GATT</span>
              <ToggleLeft size={18} className="text-slate-600 cursor-not-allowed" />
            </div>
          </div>

          {/* Adapter 3 */}
          <div className="dark-panel p-5 space-y-3 opacity-60 border-dashed border-slate-700/60">
            <div className="flex justify-between items-start">
              <div className="p-2 bg-slate-800 rounded text-slate-400">
                <Globe size={16} />
              </div>
              <span className="text-[9px] font-mono text-slate-500 uppercase px-1.5 py-0.5 bg-slate-950 rounded border border-slate-900">
                DISCONNECTED
              </span>
            </div>
            <div>
              <h4 className="text-xs font-bold text-slate-300">IoT Gateway Streaming</h4>
              <p className="text-[10px] text-slate-400 leading-relaxed font-light mt-1">
                MQTT bridge integration listening to brokers and sensor hubs across logical LAN segments.
              </p>
            </div>
            <div className="pt-2 flex items-center justify-between text-[10px] font-mono text-slate-500">
              <span>PROTOCOL: MQTT Client</span>
              <ToggleLeft size={18} className="text-slate-600 cursor-not-allowed" />
            </div>
          </div>
        </div>
      </div>

      {/* ── SESSION & ACCOUNT ───────────────────────────── */}
      <div className="space-y-4">
        <h3 className="text-xs font-semibold text-slate-400 font-mono uppercase tracking-wider flex items-center gap-1.5">
          <User size={13} className="text-cyan-500" />
          Session & Account
        </h3>

        <div className="dark-panel p-6 space-y-5">
          {/* Operator info row */}
          <div className="flex items-center gap-4 p-4 bg-slate-900/60 border border-slate-800 rounded-lg">
            <div className="w-11 h-11 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 font-bold text-sm shrink-0">
              SOC
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-white">operator_admin</p>
              <p className="text-[11px] text-slate-500 font-mono">ROLE: Analyst  •  IOTShield Platform</p>
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-500/10 border border-emerald-600/20 rounded-full text-[10px] font-mono text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              ACTIVE SESSION
            </div>
          </div>

          {/* Security info */}
          <div className="grid grid-cols-3 gap-3 text-xs font-mono">
            <div className="p-3 bg-slate-900 border border-slate-800 rounded space-y-1">
              <p className="text-slate-500 text-[10px]">AUTH METHOD</p>
              <div className="flex items-center gap-1.5 text-slate-300">
                <Shield size={11} className="text-cyan-400" />
                Gateway Token
              </div>
            </div>
            <div className="p-3 bg-slate-900 border border-slate-800 rounded space-y-1">
              <p className="text-slate-500 text-[10px]">SESSION TYPE</p>
              <p className="text-slate-300">Local Operator</p>
            </div>
            <div className="p-3 bg-slate-900 border border-slate-800 rounded space-y-1">
              <p className="text-slate-500 text-[10px]">ENCRYPTION</p>
              <p className="text-slate-300">TLS v1.3</p>
            </div>
          </div>

          {/* Divider */}
          <div className="border-t border-slate-800" />

          {/* Logout section */}
          {!confirmLogout ? (
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-300 font-medium">Sign out of IOTShield</p>
                <p className="text-[11px] text-slate-500 mt-0.5">Ends the current operator session and returns to the login screen.</p>
              </div>
              <button
                onClick={() => setConfirmLogout(true)}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg border border-rose-700/40 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 hover:text-rose-300 text-xs font-semibold transition-all"
              >
                <LogOut size={14} />
                Sign Out
              </button>
            </div>
          ) : (
            <div className="flex items-center justify-between p-4 bg-rose-500/10 border border-rose-700/30 rounded-lg">
              <div className="flex items-start gap-3">
                <AlertTriangle size={16} className="text-rose-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm text-rose-300 font-semibold">Confirm Sign Out</p>
                  <p className="text-[11px] text-rose-400/70 mt-0.5">Your session will be terminated. Any unsaved state will be lost.</p>
                </div>
              </div>
              <div className="flex items-center gap-2 ml-6 shrink-0">
                <button
                  onClick={() => setConfirmLogout(false)}
                  className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs font-semibold transition-all"
                >
                  Cancel
                </button>
                <button
                  onClick={onLogout}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold transition-all"
                >
                  <LogOut size={13} />
                  Confirm Sign Out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

    </div>{/* end flex-1 settings content */}

    {/* ── 3D Gear panel (right side) ── */}
    <div className="hidden xl:flex flex-col shrink-0 glass-panel p-4 space-y-3 relative overflow-hidden" style={{ width: 320, minHeight: 560 }}>
      <div className="flex items-center justify-between border-b border-cyan-900/30 pb-3">
        <div>
          <h3 className="text-xs font-bold text-white tracking-wide flex items-center gap-1.5">
            <Cpu size={14} className="text-cyan-400" />
            Platform Engine Core
          </h3>
          <p className="text-[9px] text-cyan-600 font-mono mt-0.5">ACTIVE SYSTEM DRIVER</p>
        </div>
        <span className="text-[8px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-400 animate-pulse">
          OPERATIONAL
        </span>
      </div>

      <div className="flex-1 w-full rounded-lg overflow-hidden relative">
        <Suspense fallback={
          <div className="h-full flex items-center justify-center text-xs text-slate-600 font-mono">
            Initializing 3D Engine...
          </div>
        }>
          <GearSceneLazy />
        </Suspense>
      </div>

      <div className="p-2.5 rounded bg-slate-950/60 border border-cyan-950 flex items-center justify-between text-[9px] font-mono text-slate-400">
        <span>ENGINE CLOCK</span>
        <span className="text-cyan-400 font-bold">SYNCHRONIZED</span>
      </div>
    </div>

  </div>
);
};
