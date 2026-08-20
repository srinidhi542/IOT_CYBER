import React from 'react';
import { 
  Sliders, 
  Cpu, 
  Bluetooth, 
  Globe, 
  Database,
  ArrowRight,
  ToggleLeft,
  Server
} from 'lucide-react';
import { SystemStatus } from '../types';

interface SettingsProps {
  systemStatus: SystemStatus | null;
}

export const Settings: React.FC<SettingsProps> = ({ systemStatus }) => {
  return (
    <div className="space-y-8 max-w-4xl">
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
    </div>
  );
};
