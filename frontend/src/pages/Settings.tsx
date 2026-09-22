import React, { useState, useEffect } from 'react';
import { 
  Sliders, 
  Cpu, 
  Radio, 
  Database, 
  Activity, 
  ShieldAlert, 
  CheckCircle2, 
  AlertCircle,
  Save,
  RotateCcw,
  LogOut,
  User,
  Shield,
  AlertTriangle,
  Folder,
  Layers,
  Network,
  Zap,
  Lock,
  RefreshCw
} from 'lucide-react';
import { SystemStatus, PlatformSettings, NetworkInterface, MLModel } from '../types';
import { apiService } from '../services/api';

interface SettingsProps {
  systemStatus: SystemStatus | null;
  onLogout: () => void;
}

export const Settings: React.FC<SettingsProps> = ({ systemStatus, onLogout }) => {
  const [confirmLogout, setConfirmLogout] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [models, setModels] = useState<MLModel[]>([]);
  const [healthMap, setHealthMap] = useState<Record<string, { name: string; status: string; details?: string }>>({});
  const [agentsHealthMap, setAgentsHealthMap] = useState<Record<string, { name: string; status: string; details?: string }>>({});

  const [settingsState, setSettingsState] = useState<PlatformSettings>({
    network_capture: {
      default_interface: 'Wi-Fi',
      capture_duration: 30,
      auto_stop: true,
      pcap_storage_path: 'backend/uploads',
    },
    flow_extraction: {
      flow_timeout: 120,
      output_directory: 'backend/uploads',
      auto_process_pcap: true,
    },
    detection_engine: {
      active_model_id: 1,
      confidence_threshold: 0.70,
      shap_top_k: 5,
    },
    multi_agent_pipeline: {
      execution_mode: 'coordinated',
      analyst_approval_required: true,
    },
    threat_intelligence: {
      enable_mitre: true,
      enable_nvd_cve: true,
      enable_cisa: true,
      rag_top_k: 3,
    },
    data_storage: {
      pcap_path: 'backend/uploads',
      flow_csv_path: 'backend/uploads',
      report_path: 'backend/reports',
      retention_days: 30,
    }
  });

  const fetchSettingsAndData = async () => {
    try {
      setLoading(true);
      const res = await apiService.getPlatformSettings();
      if (res && res.settings) {
        setSettingsState(res.settings);
      }
      if (res && res.health) setHealthMap(res.health);
      if (res && res.agents_health) setAgentsHealthMap(res.agents_health);

      const ifaces = await apiService.getCaptureInterfaces().catch(() => []);
      setInterfaces(ifaces);

      const mList = await apiService.getModels().catch(() => []);
      setModels(mList);
    } catch (err: any) {
      console.error("Error loading settings:", err);
      setSaveError("Failed to fetch platform settings from backend.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettingsAndData();
  }, []);

  const handleSaveSettings = async () => {
    try {
      setSaving(true);
      setSaveSuccess(null);
      setSaveError(null);
      const res = await apiService.updatePlatformSettings(settingsState);
      if (res && res.settings) setSettingsState(res.settings);
      if (res && res.health) setHealthMap(res.health);
      if (res && res.agents_health) setAgentsHealthMap(res.agents_health);
      setSaveSuccess("Configuration saved and applied to live pipeline successfully!");
      setTimeout(() => setSaveSuccess(null), 4000);
    } catch (err: any) {
      setSaveError(err.message || "Failed to persist configuration settings.");
    } finally {
      setSaving(false);
    }
  };

  const handleResetDefaults = () => {
    setSettingsState({
      network_capture: {
        default_interface: interfaces.length > 0 ? interfaces[0].id : 'Wi-Fi',
        capture_duration: 30,
        auto_stop: true,
        pcap_storage_path: 'backend/uploads',
      },
      flow_extraction: {
        flow_timeout: 120,
        output_directory: 'backend/uploads',
        auto_process_pcap: true,
      },
      detection_engine: {
        active_model_id: models.length > 0 ? models[0].id : 1,
        confidence_threshold: 0.70,
        shap_top_k: 5,
      },
      multi_agent_pipeline: {
        execution_mode: 'coordinated',
        analyst_approval_required: true,
      },
      threat_intelligence: {
        enable_mitre: true,
        enable_nvd_cve: true,
        enable_cisa: true,
        rag_top_k: 3,
      },
      data_storage: {
        pcap_path: 'backend/uploads',
        flow_csv_path: 'backend/uploads',
        report_path: 'backend/reports',
        retention_days: 30,
      }
    });
    setSaveSuccess("Reset configuration controls to system defaults. Click Save to persist.");
  };

  const getStatusBadge = (status?: string) => {
    switch (status?.toLowerCase()) {
      case 'operational':
      case 'ready':
        return 'bg-emerald-950/80 text-emerald-400 border-emerald-700/60';
      case 'fallback mode':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/60';
      default:
        return 'bg-slate-900 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="space-y-6 max-w-5xl">

        {/* TOP HEADER & SAVE BAR */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-base font-bold font-mono text-white tracking-wider uppercase flex items-center gap-2">
              <Sliders size={18} className="text-cyan-400" />
              Configuration Control Center
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Enterprise SOC runtime configuration, capture interfaces, pipeline parameters, and system health matrix.
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={handleResetDefaults}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-white font-mono text-xs font-semibold transition-colors"
              title="Reset all fields to standard defaults"
            >
              <RotateCcw size={13} />
              <span>Defaults</span>
            </button>

            <button
              onClick={handleSaveSettings}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold uppercase transition-all shadow-lg shadow-cyan-950/40 disabled:opacity-50"
            >
              {saving ? (
                <div className="w-3.5 h-3.5 rounded-full border-2 border-white/30 border-t-white animate-spin" />
              ) : (
                <Save size={14} />
              )}
              <span>{saving ? 'Saving...' : 'Save Configuration'}</span>
            </button>
          </div>
        </div>

        {/* FEEDBACK BANNERS */}
        {saveSuccess && (
          <div className="p-4 bg-emerald-500/10 border border-emerald-900/40 rounded-lg text-emerald-400 text-xs font-mono flex items-center gap-2">
            <CheckCircle2 size={16} className="shrink-0" />
            <span>{saveSuccess}</span>
          </div>
        )}

        {saveError && (
          <div className="p-4 bg-rose-500/10 border border-rose-900/40 rounded-lg text-rose-400 text-xs font-mono flex items-center gap-2">
            <AlertCircle size={16} className="shrink-0" />
            <span>{saveError}</span>
          </div>
        )}

        {/* ═══════════════════════════════════════════════════
            1. NETWORK CAPTURE
        ═══════════════════════════════════════════════════ */}
        <div className="dark-panel p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Network size={16} className="text-cyan-400" />
              <h3 className="text-xs font-semibold text-white font-mono uppercase tracking-wider">
                1. Network Packet Capture & TShark Sniffer
              </h3>
            </div>
            <span className={`px-2.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase border ${getStatusBadge(healthMap.tshark?.status)}`}>
              TShark: {healthMap.tshark?.status || 'Active'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label className="text-[10px] text-slate-500 block mb-1">DEFAULT TSHARK CAPTURE INTERFACE:</label>
              <select
                value={settingsState.network_capture.default_interface}
                onChange={e => setSettingsState({
                  ...settingsState,
                  network_capture: { ...settingsState.network_capture, default_interface: e.target.value }
                })}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              >
                {interfaces.length > 0 ? (
                  interfaces.map(iface => (
                    <option key={iface.id} value={iface.id}>
                      {iface.name} ({iface.ip_address || 'No IP'})
                    </option>
                  ))
                ) : (
                  <option value="Wi-Fi">Wi-Fi Adapter (Default System Interface)</option>
                )}
              </select>
            </div>

            <div>
              <label className="text-[10px] text-slate-500 block mb-1">CAPTURE DURATION LIMIT (SECONDS):</label>
              <input
                type="number"
                min={5}
                max={3600}
                value={settingsState.network_capture.capture_duration}
                onChange={e => setSettingsState({
                  ...settingsState,
                  network_capture: { ...settingsState.network_capture, capture_duration: parseInt(e.target.value) || 30 }
                })}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-500 block mb-1">PCAP STORAGE DIRECTORY:</label>
              <input
                type="text"
                value={settingsState.network_capture.pcap_storage_path}
                onChange={e => setSettingsState({
                  ...settingsState,
                  network_capture: { ...settingsState.network_capture, pcap_storage_path: e.target.value }
                })}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="flex items-center justify-between p-3 rounded bg-slate-900/60 border border-slate-800 mt-4">
              <div>
                <span className="text-white font-bold block">Auto-Stop After Limit</span>
                <span className="text-[10px] text-slate-500">Automatically stop capture session when duration is reached</span>
              </div>
              <input
                type="checkbox"
                checked={settingsState.network_capture.auto_stop}
                onChange={e => setSettingsState({
                  ...settingsState,
                  network_capture: { ...settingsState.network_capture, auto_stop: e.target.checked }
                })}
                className="w-4 h-4 accent-cyan-500 cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════
            2. FLOW EXTRACTION
        ═══════════════════════════════════════════════════ */}
        <div className="dark-panel p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Zap size={16} className="text-cyan-400" />
              <h3 className="text-xs font-semibold text-white font-mono uppercase tracking-wider">
                2. Flow Extraction & CICFlowMeter
              </h3>
            </div>
            <span className={`px-2.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase border ${getStatusBadge(healthMap.cicflowmeter?.status)}`}>
              CICFlowMeter: {healthMap.cicflowmeter?.status || 'Ready'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label className="text-[10px] text-slate-500 block mb-1">FLOW INACTIVITY TIMEOUT (SECONDS):</label>
              <input
                type="number"
                min={10}
                max={600}
                value={settingsState.flow_extraction.flow_timeout}
                onChange={e => setSettingsState({
                  ...settingsState,
                  flow_extraction: { ...settingsState.flow_extraction, flow_timeout: parseInt(e.target.value) || 120 }
                })}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-500 block mb-1">OUTPUT DIRECTORY FOR FLOW FEATURES:</label>
              <input
                type="text"
                value={settingsState.flow_extraction.output_directory}
                onChange={e => setSettingsState({
                  ...settingsState,
                  flow_extraction: { ...settingsState.flow_extraction, output_directory: e.target.value }
                })}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="md:col-span-2 flex items-center justify-between p-3 rounded bg-slate-900/60 border border-slate-800">
              <div>
                <span className="text-white font-bold block">Auto-Process Ingested PCAP Files</span>
                <span className="text-[10px] text-slate-500">Automatically trigger CICFlowMeter feature extraction upon PCAP upload</span>
              </div>
              <input
                type="checkbox"
                checked={settingsState.flow_extraction.auto_process_pcap}
                onChange={e => setSettingsState({
                  ...settingsState,
                  flow_extraction: { ...settingsState.flow_extraction, auto_process_pcap: e.target.checked }
                })}
                className="w-4 h-4 accent-cyan-500 cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════
            3. DETECTION ENGINE
        ═══════════════════════════════════════════════════ */}
        <div className="dark-panel p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Cpu size={16} className="text-purple-400" />
              <h3 className="text-xs font-semibold text-white font-mono uppercase tracking-wider">
                3. ML Detection Engine & SHAP Explainer
              </h3>
            </div>
            <span className={`px-2.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase border ${getStatusBadge(healthMap.xgboost?.status)}`}>
              Model Engine: {healthMap.xgboost?.status || 'Ready'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div>
              <label className="text-[10px] text-slate-500 block mb-1">ACTIVE CLASSIFIER MODEL:</label>
              <select
                value={settingsState.detection_engine.active_model_id}
                onChange={e => setSettingsState({
                  ...settingsState,
                  detection_engine: { ...settingsState.detection_engine, active_model_id: parseInt(e.target.value) || 1 }
                })}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              >
                {models.length > 0 ? (
                  models.map(m => (
                    <option key={m.id} value={m.id}>
                      {m.name} ({m.algorithm}) - Acc: {((m.accuracy || 0) * 100).toFixed(1)}%
                    </option>
                  ))
                ) : (
                  <option value={1}>Tuned 8-Class XGBoost Model (Default)</option>
                )}
              </select>
            </div>

            <div>
              <div className="flex justify-between text-[10px] text-slate-500 mb-1">
                <span>CONFIDENCE THRESHOLD:</span>
                <span className="text-cyan-400 font-bold">{Math.round(settingsState.detection_engine.confidence_threshold * 100)}%</span>
              </div>
              <input
                type="range"
                min={0.50}
                max={0.99}
                step={0.01}
                value={settingsState.detection_engine.confidence_threshold}
                onChange={e => setSettingsState({
                  ...settingsState,
                  detection_engine: { ...settingsState.detection_engine, confidence_threshold: parseFloat(e.target.value) }
                })}
                className="w-full accent-cyan-500 bg-slate-900 border border-slate-800 rounded h-1 cursor-pointer mt-2"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-500 block mb-1">SHAP TOP-K FEATURE ATTRIBUTIONS:</label>
              <select
                value={settingsState.detection_engine.shap_top_k}
                onChange={e => setSettingsState({
                  ...settingsState,
                  detection_engine: { ...settingsState.detection_engine, shap_top_k: parseInt(e.target.value) || 5 }
                })}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              >
                <option value={3}>Top 3 Contributing Features</option>
                <option value={5}>Top 5 Contributing Features (Standard)</option>
                <option value={10}>Top 10 Contributing Features</option>
              </select>
            </div>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════
            4. MULTI-AGENT PIPELINE
        ═══════════════════════════════════════════════════ */}
        <div className="dark-panel p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Layers size={16} className="text-cyan-400" />
              <h3 className="text-xs font-semibold text-white font-mono uppercase tracking-wider">
                4. Multi-Agent Pipeline & Containment Playbook
              </h3>
            </div>
            <span className="px-2.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase bg-emerald-950/80 text-emerald-400 border border-emerald-700/60">
              6 Agents Active
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label className="text-[10px] text-slate-500 block mb-1">PIPELINE EXECUTION MODE:</label>
              <div className="grid grid-cols-2 gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setSettingsState({
                    ...settingsState,
                    multi_agent_pipeline: { ...settingsState.multi_agent_pipeline, execution_mode: 'coordinated' }
                  })}
                  className={`px-3 py-2 rounded text-xs font-bold transition-all border ${
                    settingsState.multi_agent_pipeline.execution_mode === 'coordinated'
                      ? 'bg-cyan-950 border-cyan-500 text-cyan-200'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  ⚡ Coordinated (Parallel)
                </button>
                <button
                  type="button"
                  onClick={() => setSettingsState({
                    ...settingsState,
                    multi_agent_pipeline: { ...settingsState.multi_agent_pipeline, execution_mode: 'sequential' }
                  })}
                  className={`px-3 py-2 rounded text-xs font-bold transition-all border ${
                    settingsState.multi_agent_pipeline.execution_mode === 'sequential'
                      ? 'bg-cyan-950 border-cyan-500 text-cyan-200'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  🔗 Sequential Pipeline
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between p-3 rounded bg-amber-950/20 border border-amber-900/40">
              <div>
                <span className="text-amber-300 font-bold flex items-center gap-1.5">
                  <Lock size={13} className="text-amber-400" />
                  Analyst Approval Required
                </span>
                <span className="text-[10px] text-slate-400">Firewall enforcement commands require explicit analyst click approval</span>
              </div>
              <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                ENFORCED
              </span>
            </div>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════
            5. THREAT INTELLIGENCE
        ═══════════════════════════════════════════════════ */}
        <div className="dark-panel p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert size={16} className="text-indigo-400" />
              <h3 className="text-xs font-semibold text-white font-mono uppercase tracking-wider">
                5. Threat Intelligence Knowledge Base (RAG)
              </h3>
            </div>
            <span className={`px-2.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase border ${getStatusBadge(healthMap.rag?.status)}`}>
              RAG Engine: {healthMap.rag?.status || 'Ready'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="space-y-2">
              <span className="text-[10px] text-slate-500 uppercase block">KNOWLEDGE SOURCES:</span>
              <div className="flex items-center justify-between p-2.5 rounded bg-slate-900/60 border border-slate-800">
                <span>MITRE ATT&CK Matrix</span>
                <input
                  type="checkbox"
                  checked={settingsState.threat_intelligence.enable_mitre}
                  onChange={e => setSettingsState({
                    ...settingsState,
                    threat_intelligence: { ...settingsState.threat_intelligence, enable_mitre: e.target.checked }
                  })}
                  className="w-4 h-4 accent-cyan-500 cursor-pointer"
                />
              </div>
              <div className="flex items-center justify-between p-2.5 rounded bg-slate-900/60 border border-slate-800">
                <span>NVD Vulnerability Database (CVE)</span>
                <input
                  type="checkbox"
                  checked={settingsState.threat_intelligence.enable_nvd_cve}
                  onChange={e => setSettingsState({
                    ...settingsState,
                    threat_intelligence: { ...settingsState.threat_intelligence, enable_nvd_cve: e.target.checked }
                  })}
                  className="w-4 h-4 accent-cyan-500 cursor-pointer"
                />
              </div>
              <div className="flex items-center justify-between p-2.5 rounded bg-slate-900/60 border border-slate-800">
                <span>CISA Known Exploited Vulnerabilities</span>
                <input
                  type="checkbox"
                  checked={settingsState.threat_intelligence.enable_cisa}
                  onChange={e => setSettingsState({
                    ...settingsState,
                    threat_intelligence: { ...settingsState.threat_intelligence, enable_cisa: e.target.checked }
                  })}
                  className="w-4 h-4 accent-cyan-500 cursor-pointer"
                />
              </div>
            </div>

            <div>
              <label className="text-[10px] text-slate-500 block mb-1">RAG TOP-K RETRIEVAL CITATIONS:</label>
              <select
                value={settingsState.threat_intelligence.rag_top_k}
                onChange={e => setSettingsState({
                  ...settingsState,
                  threat_intelligence: { ...settingsState.threat_intelligence, rag_top_k: parseInt(e.target.value) || 3 }
                })}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              >
                <option value={1}>1 Citation (Fastest)</option>
                <option value={3}>3 Citations (Balanced)</option>
                <option value={5}>5 Citations (Deep Analysis)</option>
              </select>
            </div>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════
            6. DATA & STORAGE
        ═══════════════════════════════════════════════════ */}
        <div className="dark-panel p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Folder size={16} className="text-amber-400" />
              <h3 className="text-xs font-semibold text-white font-mono uppercase tracking-wider">
                6. Data Storage & Log Retention
              </h3>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label className="text-[10px] text-slate-500 block mb-1">INCIDENT REPORTS DIRECTORY:</label>
              <input
                type="text"
                value={settingsState.data_storage.report_path}
                onChange={e => setSettingsState({
                  ...settingsState,
                  data_storage: { ...settingsState.data_storage, report_path: e.target.value }
                })}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-500 block mb-1">LOG RETENTION PERIOD (DAYS):</label>
              <input
                type="number"
                min={1}
                max={365}
                value={settingsState.data_storage.retention_days}
                onChange={e => setSettingsState({
                  ...settingsState,
                  data_storage: { ...settingsState.data_storage, retention_days: parseInt(e.target.value) || 30 }
                })}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════
            7. SYSTEM HEALTH MATRIX
        ═══════════════════════════════════════════════════ */}
        <div className="dark-panel p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Activity size={16} className="text-emerald-400" />
              <h3 className="text-xs font-semibold text-white font-mono uppercase tracking-wider">
                7. Live System & Agent Health Matrix
              </h3>
            </div>

            <button
              onClick={fetchSettingsAndData}
              className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-400 transition-colors"
              title="Refresh status health checks"
            >
              <RefreshCw size={13} />
            </button>
          </div>

          {/* Infrastructure Health */}
          <div className="space-y-2">
            <span className="text-[10px] font-mono text-slate-500 uppercase block">Infrastructure Core Services:</span>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
              {Object.entries(healthMap).map(([key, item]) => (
                <div key={key} className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
                  <div className="flex justify-between items-center">
                    <span className="text-white font-bold">{item.name}</span>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase border ${getStatusBadge(item.status)}`}>
                      {item.status}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-400 truncate">{item.details}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Multi-Agent Health */}
          <div className="space-y-2 pt-2">
            <span className="text-[10px] font-mono text-slate-500 uppercase block">Multi-Agent SOC Pipeline:</span>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
              {Object.entries(agentsHealthMap).map(([key, agent]) => (
                <div key={key} className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
                  <div className="flex justify-between items-center">
                    <span className="text-cyan-300 font-bold">{agent.name}</span>
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase bg-emerald-950/80 text-emerald-400 border border-emerald-700/60">
                      {agent.status}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-400 truncate">{agent.details}</p>
                </div>
              ))}
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
                    <p className="text-[11px] text-rose-400/70 mt-0.5">Your session will be terminated.</p>
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

    </div>
  );
};
