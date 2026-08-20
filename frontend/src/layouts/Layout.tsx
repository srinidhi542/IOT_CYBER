import React from 'react';
import { 
  LayoutDashboard, 
  Database, 
  ShieldAlert, 
  Activity, 
  FileSpreadsheet, 
  Settings as SettingsIcon,
  Cpu, 
  CheckCircle, 
  AlertTriangle,
  Terminal,
  CircleDot,
  Microscope
} from 'lucide-react';
import { SystemStatus, Dataset, MLModel } from '../types';
import { apiService } from '../services/api';

interface LayoutProps {
  activePage: string;
  setActivePage: (page: string) => void;
  systemStatus: SystemStatus | null;
  selectedDataset: Dataset | null;
  selectedModel: MLModel | null;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({
  activePage,
  setActivePage,
  systemStatus,
  selectedDataset,
  selectedModel,
  children
}) => {
  
  const getPageInfo = () => {
    switch (activePage) {
      case 'dashboard':
        return { title: 'Security Dashboard', desc: 'Real-time telemetry and overview of IoT network threats.' };
      case 'dataset':
        return { title: 'Dataset Analysis & Preprocessing', desc: 'Upload, inspect, validate and clean network traffic files.' };
      case 'anomaly':
        return { title: 'Anomaly Analysis', desc: 'Inspect Isolation Forest unsupervised anomalies, scores, and feature deviations.' };
      case 'explain':
        return { title: 'Threat Explainability', desc: 'Per-record feature contribution analysis and AI reasoning for flagged threats.' };
      case 'detection':
        return { title: 'Threat Detection Engine', desc: 'Execute intrusion analysis and evaluate live classification pipelines.' };
      case 'performance':
        return { title: 'Model Performance & Analytics', desc: 'Detailed diagnostic reports, heatmaps, and global feature importance.' };
      case 'reports':
        return { title: 'Security Reports', desc: 'Generate, download, and review incident and mitigation reports.' };
      case 'settings':
        return { title: 'Platform Settings', desc: 'Configuration overlays, system settings, and pipeline parameters.' };
      default:
        return { title: 'IOTShield', desc: 'Intelligent IoT Threat Detection Platform' };
    }
  };

  const pageInfo = getPageInfo();

  // Navigation Items
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'dataset', label: 'Dataset Analysis', icon: Database },
    { id: 'anomaly', label: 'Anomaly Analysis', icon: CircleDot },
    { id: 'explain', label: 'Explainability', icon: Microscope },
    { id: 'detection', label: 'Threat Detection', icon: ShieldAlert },
    { id: 'performance', label: 'Model Performance', icon: Activity },
    { id: 'reports', label: 'Security Reports', icon: FileSpreadsheet },
    { id: 'settings', label: 'Settings', icon: SettingsIcon },
  ];

  return (
    <div className="flex h-screen overflow-hidden text-slate-100 bg-[#030712]">
      {/* SIDEBAR */}
      <aside className="flex flex-col w-64 border-r border-slate-800 bg-[#0b0f19] shrink-0">
        {/* Brand */}
        <div className="flex items-center gap-3 px-6 py-5 border-b border-slate-800">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-600/20 text-cyan-400">
            <Cpu size={20} className="animate-pulse-subtle" />
          </div>
          <div>
            <h1 className="font-semibold text-lg tracking-wider text-white">IOTShield</h1>
            <p className="text-[10px] text-slate-400 font-mono tracking-tighter">SHIELD THREAT PLATFORM</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 py-6 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activePage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActivePage(item.id)}
                className={`flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm transition-all duration-200 ${
                  isActive 
                    ? 'bg-slate-800/80 text-white font-medium shadow-inner border-l-2 border-cyan-500' 
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/30'
                }`}
              >
                <Icon size={18} className={isActive ? 'text-cyan-400' : 'text-slate-400'} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        {/* System Health Indicators (Bottom of Sidebar) */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/40 text-[11px] font-mono text-slate-400">
          <div className="flex justify-between items-center py-1">
            <span>API SERVER:</span>
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${systemStatus?.api.status === 'Operational' ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`} />
              <span>{systemStatus?.api.status || 'Checking...'}</span>
            </div>
          </div>
          <div className="flex justify-between items-center py-1">
            <span>ML ENGINE:</span>
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${systemStatus?.ml_engine.status === 'Ready' ? 'bg-emerald-500 animate-pulse' : systemStatus?.ml_engine.status === 'Operational' ? 'bg-amber-400' : 'bg-rose-500'}`} />
              <span>{systemStatus?.ml_engine.status || 'Checking...'}</span>
            </div>
          </div>
          <div className="flex justify-between items-center py-1">
            <span>DETECTION:</span>
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${systemStatus?.detection_engine.status === 'Ready' ? 'bg-emerald-500 animate-pulse' : 'bg-slate-600'}`} />
              <span>{systemStatus?.detection_engine.status || 'Checking...'}</span>
            </div>
          </div>
          <div className="mt-4 text-[10px] text-center text-slate-600">
            IOTShield v2.0.0
          </div>
        </div>
      </aside>

      {/* MAIN FRAME */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        {/* HEADER */}
        <header className="flex justify-between items-center h-16 px-8 border-b border-slate-800 bg-[#0b0f19] shrink-0">
          <div>
            <h2 className="text-base font-semibold text-white tracking-wide">{pageInfo.title}</h2>
            <p className="text-xs text-slate-400 font-light mt-0.5">{pageInfo.desc}</p>
          </div>

          {/* Quick status bar */}
          <div className="flex items-center gap-4">
            {/* Active Model */}
            <div className="flex items-center gap-2 px-3 py-1 bg-slate-900 border border-slate-800 rounded text-xs">
              <span className="text-[10px] text-slate-500 font-mono uppercase">ACTIVE MODEL:</span>
              <span className="text-slate-300 font-medium">
                {selectedModel ? `${selectedModel.algorithm}` : 'None'}
              </span>
            </div>

            {/* Active Dataset */}
            <div className="flex items-center gap-2 px-3 py-1 bg-slate-900 border border-slate-800 rounded text-xs">
              <span className="text-[10px] text-slate-500 font-mono uppercase">ACTIVE DATASET:</span>
              <span className="text-slate-300 font-medium truncate max-w-[120px]">
                {selectedDataset ? selectedDataset.name : 'None'}
              </span>
            </div>

            {/* User profile placeholder */}
            <div className="flex items-center gap-2.5 ml-2 border-l border-slate-800 pl-4">
              <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center text-slate-300 font-bold border border-slate-700 text-xs">
                SOC
              </div>
              <div className="hidden md:block">
                <p className="text-xs font-semibold text-slate-300 leading-none">Operator</p>
                <p className="text-[9px] text-slate-500 font-mono mt-0.5">ROLE: Analyst</p>
              </div>
            </div>
          </div>
        </header>

        {/* VIEWPORT */}
        <main className="flex-1 overflow-y-auto p-8 relative">
          {children}
        </main>
      </div>
    </div>
  );
};
