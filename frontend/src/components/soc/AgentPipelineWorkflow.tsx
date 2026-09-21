import React from 'react';
import { 
  ShieldCheck, 
  Cpu, 
  Binary, 
  Scale, 
  Zap, 
  FileText, 
  ChevronRight,
  CheckCircle2,
  Clock
} from 'lucide-react';
import { IncidentState } from '../../types';

interface AgentPipelineWorkflowProps {
  incident: IncidentState | null;
  isProcessing: boolean;
}

export const AgentPipelineWorkflow: React.FC<AgentPipelineWorkflowProps> = ({
  incident,
  isProcessing
}) => {
  const steps = [
    {
      id: 'detection',
      name: 'Detection Agent',
      subtitle: 'XGBoost & SHAP Attribution',
      icon: Cpu,
      color: 'text-cyan-400',
      activeColor: 'border-cyan-500 bg-cyan-950/40',
      summary: incident ? `${incident.detection.attack_type} (${(incident.detection.confidence * 100).toFixed(1)}%)` : 'Ready'
    },
    {
      id: 'coordinator',
      name: 'Coordinator Agent',
      subtitle: 'Incident State Machine',
      icon: Binary,
      color: 'text-blue-400',
      activeColor: 'border-blue-500 bg-blue-950/40',
      summary: incident ? incident.incident_id : 'Idle'
    },
    {
      id: 'threat_intel',
      name: 'Threat Intel Agent',
      subtitle: 'RAG: MITRE / NVD / CISA',
      icon: ShieldCheck,
      color: 'text-indigo-400',
      activeColor: 'border-indigo-500 bg-indigo-950/40',
      summary: incident?.threat_intel ? `${incident.threat_intel.mitre_attack.length} MITRE | ${incident.threat_intel.cve_list.length} CVE` : 'Pending'
    },
    {
      id: 'risk',
      name: 'Risk Assessment Agent',
      subtitle: 'Multi-Factor Calibrated Scoring',
      icon: Scale,
      color: 'text-amber-400',
      activeColor: 'border-amber-500 bg-amber-950/40',
      summary: incident?.risk_assessment ? `Score ${incident.risk_assessment.risk_score} (${incident.risk_assessment.severity})` : 'Pending'
    },
    {
      id: 'response',
      name: 'Response Agent',
      subtitle: 'Playbooks & ACL Rules',
      icon: Zap,
      color: 'text-rose-400',
      activeColor: 'border-rose-500 bg-rose-950/40',
      summary: incident?.response ? `${incident.response.firewall_commands.length} Rules | ${incident.response.approval_status}` : 'Pending'
    },
    {
      id: 'report',
      name: 'Incident Report Agent',
      subtitle: 'Report & Timeline Compilation',
      icon: FileText,
      color: 'text-emerald-400',
      activeColor: 'border-emerald-500 bg-emerald-950/40',
      summary: incident?.report ? 'Complete' : 'Pending'
    }
  ];

  return (
    <div className="dark-panel p-5 border border-slate-800 bg-slate-950/60 shadow-lg">
      <div className="flex items-center justify-between mb-4 pb-2.5 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Binary className="text-cyan-400" size={16} />
          <h4 className="font-mono text-xs uppercase tracking-wider text-slate-300 font-bold">
            Multi-Agent SOC Orchestration Architecture
          </h4>
        </div>
        <div className="flex items-center gap-2 text-[11px] font-mono">
          <span className="text-slate-500">Pipeline State:</span>
          {isProcessing ? (
            <span className="flex items-center gap-1 text-cyan-400 animate-pulse">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              <span>ORCHESTRATING AGENTS...</span>
            </span>
          ) : incident ? (
            <span className="text-emerald-400 font-semibold flex items-center gap-1">
              <CheckCircle2 size={13} />
              <span>CYCLE COMPLETE</span>
            </span>
          ) : (
            <span className="text-slate-500">STANDBY</span>
          )}
        </div>
      </div>

      {/* Stepper Pipeline Flow */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-3">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          const isDone = Boolean(incident);
          return (
            <div
              key={step.id}
              className={`p-3 rounded-lg border transition-all relative ${
                isDone 
                  ? 'border-slate-700/80 bg-slate-900/80 hover:border-slate-600'
                  : 'border-slate-800/60 bg-slate-900/30 text-slate-500'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <div className={`p-1.5 rounded-md bg-slate-800/80 border border-slate-700/60 ${step.color}`}>
                  <Icon size={14} />
                </div>
                <span className="text-[10px] font-mono text-slate-500 font-bold">
                  0{idx + 1}
                </span>
              </div>

              <h5 className="font-mono text-xs font-semibold text-slate-200 truncate">
                {step.name}
              </h5>
              <p className="text-[10px] text-slate-500 font-mono truncate mb-2">
                {step.subtitle}
              </p>

              <div className="pt-1.5 border-t border-slate-800/80 text-[11px] font-mono flex items-center justify-between">
                <span className="text-slate-400 truncate max-w-[110px]">{step.summary}</span>
                {isDone && <CheckCircle2 size={12} className="text-emerald-400 shrink-0" />}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
