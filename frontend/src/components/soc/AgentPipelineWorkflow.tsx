import React from 'react';
import { 
  ShieldCheck, 
  Cpu, 
  Binary, 
  Scale, 
  Zap, 
  FileText, 
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Sparkles
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
  const getAgentStatus = (agentKey: string): { status: string; color: string; badge: string } => {
    if (!incident) return { status: 'IDLE', color: 'border-slate-800 text-slate-500', badge: 'STANDBY' };
    
    const rawStatus = incident.agent_status?.[agentKey];
    if (rawStatus === 'DEGRADED') {
      return { status: 'DEGRADED', color: 'border-amber-600/70 bg-amber-950/20 text-amber-300', badge: 'DEGRADED' };
    }
    if (rawStatus === 'FAILED') {
      return { status: 'FAILED', color: 'border-rose-600/70 bg-rose-950/20 text-rose-400', badge: 'FAILED' };
    }
    if (rawStatus === 'SKIPPED') {
      return { status: 'SKIPPED', color: 'border-slate-700 bg-slate-900/40 text-slate-500', badge: 'SKIPPED' };
    }
    return { status: 'COMPLETED', color: 'border-emerald-600/60 bg-emerald-950/10 text-emerald-400', badge: 'COMPLETED' };
  };

  const getAgentError = (agentName: string): string | null => {
    if (!incident?.errors) return null;
    const err = incident.errors.find(e => e.agent.toLowerCase().includes(agentName.toLowerCase()));
    return err ? err.error : null;
  };

  const steps = [
    {
      id: 'detection',
      key: 'detection',
      name: 'Detection Agent',
      subtitle: 'XGBoost & SHAP Attribution',
      icon: Cpu,
      iconColor: 'text-cyan-400',
      summary: incident?.detection ? `${incident.detection.attack_type} (${(incident.detection.confidence * 100).toFixed(1)}%)` : 'Ready',
      generatedBy: incident?.detection?.generated_by,
      model: incident?.detection?.llm_model,
      latency: incident?.detection?.latency_ms
    },
    {
      id: 'coordinator',
      key: 'coordinator',
      name: 'Coordinator Agent',
      subtitle: 'Correlation & Incident State',
      icon: Binary,
      iconColor: 'text-blue-400',
      summary: incident ? incident.incident_id : 'Idle',
      generatedBy: 'rule_based',
      model: null,
      latency: null
    },
    {
      id: 'threat_intel',
      key: 'threat_intel',
      name: 'Threat Intel Agent',
      subtitle: 'Hybrid RAG: MITRE / CVE / CISA',
      icon: ShieldCheck,
      iconColor: 'text-indigo-400',
      summary: incident?.threat_intel ? `${incident.threat_intel.mitre_attack.length} MITRE | ${incident.threat_intel.cve_list.length} CVE` : 'No Match',
      generatedBy: incident?.threat_intel?.generated_by,
      model: incident?.threat_intel?.llm_model,
      latency: incident?.threat_intel?.latency_ms
    },
    {
      id: 'risk',
      key: 'risk_assessment',
      name: 'Risk Assessment Agent',
      subtitle: 'Calibrated Multi-Factor Score',
      icon: Scale,
      iconColor: 'text-amber-400',
      summary: incident?.risk_assessment ? `Score ${incident.risk_assessment.risk_score} (${incident.risk_assessment.severity})` : 'Pending',
      generatedBy: incident?.risk_assessment?.generated_by,
      model: incident?.risk_assessment?.llm_model,
      latency: incident?.risk_assessment?.latency_ms
    },
    {
      id: 'response',
      key: 'response',
      name: 'Response Agent',
      subtitle: 'Playbooks & Safe ACL Rules',
      icon: Zap,
      iconColor: 'text-rose-400',
      summary: incident?.response ? `${incident.response.firewall_commands.length} Rules | ${incident.response.approval_status}` : 'Pending',
      generatedBy: incident?.response?.generated_by,
      model: incident?.response?.llm_model,
      latency: incident?.response?.latency_ms
    },
    {
      id: 'report',
      key: 'incident_report',
      name: 'Incident Report Agent',
      subtitle: 'Structured Report & Timeline',
      icon: FileText,
      iconColor: 'text-emerald-400',
      summary: incident?.report ? `${incident.report.markdown_content.length} bytes` : 'Pending',
      generatedBy: incident?.report?.generated_by,
      model: incident?.report?.llm_model,
      latency: incident?.report?.latency_ms
    }
  ];

  const overall = incident?.overall_status || (incident ? 'COMPLETE' : 'STANDBY');

  return (
    <div className="dark-panel p-5 border border-slate-800 bg-slate-950/60 shadow-lg">
      <div className="flex items-center justify-between mb-4 pb-2.5 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Binary className="text-cyan-400" size={16} />
          <h4 className="font-mono text-xs uppercase tracking-wider text-slate-300 font-bold">
            Fault-Tolerant Multi-Agent SOC Pipeline (RAG + LLM)
          </h4>
        </div>
        <div className="flex items-center gap-2 text-[11px] font-mono">
          <span className="text-slate-500">Pipeline State:</span>
          {isProcessing ? (
            <span className="flex items-center gap-1 text-cyan-400 animate-pulse">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              <span>ORCHESTRATING AGENTS...</span>
            </span>
          ) : overall === 'COMPLETE' ? (
            <span className="text-emerald-400 font-semibold flex items-center gap-1">
              <CheckCircle2 size={13} />
              <span>CYCLE COMPLETE</span>
            </span>
          ) : overall === 'PARTIAL' ? (
            <span className="text-amber-400 font-semibold flex items-center gap-1">
              <AlertTriangle size={13} />
              <span>PARTIAL / DEGRADED RUN</span>
            </span>
          ) : overall === 'FAILED' ? (
            <span className="text-rose-400 font-semibold flex items-center gap-1">
              <XCircle size={13} />
              <span>PIPELINE FAILED</span>
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
          const statusInfo = getAgentStatus(step.key);
          const errorMsg = getAgentError(step.name);
          const isLlm = step.generatedBy === 'llm';
          const isFallback = step.generatedBy === 'rule_based_fallback';

          return (
            <div
              key={step.id}
              className={`p-3 rounded-lg border transition-all relative flex flex-col justify-between ${
                incident ? statusInfo.color : 'border-slate-800/60 bg-slate-900/30 text-slate-500'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className={`p-1.5 rounded-md bg-slate-800/80 border border-slate-700/60 ${step.iconColor}`}>
                    <Icon size={14} />
                  </div>
                  <div className="flex items-center gap-1">
                    {incident && (
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold uppercase ${
                        statusInfo.status === 'COMPLETED' ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/50' :
                        statusInfo.status === 'DEGRADED' ? 'bg-amber-950/80 text-amber-300 border border-amber-800/50' :
                        statusInfo.status === 'FAILED' ? 'bg-rose-950/80 text-rose-300 border border-rose-800/50' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {statusInfo.badge}
                      </span>
                    )}
                    <span className="text-[10px] font-mono text-slate-500 font-bold">
                      0{idx + 1}
                    </span>
                  </div>
                </div>

                <h5 className="font-mono text-xs font-semibold text-slate-200 truncate">
                  {step.name}
                </h5>
                <p className="text-[10px] text-slate-500 font-mono truncate mb-2">
                  {step.subtitle}
                </p>

                {/* LLM vs Fallback Tags */}
                {incident && (
                  <div className="mb-2 flex flex-wrap gap-1">
                    {isLlm && (
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/50 flex items-center gap-0.5">
                        <Sparkles size={8} />
                        <span>LLM{step.latency ? ` (${step.latency}ms)` : ''}</span>
                      </span>
                    )}
                    {isFallback && (
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-amber-950/60 text-amber-300 border border-amber-800/40">
                        Rule Fallback
                      </span>
                    )}
                  </div>
                )}

                {/* Error reason if present */}
                {errorMsg && (
                  <p className="text-[9px] font-mono text-rose-400 truncate mb-1" title={errorMsg}>
                    {errorMsg}
                  </p>
                )}
              </div>

              <div className="pt-1.5 border-t border-slate-800/80 text-[11px] font-mono flex items-center justify-between mt-1">
                <span className="text-slate-400 truncate max-w-[110px]">{step.summary}</span>
                {statusInfo.status === 'COMPLETED' && <CheckCircle2 size={12} className="text-emerald-400 shrink-0" />}
                {statusInfo.status === 'DEGRADED' && <AlertTriangle size={12} className="text-amber-400 shrink-0" />}
                {statusInfo.status === 'FAILED' && <XCircle size={12} className="text-rose-400 shrink-0" />}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
