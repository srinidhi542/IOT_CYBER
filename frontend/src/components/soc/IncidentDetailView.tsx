import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Cpu, 
  ExternalLink, 
  Copy, 
  Check, 
  Scale, 
  Zap, 
  FileText, 
  Clock, 
  ShieldCheck, 
  AlertTriangle,
  Flame,
  CheckCircle2,
  XCircle,
  Download,
  Code
} from 'lucide-react';
import { IncidentState } from '../../types';
import { apiService } from '../../services/api';

interface IncidentDetailViewProps {
  incident: IncidentState;
  onIncidentUpdated: (updated: IncidentState) => void;
}

export const IncidentDetailView: React.FC<IncidentDetailViewProps> = ({
  incident,
  onIncidentUpdated
}) => {
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [copiedMarkdown, setCopiedMarkdown] = useState<boolean>(false);
  const [analystNotes, setAnalystNotes] = useState<string>('');
  const [reviewing, setReviewing] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'playbook' | 'timeline' | 'markdown'>('overview');

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2500);
  };

  const copyReportMarkdown = () => {
    if (!incident.report?.markdown_content) return;
    navigator.clipboard.writeText(incident.report.markdown_content);
    setCopiedMarkdown(true);
    setTimeout(() => setCopiedMarkdown(false), 2500);
  };

  const downloadReport = () => {
    if (!incident.report?.markdown_content) return;
    const blob = new Blob([incident.report.markdown_content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident_report_${incident.incident_id}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleApprovalAction = async (approved: boolean) => {
    try {
      setReviewing(true);
      const updated = await apiService.reviewIncidentResponse(
        incident.incident_id,
        approved,
        "SOC Lead Analyst",
        analystNotes || (approved ? "Approved containment and firewall block rules." : "Rejected proposed mitigation.")
      );
      onIncidentUpdated(updated);
    } catch (e: any) {
      alert(`Approval update failed: ${e.message}`);
    } finally {
      setReviewing(false);
    }
  };

  const severityColor = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'text-rose-400 bg-rose-950/60 border-rose-700/60';
      case 'high': return 'text-orange-400 bg-orange-950/60 border-orange-700/60';
      case 'medium': return 'text-amber-400 bg-amber-950/60 border-amber-700/60';
      default: return 'text-emerald-400 bg-emerald-950/60 border-emerald-700/60';
    }
  };

  const net = incident.detection?.network_context || { source_ip: 'Unknown', destination_ip: 'Unknown', source_port: 0, destination_port: 0, protocol: 'TCP' };
  const isApproved = incident.response?.approval_status === 'APPROVED';
  const isRejected = incident.response?.approval_status === 'REJECTED';

  return (
    <div className="space-y-6">
      {/* Top Banner Card */}
      <div className="dark-panel p-6 border border-slate-800 bg-slate-950/80 shadow-2xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-700 text-rose-400">
              <ShieldAlert size={24} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-mono text-base font-bold text-white tracking-wide">
                  {incident.incident_id}
                </h3>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase tracking-wider border ${severityColor(incident.risk_assessment?.severity || 'Low')}`}>
                  {incident.risk_assessment?.severity || 'Low'} Severity
                </span>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-slate-900 border border-slate-700 text-slate-300">
                  {incident.risk_assessment?.priority || 'P3'}
                </span>
              </div>
              <p className="text-xs font-mono text-slate-400 mt-1">
                Detected at {incident.created_at} UTC | Engine: Tuned XGBoost + SHAP TreeExplainer
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex bg-slate-900/90 p-1 rounded-lg border border-slate-800 font-mono text-xs">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-3 py-1.5 rounded-md transition-colors ${activeTab === 'overview' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'text-slate-400 hover:text-white'}`}
            >
              Incident Overview
            </button>
            <button
              onClick={() => setActiveTab('playbook')}
              className={`px-3 py-1.5 rounded-md transition-colors ${activeTab === 'playbook' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'text-slate-400 hover:text-white'}`}
            >
              Response & ACL
            </button>
            <button
              onClick={() => setActiveTab('timeline')}
              className={`px-3 py-1.5 rounded-md transition-colors ${activeTab === 'timeline' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'text-slate-400 hover:text-white'}`}
            >
              Audit Timeline
            </button>
            <button
              onClick={() => setActiveTab('markdown')}
              className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${activeTab === 'markdown' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'text-slate-400 hover:text-white'}`}
            >
              <FileText size={12} />
              <span>Downloadable Report</span>
            </button>
            {incident.report && (
              <button
                onClick={downloadReport}
                className="px-3 py-1.5 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold transition-all flex items-center gap-1.5 ml-1 shadow-md shadow-cyan-950/30"
                title="Download Markdown Incident Report"
              >
                <Download size={13} />
                <span>Download .md</span>
              </button>
            )}
          </div>
        </div>

        {/* 5-Tuple Network Context Bar */}
        <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs font-mono">
          <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-500 block">ATTACK CLASSIFICATION</span>
            <span className="text-cyan-400 font-bold">{incident.detection.attack_type}</span>
          </div>
          <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-500 block">MODEL CONFIDENCE</span>
            <span className="text-emerald-400 font-bold">{(incident.detection.confidence * 100).toFixed(2)}%</span>
          </div>
          <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-500 block">SOURCE ENDPOINT</span>
            <span className="text-slate-200">{net.source_ip}:{net.source_port}</span>
          </div>
          <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-500 block">TARGET ENDPOINT</span>
            <span className="text-slate-200">{net.destination_ip}:{net.destination_port}</span>
          </div>
          <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-500 block">PROTOCOL</span>
            <span className="text-purple-400 font-bold">{net.protocol || "TCP"}</span>
          </div>
          <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-500 block">RISK SCORE</span>
            <span className="text-rose-400 font-bold">{incident.risk_assessment?.risk_score || 0}/100</span>
          </div>
        </div>
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Verified Threat Intelligence (RAG) */}
          <div className="dark-panel p-6 border border-slate-800 bg-slate-950/70">
            <div className="flex items-center gap-2 mb-4 pb-2 border-b border-slate-800">
              <ShieldCheck className="text-indigo-400" size={18} />
              <h4 className="font-mono text-xs uppercase tracking-wider text-slate-200 font-bold">
                Threat Intelligence Agent (RAG)
              </h4>
              <span className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-700/50">
                Verified Zero-Hallucination
              </span>
            </div>

            {/* MITRE ATT&CK */}
            <div className="space-y-3 mb-5">
              <h5 className="font-mono text-[11px] text-slate-400 uppercase tracking-wider font-semibold">
                Correlated MITRE ATT&CK Techniques:
              </h5>
              {incident.threat_intel?.mitre_attack && incident.threat_intel.mitre_attack.length > 0 ? (
                incident.threat_intel.mitre_attack.map(m => (
                  <div key={m.id} className="p-3 rounded-lg bg-slate-900/80 border border-indigo-950/60 font-mono text-xs">
                    <div className="flex justify-between items-center mb-1">
                      <a 
                        href={m.url} 
                        target="_blank" 
                        rel="noreferrer" 
                        className="text-indigo-300 font-bold flex items-center gap-1.5 hover:underline"
                      >
                        <span>{m.id}: {m.name}</span>
                        <ExternalLink size={12} />
                      </a>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                        {m.tactic}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                      {m.description}
                    </p>
                  </div>
                ))
              ) : (
                <p className="text-xs font-mono text-slate-500">No active MITRE exploitation techniques match benign traffic.</p>
              )}
            </div>

            {/* NVD CVE Records */}
            <div className="space-y-3">
              <h5 className="font-mono text-[11px] text-slate-400 uppercase tracking-wider font-semibold">
                Associated NVD / CVE Records:
              </h5>
              {incident.threat_intel?.cve_list && incident.threat_intel.cve_list.length > 0 ? (
                incident.threat_intel.cve_list.map(c => (
                  <div key={c.cve_id} className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 font-mono text-xs">
                    <div className="flex justify-between items-center mb-1">
                      <a 
                        href={c.url} 
                        target="_blank" 
                        rel="noreferrer" 
                        className="text-cyan-400 font-bold flex items-center gap-1.5 hover:underline"
                      >
                        <span>{c.cve_id}</span>
                        <ExternalLink size={12} />
                      </a>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/40 font-bold">
                        CVSS {c.cvss_score} ({c.severity})
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                      {c.description}
                    </p>
                  </div>
                ))
              ) : (
                <p className="text-xs font-mono text-slate-500">No matching high-risk CVE vulnerabilities found.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: RESPONSE PLAYBOOK & FIREWALL RULES */}
      {activeTab === 'playbook' && (
        <div className="space-y-6">
          {/* Mandatory Analyst Approval Banner */}
          <div className="p-5 rounded-xl border border-amber-500/50 bg-amber-950/20 backdrop-blur-md">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-start gap-3">
                <AlertTriangle size={22} className="text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-mono text-xs font-bold uppercase tracking-wider text-amber-300">
                    MANDATORY ANALYST APPROVAL REQUIRED
                  </h4>
                  <p className="text-xs text-slate-400 mt-1">
                    In compliance with SOC safety policy, automated execution of firewall rules and isolation commands is strictly disabled.
                    Review the playbooks below and record your authorization decision.
                  </p>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-3 shrink-0">
                {isApproved ? (
                  <span className="px-3 py-1.5 rounded-lg bg-emerald-950/80 border border-emerald-600 text-emerald-300 font-mono text-xs font-bold flex items-center gap-1.5">
                    <CheckCircle2 size={14} />
                    <span>APPROVED BY ANALYST</span>
                  </span>
                ) : isRejected ? (
                  <span className="px-3 py-1.5 rounded-lg bg-rose-950/80 border border-rose-600 text-rose-300 font-mono text-xs font-bold flex items-center gap-1.5">
                    <XCircle size={14} />
                    <span>REJECTED BY ANALYST</span>
                  </span>
                ) : (
                  <>
                    <button
                      onClick={() => handleApprovalAction(true)}
                      disabled={reviewing}
                      className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold uppercase tracking-wider transition-colors flex items-center gap-1.5 shadow-lg shadow-emerald-950/50 disabled:opacity-50"
                    >
                      <CheckCircle2 size={14} />
                      <span>APPROVE PLAYBOOK</span>
                    </button>
                    <button
                      onClick={() => handleApprovalAction(false)}
                      disabled={reviewing}
                      className="px-4 py-2 rounded-lg bg-rose-900/50 hover:bg-rose-800/80 text-rose-300 border border-rose-700/60 font-mono text-xs font-bold uppercase tracking-wider transition-colors flex items-center gap-1.5 disabled:opacity-50"
                    >
                      <XCircle size={14} />
                      <span>REJECT</span>
                    </button>
                  </>
                )}
              </div>
            </div>

            {/* Optional analyst notes input */}
            {!isApproved && !isRejected && (
              <div className="mt-4 pt-3 border-t border-amber-500/20 flex gap-2">
                <input
                  type="text"
                  placeholder="Optional analyst review notes or ticket reference..."
                  value={analystNotes}
                  onChange={e => setAnalystNotes(e.target.value)}
                  className="flex-1 bg-slate-900/90 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-300 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            )}
          </div>

          {/* Copyable Firewall & ACL Rules */}
          <div className="dark-panel p-6 border border-slate-800 bg-slate-950/70">
            <div className="flex items-center gap-2 mb-4 pb-2 border-b border-slate-800">
              <Code className="text-cyan-400" size={18} />
              <h4 className="font-mono text-xs uppercase tracking-wider text-slate-200 font-bold">
                Copyable Firewall & ACL Commands (Tailored to Flow Context)
              </h4>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {(incident.response?.firewall_commands || []).map((cmd, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 font-mono flex flex-col justify-between">
                  <div>
                    <div className="flex justify-between items-center mb-2 pb-1.5 border-b border-slate-800">
                      <span className="text-[11px] font-bold text-cyan-400 uppercase">{cmd.firewall_type}</span>
                      <button
                        onClick={() => copyToClipboard(cmd.command, `${idx}`)}
                        className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px] transition-colors"
                      >
                        {copiedCmd === `${idx}` ? (
                          <>
                            <Check size={12} className="text-emerald-400" />
                            <span className="text-emerald-400 font-bold">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy size={12} />
                            <span>Copy</span>
                          </>
                        )}
                      </button>
                    </div>
                    <p className="text-[11px] text-slate-400 mb-3">{cmd.description}</p>
                  </div>
                  <pre className="p-2.5 rounded bg-black/60 border border-slate-800/80 text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap select-all font-mono">
                    {cmd.command}
                  </pre>
                </div>
              ))}
            </div>
          </div>

          {/* Structured Playbooks (Containment, Recovery, Prevention) */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="dark-panel p-5 border border-slate-800 bg-slate-950/70">
              <h5 className="font-mono text-xs uppercase tracking-wider text-rose-400 font-bold mb-3 pb-1 border-b border-rose-900/40">
                1. Immediate Containment
              </h5>
              <ul className="space-y-2 text-xs font-mono text-slate-300">
                {(incident.response?.containment || []).map((c, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-rose-400 font-bold">▶</span>
                    <span>{c}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="dark-panel p-5 border border-slate-800 bg-slate-950/70">
              <h5 className="font-mono text-xs uppercase tracking-wider text-amber-400 font-bold mb-3 pb-1 border-b border-amber-900/40">
                2. System Recovery
              </h5>
              <ul className="space-y-2 text-xs font-mono text-slate-300">
                {(incident.response?.recovery || []).map((r, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-amber-400 font-bold">▶</span>
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="dark-panel p-5 border border-slate-800 bg-slate-950/70">
              <h5 className="font-mono text-xs uppercase tracking-wider text-cyan-400 font-bold mb-3 pb-1 border-b border-cyan-900/40">
                3. Prevention & Hardening
              </h5>
              <ul className="space-y-2 text-xs font-mono text-slate-300">
                {(incident.response?.prevention || []).map((p, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-cyan-400 font-bold">▶</span>
                    <span>{p}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: TIMELINE */}
      {activeTab === 'timeline' && (
        <div className="dark-panel p-6 border border-slate-800 bg-slate-950/70">
          <div className="flex items-center gap-2 mb-4 pb-2 border-b border-slate-800">
            <Clock className="text-cyan-400" size={18} />
            <h4 className="font-mono text-xs uppercase tracking-wider text-slate-200 font-bold">
              Multi-Agent SOC Chronological Audit Timeline
            </h4>
          </div>

          <div className="relative pl-6 border-l-2 border-cyan-800/40 space-y-6">
            {(incident.timeline || []).map((ev, idx) => (
              <div key={idx} className="relative group">
                <div className="absolute -left-[31px] top-0 w-3.5 h-3.5 rounded-full bg-slate-900 border-2 border-cyan-500 group-hover:bg-cyan-400 transition-colors" />
                <div className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 font-mono text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-cyan-400">{ev.agent}</span>
                    <span className="text-slate-500 text-[11px]">{ev.timestamp}</span>
                  </div>
                  <div className="text-slate-200 font-semibold mb-1">{ev.action}</div>
                  <p className="text-slate-400 text-[11px]">{ev.details}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 4: MARKDOWN REPORT */}
      {activeTab === 'markdown' && (
        <div className="dark-panel p-6 border border-slate-800 bg-slate-950/70">
          <div className="flex items-center justify-between mb-4 pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <FileText className="text-cyan-400" size={18} />
              <h4 className="font-mono text-xs uppercase tracking-wider text-slate-200 font-bold">
                Complete Structured SOC Incident Report (Markdown)
              </h4>
            </div>
            <div className="flex gap-2">
              <button
                onClick={copyReportMarkdown}
                className="px-3 py-1.5 rounded bg-slate-900 border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white text-xs font-mono flex items-center gap-1.5 transition-colors"
              >
                {copiedMarkdown ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                <span>{copiedMarkdown ? "Copied" : "Copy Markdown"}</span>
              </button>
              <button
                onClick={downloadReport}
                className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono flex items-center gap-1.5 transition-colors shadow"
              >
                <Download size={13} />
                <span>Download Report</span>
              </button>
            </div>
          </div>

          <pre className="p-4 rounded-lg bg-black/70 border border-slate-800/80 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-[500px]">
            {incident.report?.markdown_content || "Report compiling..."}
          </pre>
        </div>
      )}
    </div>
  );
};
