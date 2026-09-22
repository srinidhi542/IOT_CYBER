import React, { useState } from 'react';
import { IncidentState } from '../types';
import { AgentPipelineWorkflow } from '../components/soc/AgentPipelineWorkflow';
import { IncidentDetailView } from '../components/soc/IncidentDetailView';
import { ErrorBoundary } from '../components/common/ErrorBoundary';
import { 
  ShieldAlert, 
  Shield, 
  Layers, 
  Clock, 
  AlertTriangle, 
  ArrowRight, 
  RefreshCw, 
  Download, 
  FileText, 
  Printer, 
  Copy, 
  Check, 
  Cpu, 
  CheckCircle2, 
  ExternalLink 
} from 'lucide-react';

interface IncidentsProps {
  activeIncident: IncidentState | null;
  incidentsList: IncidentState[];
  setActiveIncident: (inc: IncidentState) => void;
  setIncidentsList: React.Dispatch<React.SetStateAction<IncidentState[]>>;
  isProcessingSoc?: boolean;
  onNavigateToDashboard: () => void;
  refreshIncidents?: () => void;
}

export const Incidents: React.FC<IncidentsProps> = ({
  activeIncident,
  incidentsList,
  setActiveIncident,
  setIncidentsList,
  isProcessingSoc = false,
  onNavigateToDashboard,
  refreshIncidents
}) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [viewMode, setViewMode] = useState<'triage' | 'report'>('triage');
  const [copiedMd, setCopiedMd] = useState<boolean>(false);
  const [reportSubTab, setReportSubTab] = useState<'formatted' | 'raw'>('formatted');

  const downloadReport = () => {
    if (!activeIncident?.report?.markdown_content) return;
    const blob = new Blob([activeIncident.report.markdown_content], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident_report_${activeIncident.incident_id}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copyMarkdown = () => {
    if (!activeIncident?.report?.markdown_content) return;
    navigator.clipboard.writeText(activeIncident.report.markdown_content);
    setCopiedMd(true);
    setTimeout(() => setCopiedMd(false), 2500);
  };

  const handlePrint = () => {
    window.print();
  };

  const filteredIncidents = incidentsList.filter(inc => {
    if (filterSeverity === 'ALL') return true;
    return inc.risk_assessment?.severity.toUpperCase() === filterSeverity;
  });

  const getSeverityBadgeClass = (severity?: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-600/60 shadow-rose-950/40';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-300 border-amber-600/60 shadow-amber-950/40';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-600/60 shadow-yellow-950/40';
      default:
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-600/60 shadow-emerald-950/40';
    }
  };

  return (
    <div className="space-y-6">
      {/* ═══════════════════════════════════════════════════
          1. HEADER & INCIDENT REGISTRY SELECTOR
      ═══════════════════════════════════════════════════ */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-rose-950/50 border border-rose-800/50 text-rose-400 shadow-md">
              <ShieldAlert size={20} />
            </div>
            <div>
              <h2 className="text-base font-bold font-mono text-white tracking-wider uppercase">
                SOC Incident Management & Containment Center
              </h2>
              <p className="text-xs text-slate-400">
                Multi-agent incident triage, MITRE ATT&CK / CVE threat intelligence, risk calibration, and firewall playbook execution.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Mode Switcher */}
          {activeIncident?.report && (
            <div className="flex bg-slate-900 p-1 rounded-lg border border-slate-800 font-mono text-xs">
              <button
                onClick={() => setViewMode('triage')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-all ${
                  viewMode === 'triage'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/60 font-bold shadow'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <ShieldAlert size={13} />
                <span>Incident Triage</span>
              </button>
              <button
                onClick={() => setViewMode('report')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-all ${
                  viewMode === 'report'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/60 font-bold shadow'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <FileText size={13} />
                <span>View Full Report</span>
              </button>
            </div>
          )}

          {activeIncident?.report && (
            <button
              onClick={downloadReport}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold uppercase transition-all shadow-lg shadow-cyan-950/40"
              title="Download complete structured Markdown SOC report"
            >
              <Download size={14} />
              <span>Download Report (.md)</span>
            </button>
          )}

          {refreshIncidents && (
            <button
              onClick={refreshIncidents}
              className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-800 text-slate-400 hover:text-cyan-400 transition-colors"
              title="Refresh Incident Registry"
            >
              <RefreshCw size={14} />
            </button>
          )}

          <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-900/80 border border-slate-800 font-mono text-[10px]">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-2 py-1 rounded transition-all ${
                  filterSeverity === sev
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/60 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════
          2. INCIDENT SELECTOR CAROUSEL / PILLS
      ═══════════════════════════════════════════════════ */}
      {filteredIncidents.length > 1 && (
        <div className="flex items-center gap-2 overflow-x-auto pb-2 border-b border-slate-800/60">
          <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5 shrink-0 pr-1">
            <Layers size={14} className="text-cyan-400" />
            <span>Incidents ({filteredIncidents.length}):</span>
          </span>
          <div className="flex gap-2">
            {filteredIncidents.map((inc) => {
              const isSelected = activeIncident?.incident_id === inc.incident_id;
              const sev = inc.risk_assessment?.severity || 'Low';
              return (
                <button
                  key={inc.incident_id}
                  onClick={() => setActiveIncident(inc)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all shrink-0 flex items-center gap-2.5 border ${
                    isSelected
                      ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200 font-bold shadow-lg shadow-cyan-950/30'
                      : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-850'
                  }`}
                >
                  <span className="truncate max-w-[140px]">
                    {inc.incident_id.replace('INC-', '')}: [{inc.detection.attack_type}]
                  </span>
                  <span className={`px-1.5 py-0.5 rounded text-[9px] uppercase font-bold border ${getSeverityBadgeClass(sev)}`}>
                    {sev}
                  </span>
                  {inc.response?.approval_status === 'APPROVED' && (
                    <span className="w-2 h-2 rounded-full bg-emerald-400" title="Containment Approved" />
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════
          3. MULTI-AGENT EXECUTION PIPELINE
      ═══════════════════════════════════════════════════ */}
      <AgentPipelineWorkflow
        incident={activeIncident}
        isProcessing={isProcessingSoc}
      />

      {/* ═══════════════════════════════════════════════════
          4. MAIN VIEW: REPORT VIEW OR TRIAGE VIEW
      ═══════════════════════════════════════════════════ */}
      {activeIncident ? (
        viewMode === 'report' && activeIncident.report ? (
          /* FULL SOC REPORT VIEWER */
          <ErrorBoundary fallbackTitle="Error Displaying Incident Report">
            <div className="dark-panel p-6 border border-slate-800 bg-slate-950/90 shadow-2xl space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-800/60 text-cyan-400">
                  <FileText size={20} />
                </div>
                <div>
                  <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                    Official SOC Incident Assessment Report: {activeIncident.incident_id}
                  </h3>
                  <p className="text-xs font-mono text-slate-400 mt-0.5">
                    Generated {activeIncident.report.generated_at} | Classification: RESTRICTED / SOC-OPERATIONAL
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 flex-wrap font-mono text-xs">
                <div className="flex bg-slate-900 p-0.5 rounded border border-slate-800 text-[11px]">
                  <button
                    onClick={() => setReportSubTab('formatted')}
                    className={`px-2.5 py-1 rounded transition-colors ${reportSubTab === 'formatted' ? 'bg-cyan-950 text-cyan-300 font-bold' : 'text-slate-400 hover:text-white'}`}
                  >
                    Formatted View
                  </button>
                  <button
                    onClick={() => setReportSubTab('raw')}
                    className={`px-2.5 py-1 rounded transition-colors ${reportSubTab === 'raw' ? 'bg-cyan-950 text-cyan-300 font-bold' : 'text-slate-400 hover:text-white'}`}
                  >
                    Raw Markdown
                  </button>
                </div>

                <button
                  onClick={copyMarkdown}
                  className="px-3 py-1.5 rounded bg-slate-900 border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white flex items-center gap-1.5 transition-colors"
                  title="Copy complete markdown to clipboard"
                >
                  {copiedMd ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                  <span>{copiedMd ? "Copied" : "Copy"}</span>
                </button>

                <button
                  onClick={downloadReport}
                  className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold flex items-center gap-1.5 transition-all shadow-md shadow-cyan-950/40"
                  title="Download report file (.md)"
                >
                  <Download size={13} />
                  <span>Download .md</span>
                </button>

                <button
                  onClick={handlePrint}
                  className="px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white flex items-center gap-1.5 transition-colors"
                  title="Print or save as PDF"
                >
                  <Printer size={13} />
                  <span>Print</span>
                </button>
              </div>
            </div>

            {reportSubTab === 'formatted' ? (
              <div className="space-y-6 font-mono text-xs">
                {/* 1. Executive Summary */}
                <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
                  <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest block">
                    1. Executive Summary
                  </span>
                  <p className="text-slate-200 text-xs leading-relaxed font-light font-sans">
                    {activeIncident.report.executive_summary || "No executive summary available."}
                  </p>
                </div>

                {/* 2. Telemetry & Attack Classification */}
                <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
                  <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest block">
                    2. Threat Classification & Network Telemetry
                  </span>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-850">
                      <span className="text-[9px] text-slate-500 uppercase block">Attack Family</span>
                      <span className="text-sm font-bold text-emerald-400">{activeIncident.detection?.attack_type || 'Unknown'}</span>
                    </div>
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-850">
                      <span className="text-[9px] text-slate-500 uppercase block">Classification Certainty</span>
                      <span className="text-sm font-bold text-cyan-400">{((activeIncident.detection?.confidence ?? 0) * 100).toFixed(2)}%</span>
                    </div>
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-850">
                      <span className="text-[9px] text-slate-500 uppercase block">Endpoints (Src → Dst)</span>
                      <span className="text-xs text-slate-300 truncate block">
                        {activeIncident.detection?.network_context?.source_ip || 'N/A'}:{activeIncident.detection?.network_context?.source_port ?? 'N/A'} → {activeIncident.detection?.network_context?.destination_ip || 'N/A'}:{activeIncident.detection?.network_context?.destination_port ?? 'N/A'}
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-850">
                      <span className="text-[9px] text-slate-500 uppercase block">Transport Protocol</span>
                      <span className="text-sm font-bold text-slate-300">{activeIncident.detection?.network_context?.protocol || 'TCP'}</span>
                    </div>
                  </div>
                </div>

                {/* 3. Threat Intel Citations */}
                {activeIncident.threat_intel && (
                  <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
                    <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest block">
                      3. Verified Threat Intelligence & Knowledge Base Citations
                    </span>
                    {activeIncident.threat_intel.iot_threat_context && (
                      <p className="text-slate-300 text-xs leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-850 font-sans">
                        {activeIncident.threat_intel.iot_threat_context}
                      </p>
                    )}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {(activeIncident.threat_intel.mitre_attack || []).map((tech) => (
                        <div key={tech.id} className="p-3 rounded-lg bg-slate-950 border border-slate-850 space-y-1">
                          <div className="flex justify-between items-center">
                            <span className="font-bold text-cyan-400">{tech.id}: {tech.name}</span>
                            <span className="text-[9px] text-slate-500 uppercase">{tech.tactic}</span>
                          </div>
                          <p className="text-[11px] text-slate-400 line-clamp-2">{tech.description}</p>
                          <a href={tech.url} target="_blank" rel="noreferrer" className="text-[10px] text-cyan-500 hover:underline flex items-center gap-1 pt-1">
                            <span>MITRE ATT&CK Reference</span>
                            <ExternalLink size={10} />
                          </a>
                        </div>
                      ))}
                    </div>

                    {/* CVE items */}
                    {activeIncident.threat_intel.cve_list && activeIncident.threat_intel.cve_list.length > 0 && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                        {activeIncident.threat_intel.cve_list.map((cve) => (
                          <div key={cve.cve_id} className="p-3 rounded-lg bg-slate-950 border border-slate-850 space-y-1">
                            <div className="flex justify-between items-center">
                              <span className="font-bold text-rose-400">{cve.cve_id}</span>
                              <span className="text-[9px] px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/40 font-bold">
                                CVSS {cve.cvss_score} ({cve.severity})
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 line-clamp-2">{cve.description}</p>
                            <a href={cve.url} target="_blank" rel="noreferrer" className="text-[10px] text-cyan-500 hover:underline flex items-center gap-1 pt-1">
                              <span>NVD Reference</span>
                              <ExternalLink size={10} />
                            </a>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* 4. Response Playbook & Firewall Rules */}
                {activeIncident.response && (
                  <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest">
                        4. Containment Procedures & Firewall Enforcement
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${activeIncident.response.approval_status === 'APPROVED' ? 'bg-emerald-950 text-emerald-300 border-emerald-700/60' : 'bg-amber-950 text-amber-300 border-amber-700/60'}`}>
                        {activeIncident.response.approval_status}
                      </span>
                    </div>
                    <div className="space-y-2">
                      {(activeIncident.response.firewall_commands || []).map((cmd, i) => (
                        <div key={i} className="p-2.5 rounded bg-slate-950 border border-slate-850">
                          <span className="text-[9px] text-slate-500 uppercase block mb-1">{cmd.firewall_type} ({cmd.description})</span>
                          <code className="text-cyan-300 text-xs">{cmd.command}</code>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              /* Raw Markdown */
              <pre className="p-4 rounded-xl bg-black/80 border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-[600px]">
                {activeIncident.report.markdown_content}
              </pre>
            )}
          </div>
        </ErrorBoundary>
        ) : (
          /* TRIAGE VIEW */
          <ErrorBoundary fallbackTitle="Error Rendering Incident Triage View">
            <IncidentDetailView
              incident={activeIncident}
              onIncidentUpdated={(updated) => {
                setActiveIncident(updated);
                setIncidentsList(prev => prev.map(i => i.incident_id === updated.incident_id ? updated : i));
              }}
            />
          </ErrorBoundary>
        )
      ) : (
        <div className="dark-panel p-16 flex flex-col items-center justify-center text-center space-y-4 max-w-2xl mx-auto my-12">
          <div className="w-16 h-16 rounded-2xl bg-cyan-950/40 border border-cyan-800/40 flex items-center justify-center text-cyan-400 shadow-xl shadow-cyan-950/20">
            <Shield size={32} />
          </div>
          <div>
            <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider mb-1">
              No Active Security Incident
            </h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              There are currently no active security incidents requiring analyst triage. Start a live network packet capture on the Dashboard or upload a PCAP file to initiate multi-agent cybersecurity analysis.
            </p>
          </div>
          <button
            onClick={onNavigateToDashboard}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold uppercase transition-all shadow-lg shadow-cyan-950/40"
          >
            <span>Go to Network Capture Dashboard</span>
            <ArrowRight size={14} />
          </button>
        </div>
      )}
    </div>
  );
};
