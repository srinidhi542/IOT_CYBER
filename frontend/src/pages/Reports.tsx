import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Download, 
  Plus, 
  CheckCircle, 
  AlertCircle,
  FileSpreadsheet,
  ShieldCheck,
  Zap
} from 'lucide-react';
import { SecurityReport, DetectionJob, Dataset } from '../types';
import { apiService } from '../services/api';

interface ReportsProps {
  detectionJobs: DetectionJob[];
  datasets: Dataset[];
}

export const Reports: React.FC<ReportsProps> = ({
  detectionJobs,
  datasets
}) => {
  const [reports, setReports] = useState<SecurityReport[]>([]);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [selectedJobId, setSelectedJobId] = useState<number>(0);
  const [selectedReport, setSelectedReport] = useState<SecurityReport | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Load reports
  async function loadReports() {
    setLoading(true);
    try {
      const list = await apiService.getReports();
      setReports(list);
      if (list.length > 0 && !selectedReport) {
        setSelectedReport(list[0]);
      }
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.message || "Failed to load reports library.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadReports();
  }, []);

  // Set default job selection
  useEffect(() => {
    if (detectionJobs.length > 0 && selectedJobId === 0) {
      setSelectedJobId(detectionJobs[0].id);
    }
  }, [detectionJobs]);

  // Handle report generation
  const handleGenerateReport = async () => {
    if (selectedJobId === 0) {
      setErrorMsg("Please select a valid detection job to document.");
      return;
    }

    setGenerating(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      const rep = await apiService.generateReport(selectedJobId);
      setSelectedReport(rep);
      setSuccessMsg("Security Assessment PDF Report generated successfully!");
      await loadReports();
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.message || "Failed to generate security report.");
    } finally {
      setGenerating(false);
    }
  };

  // Find dataset name for a job id
  const getDatasetName = (jobId: number) => {
    const job = detectionJobs.find(j => j.id === jobId);
    if (!job) return 'IoT Network';
    const ds = datasets.find(d => d.id === job.dataset_id);
    return ds ? ds.name : `Dataset #${job.dataset_id}`;
  };

  const handleDownloadPdf = (report: SecurityReport) => {
    // Open the download link in a new window or trigger download
    const url = apiService.getReportDownloadUrl(report.id);
    window.open(url, '_blank');
  };

  return (
    <div className="space-y-8">
      {/* ALERTS */}
      {errorMsg && (
        <div className="flex items-center gap-3 p-4 bg-rose-500/10 border border-rose-900/30 rounded-lg text-rose-400 text-xs font-mono">
          <AlertCircle size={16} />
          <span>{errorMsg}</span>
        </div>
      )}
      {successMsg && (
        <div className="flex items-center gap-3 p-4 bg-emerald-500/10 border border-emerald-900/30 rounded-lg text-emerald-400 text-xs font-mono">
          <CheckCircle size={16} />
          <span>{successMsg}</span>
        </div>
      )}

      {/* CREATE REPORT OVERLAY */}
      <div className="dark-panel p-6 space-y-4">
        <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">Generate Security Assessment Report</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 items-end">
          {/* Select detection run */}
          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-500 font-mono">CHOOSE DETECTION AUDIT RUN:</label>
            <select
              value={selectedJobId}
              onChange={(e) => setSelectedJobId(parseInt(e.target.value))}
              disabled={generating}
              className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              <option value={0}>-- Choose Audit Run --</option>
              {detectionJobs.map(j => (
                <option key={j.id} value={j.id}>
                  Run #{j.id} - {getDatasetName(j.id)} ({j.malicious_count.toLocaleString()} threats)
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleGenerateReport}
            disabled={generating || selectedJobId === 0}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {generating ? (
              <>
                <div className="w-4 h-4 rounded-full border-2 border-slate-800 border-t-white animate-spin" />
                <span>Generating Document...</span>
              </>
            ) : (
              <>
                <Plus size={14} />
                <span>Create Security Report</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* REPORT VIEWER / SIDEBAR GRID */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start">
        {/* Reports Archive Sidebar */}
        <div className="dark-panel p-6 space-y-4 h-[550px] flex flex-col">
          <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider shrink-0">Report Archive Vault</h3>
          
          <div className="flex-1 overflow-y-auto space-y-2 pr-2 text-xs">
            {loading ? (
              <div className="flex justify-center py-12">
                <div className="w-6 h-6 rounded-full border-2 border-slate-800 border-t-cyan-500 animate-spin" />
              </div>
            ) : reports.length === 0 ? (
              <p className="text-slate-500 italic py-8 text-center">No reports generated in this workspace.</p>
            ) : (
              reports.map((r) => (
                <button
                  key={r.id}
                  onClick={() => setSelectedReport(r)}
                  className={`flex flex-col gap-1 w-full px-4 py-3 rounded text-left border transition-all ${
                    selectedReport?.id === r.id 
                      ? 'bg-slate-800/80 border-cyan-600 text-white font-semibold' 
                      : 'border-slate-800 text-slate-400 hover:bg-slate-900/50'
                  }`}
                >
                  <div className="flex items-center gap-2 w-full">
                    <FileText size={14} className="text-cyan-500 shrink-0" />
                    <span className="truncate font-semibold">{r.title}</span>
                  </div>
                  <div className="flex justify-between items-center text-[9px] font-mono text-slate-500 mt-1">
                    <span>AUDIT RUN: #{r.detection_job_id}</span>
                    <span>{r.summary?.generated_at?.split(' ')[0]}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Selected Report Viewer Frame */}
        <div className="dark-panel p-6 xl:col-span-2 space-y-6 h-[550px] overflow-y-auto flex flex-col justify-between">
          {selectedReport ? (
            <div className="space-y-6">
              {/* Header block */}
              <div className="flex justify-between items-start border-b border-slate-800 pb-4">
                <div>
                  <h4 className="text-sm font-bold text-white tracking-wide">{selectedReport.title}</h4>
                  <p className="text-[10px] text-slate-400 font-mono mt-1">
                    GENERATED AT: {selectedReport.summary.generated_at} | MODEL: {selectedReport.summary.model_name}
                  </p>
                </div>
                <button
                  onClick={() => handleDownloadPdf(selectedReport)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs border border-slate-800 rounded font-semibold transition-colors"
                >
                  <Download size={13} />
                  <span>Download PDF</span>
                </button>
              </div>

              {/* KPI metrics row */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
                <div className="bg-slate-900/80 p-3 border border-slate-800/50 rounded">
                  <span className="text-slate-500 text-[10px] block">TOTAL NETWORK PACKETS</span>
                  <span className="text-sm font-bold text-white mt-1 block">{selectedReport.summary.total_records.toLocaleString()}</span>
                </div>
                <div className="bg-slate-900/80 p-3 border border-slate-800/50 rounded">
                  <span className="text-slate-500 text-[10px] block">BENIGN FLOWS</span>
                  <span className="text-sm font-bold text-emerald-400 mt-1 block">{selectedReport.summary.benign_records.toLocaleString()}</span>
                </div>
                <div className="bg-slate-900/80 p-3 border border-slate-800/50 rounded">
                  <span className="text-slate-500 text-[10px] block">MALICIOUS INCIDENTS</span>
                  <span className="text-sm font-bold text-rose-500 mt-1 block">{selectedReport.summary.malicious_records.toLocaleString()}</span>
                </div>
                <div className="bg-slate-900/80 p-3 border border-slate-800/50 rounded">
                  <span className="text-slate-500 text-[10px] block">CRITICAL EVENTS</span>
                  <span className="text-sm font-bold text-red-500 mt-1 block">{selectedReport.summary.critical_records.toLocaleString()}</span>
                </div>
              </div>

              {/* Findings */}
              <div className="space-y-2 text-xs">
                <h5 className="text-[10px] font-semibold text-slate-400 font-mono uppercase tracking-wider flex items-center gap-1">
                  <Zap size={12} className="text-cyan-400" />
                  Security Audit Findings
                </h5>
                <div className="p-4 bg-slate-900/40 border border-slate-800/80 rounded space-y-2">
                  {selectedReport.summary.key_findings?.map((finding, idx) => (
                    <p key={idx} className="leading-relaxed text-slate-300">
                      • {finding}
                    </p>
                  ))}
                </div>
              </div>

              {/* Threat distribution list */}
              <div className="space-y-2 text-xs">
                <h5 className="text-[10px] font-semibold text-slate-400 font-mono uppercase tracking-wider">Threat Profile Summary</h5>
                <div className="border border-slate-800 rounded overflow-hidden">
                  <table className="w-full text-left text-[11px] font-mono border-collapse">
                    <thead className="bg-slate-900 text-slate-400">
                      <tr className="border-b border-slate-800">
                        <th className="py-2 px-3">ATTACK CATEGORY</th>
                        <th className="py-2 px-3 text-right">EVENTS</th>
                        <th className="py-2 px-3 text-right">PERCENTAGE</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/40 text-slate-300">
                      {Object.entries(selectedReport.summary.attack_distribution).map(([attack, count]) => {
                        const pct = (count / selectedReport.summary.total_records) * 100;
                        return (
                          <tr key={attack} className="hover:bg-slate-900/20">
                            <td className="py-2 px-3 font-semibold text-white">{attack}</td>
                            <td className="py-2 px-3 text-right">{count.toLocaleString()}</td>
                            <td className="py-2 px-3 text-right">{pct.toFixed(2)}%</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Recommendations */}
              {selectedReport.summary.recommendations && Object.keys(selectedReport.summary.recommendations).length > 0 && (
                <div className="space-y-3 text-xs">
                  <h5 className="text-[10px] font-semibold text-slate-400 font-mono uppercase tracking-wider">mitigation and response actions</h5>
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {Object.entries(selectedReport.summary.recommendations).map(([attack, actions]) => (
                      <div key={attack} className="p-3 bg-slate-900 border border-slate-800/50 rounded space-y-1.5">
                        <p className="font-semibold text-white">For {attack} Incidents:</p>
                        <ul className="list-disc list-inside text-slate-400 pl-1 space-y-1 font-mono text-[10px]">
                          {actions.map((act, actIdx) => (
                            <li key={actIdx} className="leading-snug">{act}</li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-20 text-slate-500 text-xs">
              <ShieldCheck size={32} className="text-slate-600 mb-2" />
              <span>Select an archived security report or generate a new assessment from above.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
