import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  Trash2,
  RefreshCw,
  Search,
  Filter,
  ShieldAlert,
  CheckCircle,
  Database,
  HardDrive,
  Eye,
  ExternalLink,
  ChevronRight,
  Clock,
  Radio,
  X,
  FileCode,
  AlertTriangle
} from 'lucide-react';
import { PersistentReport, StorageStatus } from '../types';
import { apiService } from '../services/api';

export const ReportHistory: React.FC = () => {
  const [reports, setReports] = useState<PersistentReport[]>([]);
  const [storageStatus, setStorageStatus] = useState<StorageStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedReport, setSelectedReport] = useState<PersistentReport | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [attackFilter, setAttackFilter] = useState<string>('all');
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchReportsAndStatus = async () => {
    try {
      setLoading(true);
      const [statusRes, reportsRes] = await Promise.all([
        apiService.getReportStorageStatus().catch(() => null),
        apiService.getStoredReports(100, 0).catch(() => [])
      ]);
      setStorageStatus(statusRes);
      setReports(reportsRes);
    } catch (err: any) {
      setNotification({ type: 'error', message: err.message || 'Failed to load reports from MongoDB.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReportsAndStatus();
  }, []);

  const handleDelete = async (reportId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm(`Are you sure you want to permanently delete report ${reportId} from MongoDB and local storage?`)) {
      return;
    }
    try {
      setDeletingId(reportId);
      await apiService.deleteStoredReport(reportId);
      setReports(prev => prev.filter(r => r.report_id !== reportId));
      if (selectedReport?.report_id === reportId) {
        setSelectedReport(null);
      }
      setNotification({ type: 'success', message: `Report ${reportId} deleted successfully.` });
      // Refresh status counts
      apiService.getReportStorageStatus().then(st => setStorageStatus(st)).catch(() => {});
    } catch (err: any) {
      setNotification({ type: 'error', message: err.message || 'Failed to delete report.' });
    } finally {
      setDeletingId(null);
    }
  };

  const handleDownload = (reportId: string, format: 'md' | 'json', e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const url = apiService.getStoredReportDownloadUrl(reportId, format);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${reportId}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  // Filter reports
  const filteredReports = reports.filter(r => {
    const matchesSearch =
      r.report_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.incident_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.attack_classification.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.flow_statistics?.source_ip && r.flow_statistics.source_ip.includes(searchQuery)) ||
      (r.flow_statistics?.destination_ip && r.flow_statistics.destination_ip.includes(searchQuery));

    const matchesSeverity =
      severityFilter === 'all' ||
      r.agent_findings?.severity?.toLowerCase() === severityFilter.toLowerCase();

    const matchesAttack =
      attackFilter === 'all' ||
      r.attack_classification.toLowerCase() === attackFilter.toLowerCase();

    return matchesSearch && matchesSeverity && matchesAttack;
  });

  const uniqueAttacks = Array.from(new Set(reports.map(r => r.attack_classification))).filter(Boolean);

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
        return 'bg-rose-950/70 text-rose-400 border-rose-800/80';
      case 'high':
        return 'bg-amber-950/70 text-amber-400 border-amber-800/80';
      case 'medium':
        return 'bg-yellow-950/70 text-yellow-400 border-yellow-800/80';
      default:
        return 'bg-emerald-950/70 text-emerald-400 border-emerald-800/80';
    }
  };

  return (
    <div className="space-y-6">
      {/* ─── Notification Banner ─── */}
      {notification && (
        <div className={`p-3.5 rounded-xl border flex items-center justify-between text-xs font-mono ${
          notification.type === 'success'
            ? 'bg-emerald-950/50 border-emerald-800/60 text-emerald-300'
            : 'bg-rose-950/50 border-rose-800/60 text-rose-300'
        }`}>
          <div className="flex items-center gap-2">
            {notification.type === 'success' ? <CheckCircle size={15} /> : <AlertTriangle size={15} />}
            <span>{notification.message}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-white">
            <X size={14} />
          </button>
        </div>
      )}

      {/* ─── MongoDB & Storage Health Overview ─── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="dark-panel p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">Database Storage</span>
            <div className="flex items-center gap-2 mt-1">
              <span className={`w-2 h-2 rounded-full ${storageStatus?.mongodb_connected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
              <span className="text-sm font-bold font-mono text-white">
                {storageStatus?.mongodb_connected ? 'MongoDB Active' : 'MongoDB Offline'}
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-400 block mt-0.5 truncate max-w-[180px]">
              {storageStatus?.mongodb_database || 'iot_sentinel'} ({storageStatus?.mongodb_uri})
            </span>
          </div>
          <div className="w-10 h-10 rounded-xl bg-cyan-950/60 border border-cyan-800/50 flex items-center justify-center text-cyan-400">
            <Database size={18} />
          </div>
        </div>

        <div className="dark-panel p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">Local Storage Directory</span>
            <span className="text-sm font-bold font-mono text-white mt-1 block">
              storage/reports/
            </span>
            <span className="text-[10px] font-mono text-slate-400 block mt-0.5">
              {storageStatus?.total_files_on_disk || 0} file(s) persisted
            </span>
          </div>
          <div className="w-10 h-10 rounded-xl bg-purple-950/60 border border-purple-800/50 flex items-center justify-center text-purple-400">
            <HardDrive size={18} />
          </div>
        </div>

        <div className="dark-panel p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">Archived Reports</span>
            <span className="text-xl font-bold font-mono text-cyan-400 mt-0.5 block">
              {reports.length}
            </span>
            <span className="text-[10px] font-mono text-slate-400 block mt-0.5">
              Across all SOC sessions
            </span>
          </div>
          <div className="w-10 h-10 rounded-xl bg-slate-900 border border-slate-750 flex items-center justify-center text-cyan-300">
            <FileText size={18} />
          </div>
        </div>

        <div className="dark-panel p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">Persistence Mode</span>
            <span className="text-sm font-bold font-mono text-emerald-400 mt-1 block">
              Permanent Sync
            </span>
            <span className="text-[10px] font-mono text-slate-400 block mt-0.5">
              Survives server restarts
            </span>
          </div>
          <div className="w-10 h-10 rounded-xl bg-emerald-950/60 border border-emerald-800/50 flex items-center justify-center text-emerald-400">
            <CheckCircle size={18} />
          </div>
        </div>
      </div>

      {/* ─── Search & Filters Bar ─── */}
      <div className="dark-panel p-4 flex flex-col md:flex-row gap-4 items-center justify-between">
        <div className="flex-1 w-full md:w-auto relative">
          <Search size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search by Report ID, Incident ID, IP, or attack category..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900/90 border border-slate-850 rounded-lg pl-9 pr-3.5 py-2 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="flex items-center gap-2">
            <Filter size={13} className="text-slate-500" />
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="bg-slate-900/90 border border-slate-850 rounded-lg px-2.5 py-2 text-xs font-mono text-slate-300 focus:border-cyan-500 focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <select
            value={attackFilter}
            onChange={e => setAttackFilter(e.target.value)}
            className="bg-slate-900/90 border border-slate-850 rounded-lg px-2.5 py-2 text-xs font-mono text-slate-300 focus:border-cyan-500 focus:outline-none"
          >
            <option value="all">All Attack Classes</option>
            {uniqueAttacks.map(att => (
              <option key={att} value={att}>{att}</option>
            ))}
          </select>

          <button
            onClick={fetchReportsAndStatus}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white text-xs font-mono transition-colors"
            title="Refresh reports from MongoDB"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin text-cyan-400' : ''} />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </div>

      {/* ─── Reports Grid / Table ─── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Reports List */}
        <div className={`space-y-3 ${selectedReport ? 'lg:col-span-1' : 'lg:col-span-3'}`}>
          {loading ? (
            <div className="dark-panel p-12 text-center">
              <RefreshCw size={24} className="animate-spin text-cyan-400 mx-auto mb-3" />
              <p className="text-xs font-mono text-slate-400">Loading reports from MongoDB...</p>
            </div>
          ) : filteredReports.length === 0 ? (
            <div className="dark-panel p-12 text-center space-y-3">
              <FileText size={32} className="text-slate-600 mx-auto" />
              <h4 className="text-sm font-mono text-slate-300 font-bold">No Stored Reports Found</h4>
              <p className="text-xs font-mono text-slate-500 max-w-md mx-auto">
                No persistent incident reports matched your query. Capture traffic or process a PCAP file to generate reports.
              </p>
            </div>
          ) : (
            filteredReports.map(report => (
              <div
                key={report.report_id}
                onClick={() => setSelectedReport(report)}
                className={`p-4 rounded-xl border transition-all cursor-pointer relative ${
                  selectedReport?.report_id === report.report_id
                    ? 'bg-slate-900/95 border-cyan-500/80 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-500/50'
                    : 'bg-slate-950/70 border-slate-850 hover:border-slate-700 hover:bg-slate-900/60'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs font-bold text-white tracking-wider">
                        {report.report_id}
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-semibold ${getSeverityBadge(report.agent_findings?.severity)}`}>
                        {report.agent_findings?.severity || 'Low'}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/60 text-cyan-300">
                        {report.attack_classification} ({(report.confidence * 100).toFixed(1)}%)
                      </span>
                    </div>

                    <p className="text-xs font-mono text-slate-400 truncate">
                      {report.flow_statistics?.source_ip || 'N/A'}:{report.flow_statistics?.source_port || ''} → {report.flow_statistics?.destination_ip || 'N/A'}:{report.flow_statistics?.destination_port || ''} ({report.flow_statistics?.protocol || 'IP'})
                    </p>

                    <div className="flex items-center gap-4 text-[11px] font-mono text-slate-500">
                      <span className="flex items-center gap-1">
                        <Clock size={11} />
                        {new Date(report.created_at).toLocaleString()}
                      </span>
                      <span>
                        {(report.file_size / 1024).toFixed(1)} KB
                      </span>
                      <span className={report.file_exists !== false ? 'text-emerald-400' : 'text-rose-400'}>
                        {report.file_exists !== false ? '● on disk' : '○ missing file'}
                      </span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1.5 shrink-0" onClick={e => e.stopPropagation()}>
                    <button
                      onClick={e => handleDownload(report.report_id, 'md', e)}
                      title="Download Markdown Report"
                      className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-cyan-400 border border-slate-800 transition-colors"
                    >
                      <Download size={13} />
                    </button>
                    <button
                      onClick={e => handleDownload(report.report_id, 'json', e)}
                      title="Download JSON Bundle"
                      className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-purple-400 border border-slate-800 transition-colors"
                    >
                      <FileCode size={13} />
                    </button>
                    <button
                      onClick={e => handleDelete(report.report_id, e)}
                      disabled={deletingId === report.report_id}
                      title="Delete from MongoDB & Disk"
                      className="p-1.5 rounded-lg bg-slate-900 hover:bg-rose-950/60 text-slate-400 hover:text-rose-400 border border-slate-800 hover:border-rose-800/60 transition-colors disabled:opacity-40"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Selected Report Detail View (Slide-in / Expand) */}
        {selectedReport && (
          <div className="lg:col-span-2 space-y-4">
            <div className="dark-panel p-6 border-l-4 border-l-cyan-500 space-y-6">
              {/* Header */}
              <div className="flex items-start justify-between pb-4 border-b border-slate-850">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-mono uppercase tracking-wider text-white font-bold">
                      {selectedReport.title}
                    </h3>
                  </div>
                  <div className="flex items-center gap-3 text-xs font-mono text-slate-400 mt-1">
                    <span>Incident: <b className="text-slate-200">{selectedReport.incident_id}</b></span>
                    <span>•</span>
                    <span>Created: {new Date(selectedReport.created_at).toLocaleString()}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleDownload(selectedReport.report_id, 'md')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold transition-all shadow-md shadow-cyan-950/40"
                  >
                    <Download size={13} />
                    <span>Download (.md)</span>
                  </button>
                  <button
                    onClick={() => handleDownload(selectedReport.report_id, 'json')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-950 hover:bg-purple-900 border border-purple-700/60 text-purple-300 font-mono text-xs font-semibold transition-all"
                  >
                    <FileCode size={13} />
                    <span>JSON Bundle</span>
                  </button>
                  <button
                    onClick={() => setSelectedReport(null)}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-white"
                  >
                    <X size={16} />
                  </button>
                </div>
              </div>

              {/* KPI Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-850">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Classification</span>
                  <span className="text-sm font-bold font-mono text-cyan-400">
                    {selectedReport.attack_classification}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-850">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Confidence</span>
                  <span className="text-sm font-bold font-mono text-emerald-400">
                    {(selectedReport.confidence * 100).toFixed(2)}%
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-850">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Risk Score</span>
                  <span className="text-sm font-bold font-mono text-amber-400">
                    {selectedReport.agent_findings?.risk_score}/100
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-850">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Priority</span>
                  <span className="text-sm font-bold font-mono text-purple-400">
                    {selectedReport.agent_findings?.priority || 'P3'}
                  </span>
                </div>
              </div>

              {/* Network 5-Tuple Telemetry */}
              <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-850 space-y-2">
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2">
                  <Radio size={13} className="text-cyan-400" />
                  <span>Network Flow Telemetry</span>
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block text-[10px]">Source</span>
                    <span className="text-slate-200">{selectedReport.flow_statistics?.source_ip}:{selectedReport.flow_statistics?.source_port}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Destination</span>
                    <span className="text-slate-200">{selectedReport.flow_statistics?.destination_ip}:{selectedReport.flow_statistics?.destination_port}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Transport</span>
                    <span className="text-slate-200">{selectedReport.flow_statistics?.protocol}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Storage Path</span>
                    <span className="text-slate-400 truncate block">{selectedReport.filepath}</span>
                  </div>
                </div>
              </div>

              {/* MITRE Threat Intel & Verified CVEs */}
              {selectedReport.agent_findings?.nvd_cves && selectedReport.agent_findings.nvd_cves.length > 0 && (
                <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-850 space-y-2">
                  <h4 className="text-xs font-mono uppercase tracking-wider text-rose-300 font-bold flex items-center gap-2">
                    <ShieldAlert size={13} className="text-rose-400" />
                    <span>Correlated Vulnerabilities (NVD / CISA)</span>
                  </h4>
                  <div className="space-y-1.5">
                    {selectedReport.agent_findings.nvd_cves.map(cve => (
                      <div key={cve.cve_id} className="p-2.5 rounded bg-slate-950/80 border border-slate-800 text-xs font-mono flex items-center justify-between">
                        <div>
                          <span className="text-rose-400 font-bold mr-2">{cve.cve_id}</span>
                          <span className="text-slate-400">{cve.description}</span>
                        </div>
                        <span className="px-2 py-0.5 rounded bg-rose-950 border border-rose-800 text-rose-300 text-[10px] font-bold shrink-0 ml-2">
                          CVSS {cve.cvss}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* SHAP Feature Attributions */}
              {selectedReport.shap_explanations?.top_contributing_features && (
                <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-850 space-y-2">
                  <h4 className="text-xs font-mono uppercase tracking-wider text-cyan-300 font-bold">
                    SHAP Explainability Top Drivers
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                    {selectedReport.shap_explanations.top_contributing_features.slice(0, 4).map((f, i) => (
                      <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800 flex justify-between items-center">
                        <span className="text-slate-300">{f.feature}</span>
                        <span className="text-cyan-400 font-bold">SHAP: {f.shap_value > 0 ? `+${f.shap_value.toFixed(3)}` : f.shap_value.toFixed(3)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Markdown Document Preview */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold">
                  Report Document Preview (.md)
                </h4>
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 max-h-96 overflow-y-auto text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed select-text">
                  {selectedReport.markdown_content || 'No preview available.'}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
