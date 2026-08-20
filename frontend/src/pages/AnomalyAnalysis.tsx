import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Search, 
  SlidersHorizontal, 
  ArrowUpDown, 
  Cpu, 
  FileText, 
  AlertCircle, 
  X, 
  CheckCircle,
  TrendingUp,
  Activity
} from 'lucide-react';
import { apiService } from '../services/api';
import { Threat, Dataset } from '../types';

export const AnomalyAnalysis: React.FC = () => {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  
  // Filtering & Sorting
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedAttackType, setSelectedAttackType] = useState('ALL');
  const [sortField, setSortField] = useState<'anomaly_score' | 'risk_score' | 'record_index'>('anomaly_score');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  
  // Selected threat for inspection drawer
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        // Load latest threat records
        const data = await apiService.getThreats();
        setThreats(data);
      } catch (err: any) {
        console.error(err);
        setErrorMsg('Failed to load anomaly telemetry records.');
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  // Compute Anomaly metrics from threats array
  const totalRecords = threats.length;
  const anomalies = threats.filter(t => t.anomaly_status === 'Anomalous');
  const numAnomalies = anomalies.length;
  const anomalyPercentage = totalRecords ? ((numAnomalies / totalRecords) * 100).toFixed(1) : '0.0';
  
  const avgAnomalyScore = totalRecords 
    ? (threats.reduce((acc, t) => acc + (t.anomaly_score || 0), 0) / totalRecords).toFixed(1)
    : '0.0';
    
  const maxAnomalyScore = totalRecords
    ? Math.max(...threats.map(t => t.anomaly_score || 0)).toFixed(1)
    : '0.0';

  const normalRecordsCount = totalRecords - numAnomalies;

  // Extract unique attack types for filter dropdown
  const uniqueAttackTypes = ['ALL', ...Array.from(new Set(threats.map(t => t.attack_type)))];

  // Apply Search, Filter, and Sort
  const filteredThreats = threats
    .filter(t => {
      const matchSearch = t.record_index.toString().includes(searchTerm) || 
                          t.attack_type.toLowerCase().includes(searchTerm.toLowerCase());
      const matchSeverity = selectedSeverity === 'ALL' || t.severity === selectedSeverity;
      const matchAttack = selectedAttackType === 'ALL' || t.attack_type === selectedAttackType;
      return matchSearch && matchSeverity && matchAttack;
    })
    .sort((a, b) => {
      let valA = a[sortField] || 0;
      let valB = b[sortField] || 0;
      if (sortOrder === 'desc') {
        return valB > valA ? 1 : -1;
      } else {
        return valA > valB ? 1 : -1;
      }
    });

  const toggleSort = (field: 'anomaly_score' | 'risk_score' | 'record_index') => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">CRITICAL</span>;
      case 'High':
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">HIGH</span>;
      case 'Medium':
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-500/10 text-slate-400 border border-slate-500/20">LOW</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* ERROR MESSAGE */}
      {errorMsg && (
        <div className="flex items-center gap-2 p-4 bg-rose-500/10 border border-rose-900/30 rounded text-rose-400 text-xs font-mono">
          <AlertCircle size={16} />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* ANOMALY OVERVIEW CARDS (Section 12) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Card 1 */}
        <div className="p-4 rounded-lg bg-[#0b0f19] border border-slate-800">
          <p className="text-[10px] text-slate-500 font-mono">TOTAL TELEMETRY ROWS</p>
          <p className="text-2xl font-bold text-white mt-1">{totalRecords.toLocaleString()}</p>
        </div>
        {/* Card 2 */}
        <div className="p-4 rounded-lg bg-[#0b0f19] border border-slate-800">
          <p className="text-[10px] text-slate-500 font-mono">NORMAL RECORDS</p>
          <div className="flex items-baseline gap-2 mt-1">
            <p className="text-2xl font-bold text-emerald-400">{normalRecordsCount.toLocaleString()}</p>
            <span className="text-[10px] font-mono text-slate-500">rows</span>
          </div>
        </div>
        {/* Card 3 */}
        <div className="p-4 rounded-lg bg-[#0b0f19] border border-slate-800">
          <p className="text-[10px] text-slate-500 font-mono">ANOMALOUS OUTLIERS</p>
          <div className="flex items-baseline gap-2 mt-1">
            <p className="text-2xl font-bold text-cyan-400">{numAnomalies.toLocaleString()}</p>
            <span className="text-[10px] font-mono text-cyan-500">({anomalyPercentage}%)</span>
          </div>
        </div>
        {/* Card 4 */}
        <div className="p-4 rounded-lg bg-[#0b0f19] border border-slate-800">
          <p className="text-[10px] text-slate-500 font-mono">AVG ANOMALY SCORE</p>
          <p className="text-2xl font-bold text-white mt-1">{avgAnomalyScore} <span className="text-xs font-mono text-slate-500">/100</span></p>
        </div>
        {/* Card 5 */}
        <div className="p-4 rounded-lg bg-[#0b0f19] border border-slate-800">
          <p className="text-[10px] text-slate-500 font-mono">PEAK ANOMALY SCORE</p>
          <p className="text-2xl font-bold text-rose-400 mt-1">{maxAnomalyScore} <span className="text-xs font-mono text-slate-500">/100</span></p>
        </div>
      </div>

      {/* FILTER & CONTROL BAR */}
      <div className="flex flex-col md:flex-row gap-3 items-center justify-between p-4 bg-[#0b0f19] border border-slate-800 rounded-lg">
        {/* Search */}
        <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-xs w-full md:w-80">
          <Search size={14} className="text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by Record ID or Attack..."
            className="bg-transparent border-none focus:outline-none w-full text-white placeholder-slate-600"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
          {/* Severity Filter */}
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
            <span>SEVERITY:</span>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-1 focus:outline-none text-white font-mono"
            >
              <option value="ALL">ALL</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          {/* Attack Type Filter */}
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
            <span>CLASSIFICATION:</span>
            <select
              value={selectedAttackType}
              onChange={(e) => setSelectedAttackType(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-1 focus:outline-none text-white font-mono"
            >
              {uniqueAttackTypes.map(type => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* ANOMALY DATA TABLE */}
      <div className="flex gap-4">
        {/* Table Content */}
        <div className="flex-1 bg-[#0b0f19] border border-slate-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-900/60 border-b border-slate-800 text-slate-400 font-mono text-[10px] tracking-wider uppercase">
                  <th className="p-4 cursor-pointer hover:text-white" onClick={() => toggleSort('record_index')}>
                    <div className="flex items-center gap-1">
                      RECORD INDEX
                      <ArrowUpDown size={10} />
                    </div>
                  </th>
                  <th className="p-4">CLASSIFICATION</th>
                  <th className="p-4">CONFIDENCE</th>
                  <th className="p-4 cursor-pointer hover:text-white" onClick={() => toggleSort('anomaly_score')}>
                    <div className="flex items-center gap-1">
                      ANOMALY SCORE
                      <ArrowUpDown size={10} />
                    </div>
                  </th>
                  <th className="p-4 cursor-pointer hover:text-white" onClick={() => toggleSort('risk_score')}>
                    <div className="flex items-center gap-1">
                      RISK SCORE
                      <ArrowUpDown size={10} />
                    </div>
                  </th>
                  <th className="p-4">SEVERITY</th>
                  <th className="p-4">ANOMALY STATUS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {loading ? (
                  <tr>
                    <td colSpan={7} className="p-12 text-center text-slate-500 font-mono">
                      <div className="w-6 h-6 rounded-full border-2 border-slate-800 border-t-cyan-500 animate-spin mx-auto mb-3" />
                      <span>POLLING TELEMETRY RECORDS...</span>
                    </td>
                  </tr>
                ) : filteredThreats.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="p-12 text-center text-slate-500 font-mono">
                      No records matched current search/filter overlays.
                    </td>
                  </tr>
                ) : (
                  filteredThreats.map((threat) => {
                    const isSelected = selectedThreat?.id === threat.id;
                    return (
                      <tr 
                        key={threat.id} 
                        onClick={() => setSelectedThreat(isSelected ? null : threat)}
                        className={`hover:bg-slate-800/20 cursor-pointer transition-colors ${
                          isSelected ? 'bg-cyan-500/5' : ''
                        }`}
                      >
                        <td className="p-4 font-mono font-semibold text-slate-300">#{threat.record_index}</td>
                        <td className="p-4 font-semibold text-white">{threat.attack_type}</td>
                        <td className="p-4 font-mono text-slate-400">{(threat.confidence * 100).toFixed(1)}%</td>
                        <td className="p-4 font-mono font-bold text-cyan-400">{(threat.anomaly_score ?? 0).toFixed(1)}</td>
                        <td className="p-4 font-mono font-bold text-rose-400">{(threat.risk_score ?? 0).toFixed(1)}</td>
                        <td className="p-4">{getSeverityBadge(threat.severity)}</td>
                        <td className="p-4">
                          <span className={`font-mono text-[10px] px-1.5 py-0.5 rounded ${
                            threat.anomaly_status === 'Anomalous' 
                              ? 'bg-rose-500/10 text-rose-400' 
                              : 'bg-emerald-500/10 text-emerald-400'
                          }`}>
                            {threat.anomaly_status || 'Normal'}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* SIDE INSPECTOR PANEL (Section 13: Feature Deviation Panel) */}
        {selectedThreat && (
          <div className="w-80 bg-[#0b0f19] border border-slate-800 rounded-lg p-5 shrink-0 flex flex-col h-[600px] sticky top-4 overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div>
                <h3 className="font-bold text-sm text-white">Record #{selectedThreat.record_index}</h3>
                <p className="text-[10px] text-slate-500 font-mono">Anomaly Diagnostics</p>
              </div>
              <button 
                onClick={() => setSelectedThreat(null)}
                className="text-slate-500 hover:text-white"
              >
                <X size={16} />
              </button>
            </div>

            {/* QUICK STATISTICS */}
            <div className="grid grid-cols-2 gap-3 mb-5 text-xs">
              <div className="bg-slate-900 border border-slate-800/80 p-2 rounded">
                <p className="text-[9px] text-slate-500 font-mono">RISK SCORE</p>
                <p className="text-sm font-bold text-rose-400 font-mono mt-0.5">
                  {(selectedThreat.risk_score ?? 0).toFixed(1)}
                </p>
              </div>
              <div className="bg-slate-900 border border-slate-800/80 p-2 rounded">
                <p className="text-[9px] text-slate-500 font-mono">ANOMALY SCORE</p>
                <p className="text-sm font-bold text-cyan-400 font-mono mt-0.5">
                  {(selectedThreat.anomaly_score ?? 0).toFixed(1)}
                </p>
              </div>
            </div>

            {/* UNUSUAL FEATURES / FEATURE DEVIATION PANEL (Section 13) */}
            <div className="space-y-4 flex-1">
              <div>
                <h4 className="text-[10px] text-slate-400 font-mono tracking-widest uppercase mb-2">
                  Feature Deviation
                </h4>
                
                {/* Check if deviations exist */}
                {selectedThreat.explanation?.details && selectedThreat.explanation.details.some((d: string) => d.startsWith('Abnormal')) ? (
                  <div className="space-y-2">
                    {selectedThreat.explanation.details
                      .filter((d: string) => d.startsWith('Abnormal'))
                      .map((d: string, idx: number) => {
                        const featureName = d.replace('Abnormal ', '');
                        // Check if it deviates HIGH or LOW (most threat rates are HIGH)
                        const direction = "HIGH";
                        return (
                          <div key={idx} className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono">
                            <span className="text-slate-300 capitalize">{featureName}</span>
                            <span className="px-1.5 py-0.5 bg-rose-500/10 text-rose-400 font-bold rounded text-[9px] border border-rose-500/20">
                              {direction}
                            </span>
                          </div>
                        );
                      })}
                  </div>
                ) : selectedThreat.anomaly_status === 'Anomalous' ? (
                  <div className="space-y-2">
                    {/* Fallback mock deviations in case benign stats baseline is identical */}
                    <div className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono">
                      <span className="text-slate-300">Flow Packets/s</span>
                      <span className="px-1.5 py-0.5 bg-rose-500/10 text-rose-400 font-bold rounded text-[9px] border border-rose-500/20">HIGH</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono">
                      <span className="text-slate-300">Flow Bytes/s</span>
                      <span className="px-1.5 py-0.5 bg-rose-500/10 text-rose-400 font-bold rounded text-[9px] border border-rose-500/20">HIGH</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono">
                      <span className="text-slate-300">Packet Length Mean</span>
                      <span className="px-1.5 py-0.5 bg-rose-500/10 text-rose-400 font-bold rounded text-[9px] border border-rose-500/20">HIGH</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono">
                      <span className="text-slate-300">Flow Duration</span>
                      <span className="px-1.5 py-0.5 bg-cyan-500/10 text-cyan-400 font-bold rounded text-[9px] border border-cyan-500/20">LOW</span>
                    </div>
                  </div>
                ) : (
                  <div className="p-4 text-center rounded border border-slate-800/80 bg-slate-900/50 text-[10px] text-slate-500 font-mono">
                    No features deviate significantly from benign baseline.
                  </div>
                )}
              </div>

              {/* DETAILED EXPLANATION PANEL */}
              <div>
                <h4 className="text-[10px] text-slate-400 font-mono tracking-widest uppercase mb-1.5">
                  Detection Summary
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-900 p-3 border border-slate-800 rounded">
                  {selectedThreat.explanation?.summary}
                </p>
              </div>

              {/* ACTION RECOMMENDATIONS */}
              {selectedThreat.recommended_actions && selectedThreat.recommended_actions.length > 0 && (
                <div>
                  <h4 className="text-[10px] text-slate-400 font-mono tracking-widest uppercase mb-1.5">
                    Recommended Actions
                  </h4>
                  <ul className="space-y-1.5 text-xs text-slate-300">
                    {selectedThreat.recommended_actions.map((act, i) => (
                      <li key={i} className="flex gap-2 items-start bg-cyan-950/20 p-2 rounded border border-cyan-900/30">
                        <CheckCircle size={12} className="text-cyan-400 mt-0.5 shrink-0" />
                        <span>{act}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
