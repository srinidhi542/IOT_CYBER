import React, { useState, useEffect } from 'react';
import { 
  Play, 
  ShieldAlert, 
  Search, 
  X, 
  AlertOctagon, 
  CheckCircle2, 
  Info,
  Server,
  ArrowRight,
  Filter,
  Microscope
} from 'lucide-react';
import { Dataset, MLModel, Threat, DetectionJob } from '../types';
import { apiService } from '../services/api';

interface ThreatDetectionProps {
  datasets: Dataset[];
  models: MLModel[];
  onDetectionSuccess: (job: DetectionJob) => void;
  onExplainThreat?: (threatId: number) => void;
}

export const ThreatDetection: React.FC<ThreatDetectionProps> = ({
  datasets,
  models,
  onDetectionSuccess,
  onExplainThreat
}) => {
  const [selectedDatasetId, setSelectedDatasetId] = useState<number>(0);
  const [selectedModelId, setSelectedModelId] = useState<number>(0);
  const [selectedAnomalyModelId, setSelectedAnomalyModelId] = useState<number>(0);
  const [running, setRunning] = useState(false);
  const [stepIndex, setStepIndex] = useState(-1);
  const [resultJob, setResultJob] = useState<DetectionJob | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [filteredThreats, setFilteredThreats] = useState<Threat[]>([]);
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Filters
  const [searchIp, setSearchIp] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [attackFilter, setAttackFilter] = useState('');

  const steps = [
    "Loading network traffic dataset",
    "Preprocessing and cleaning packet logs",
    "Running machine learning model inference",
    "Calculating class prediction confidence scores",
    "Assigning rule-based threat severity rankings",
    "Generating actionable response recommendations"
  ];

  const classifiers = models.filter(m => m.model_type !== 'anomaly');
  const anomalyModels = models.filter(m => m.model_type === 'anomaly');

  // Set default selects
  useEffect(() => {
    if (datasets.length > 0 && selectedDatasetId === 0) {
      setSelectedDatasetId(datasets[0].id);
    }
    if (classifiers.length > 0 && selectedModelId === 0) {
      setSelectedModelId(classifiers[0].id);
    }
    if (anomalyModels.length > 0 && selectedAnomalyModelId === 0) {
      setSelectedAnomalyModelId(anomalyModels[0].id);
    }
  }, [datasets, models]);

  // Apply filters to threats list
  useEffect(() => {
    let result = threats;

    if (searchIp.trim()) {
      const q = searchIp.toLowerCase();
      result = result.filter(t => {
        const src = (t.record_data.Source_IP || t.record_data.source_ip || '').toLowerCase();
        const dst = (t.record_data.Destination_IP || t.record_data.dest_ip || '').toLowerCase();
        return src.includes(q) || dst.includes(q);
      });
    }

    if (severityFilter) {
      result = result.filter(t => t.severity === severityFilter);
    }

    if (attackFilter) {
      result = result.filter(t => t.attack_type.toLowerCase() === attackFilter.toLowerCase());
    }

    setFilteredThreats(result);
  }, [threats, searchIp, severityFilter, attackFilter]);

  // Execute detection run simulation
  const handleExecuteDetection = async () => {
    if (selectedDatasetId === 0 || selectedModelId === 0) {
      setErrorMsg("Please select both a dataset and model for inference.");
      return;
    }

    setRunning(true);
    setStepIndex(0);
    setErrorMsg(null);
    setResultJob(null);
    setThreats([]);
    setSelectedThreat(null);

    // Simulate pipeline steps animation (1s per step)
    const stepTimer = setInterval(() => {
      setStepIndex(prev => {
        if (prev < steps.length - 1) {
          return prev + 1;
        } else {
          clearInterval(stepTimer);
          return prev;
        }
      });
    }, 900);

    try {
      const result = await apiService.runDetection(selectedDatasetId, selectedModelId, selectedAnomalyModelId || undefined);
      
      // Wait slightly if the backend finished quickly to ensure the user sees the steps progress
      await new Promise(resolve => setTimeout(resolve, steps.length * 900 + 200));
      
      clearInterval(stepTimer);
      setStepIndex(steps.length); // Finished
      
      setResultJob(result.job);
      setThreats(result.threats);
      onDetectionSuccess(result.job);
    } catch (err: any) {
      clearInterval(stepTimer);
      console.error(err);
      setErrorMsg(err.message || "Threat detection execution crashed.");
      setStepIndex(-1);
    } finally {
      setRunning(false);
    }
  };

  // Get distinct attack types in predictions for filters
  const getDistinctAttacks = () => {
    const list = threats.map(t => t.attack_type);
    return Array.from(new Set(list));
  };

  return (
    <div className="space-y-8">
      {/* ERROR CARD */}
      {errorMsg && (
        <div className="flex items-center gap-3 p-4 bg-rose-500/10 border border-rose-900/30 rounded-lg text-rose-400 text-xs font-mono">
          <AlertOctagon size={16} />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* PIPELINE CONTROL ZONE */}
      <div className="dark-panel p-6 space-y-4">
        <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">Execute Threat Analysis Pipeline</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 items-end">
          {/* Select dataset */}
          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-500 font-mono">CHOOSE EVALUATION DATASET:</label>
            <select
              value={selectedDatasetId}
              onChange={(e) => setSelectedDatasetId(parseInt(e.target.value))}
              disabled={running}
              className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              <option value={0}>-- Choose Dataset --</option>
              {datasets.map(d => (
                <option key={d.id} value={d.id}>
                  {d.name} ({d.row_count?.toLocaleString()} rows)
                </option>
              ))}
            </select>
          </div>

          {/* Select classifier model */}
          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-500 font-mono">SUPERVISED CLASSIFIER:</label>
            <select
              value={selectedModelId}
              onChange={(e) => setSelectedModelId(parseInt(e.target.value))}
              disabled={running}
              className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              <option value={0}>-- Choose Classifier --</option>
              {classifiers.map(m => (
                <option key={m.id} value={m.id}>
                  {m.name} (ACC: {m.accuracy ? Math.round(m.accuracy*100) : 0}%)
                </option>
              ))}
            </select>
          </div>

          {/* Select anomaly model */}
          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-500 font-mono">UNSUPERVISED ANOMALY MODEL:</label>
            <select
              value={selectedAnomalyModelId}
              onChange={(e) => setSelectedAnomalyModelId(parseInt(e.target.value))}
              disabled={running}
              className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              <option value={0}>-- Auto Isolation Forest --</option>
              {anomalyModels.map(m => (
                <option key={m.id} value={m.id}>
                  {m.name} (CONTAM: {m.contamination ? Math.round(m.contamination*100) : 5}%)
                </option>
              ))}
            </select>
          </div>

          {/* Trigger button */}
          <button
            onClick={handleExecuteDetection}
            disabled={running || selectedDatasetId === 0 || selectedModelId === 0}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            <Play size={14} />
            <span>Run Threat Detection</span>
          </button>
        </div>
      </div>

      {/* PIPELINE PROGRESS BAR */}
      {stepIndex >= 0 && stepIndex < steps.length && (
        <div className="dark-panel p-6 space-y-4">
          <h3 className="text-xs font-semibold text-cyan-400 font-mono uppercase tracking-wider animate-pulse-subtle">
            Analysis Pipeline Execution in Progress
          </h3>
          <div className="space-y-3 font-mono text-[11px]">
            {steps.map((step, idx) => (
              <div key={idx} className="flex items-center gap-3">
                {idx < stepIndex ? (
                  <CheckCircle2 size={14} className="text-emerald-500 shrink-0" />
                ) : idx === stepIndex ? (
                  <div className="w-3.5 h-3.5 rounded-full border-2 border-slate-800 border-t-cyan-500 animate-spin shrink-0" />
                ) : (
                  <span className="w-3.5 h-3.5 rounded-full bg-slate-800 shrink-0" />
                )}
                <span className={idx === stepIndex ? 'text-white font-medium' : idx < stepIndex ? 'text-slate-400' : 'text-slate-600'}>
                  {step}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* RESULT INVENTORY CARD */}
      {resultJob && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <div className="dark-panel p-4 text-center">
            <span className="text-[10px] text-slate-500 font-mono block">TOTAL ANALYZED</span>
            <span className="text-lg font-bold text-white mt-1 block">{resultJob.total_records.toLocaleString()}</span>
          </div>
          <div className="dark-panel p-4 text-center">
            <span className="text-[10px] text-slate-500 font-mono block">BENIGN FILES</span>
            <span className="text-lg font-bold text-emerald-400 mt-1 block">{resultJob.benign_count.toLocaleString()}</span>
          </div>
          <div className="dark-panel p-4 text-center">
            <span className="text-[10px] text-slate-500 font-mono block">MALICIOUS INCIDENTS</span>
            <span className="text-lg font-bold text-rose-500 mt-1 block">{resultJob.malicious_count.toLocaleString()}</span>
          </div>
          <div className="dark-panel p-4 text-center">
            <span className="text-[10px] text-slate-500 font-mono block">CRITICAL EVENTS</span>
            <span className="text-lg font-bold text-red-500 mt-1 block">{resultJob.critical_count.toLocaleString()}</span>
          </div>
          <div className="dark-panel p-4 text-center">
            <span className="text-[10px] text-slate-500 font-mono block">AVG CONFIDENCE</span>
            <span className="text-lg font-bold text-white mt-1 block">{(resultJob.avg_confidence * 100).toFixed(1)}%</span>
          </div>
          <div className="dark-panel p-4 text-center">
            <span className="text-[10px] text-slate-500 font-mono block">HIGHEST-RISK VECTOR</span>
            <span className="text-xs font-semibold text-rose-400 mt-2 block truncate">
              {getDistinctAttacks().filter(a => a.toLowerCase() !== 'benign')[0] || 'None'}
            </span>
          </div>
        </div>
      )}

      {/* THREAT LIST AND DRAWER FRAME */}
      {resultJob && (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start">
          {/* Threats Table List */}
          <div className="dark-panel p-6 xl:col-span-2 space-y-4">
            <div className="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center">
              <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">Analysis Threat Vault</h3>
              
              {/* Table search filters */}
              <div className="flex flex-wrap gap-2 w-full md:w-auto text-xs font-mono">
                <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded px-2 py-1">
                  <Search size={12} className="text-slate-500" />
                  <input
                    type="text"
                    placeholder="Search IP..."
                    value={searchIp}
                    onChange={(e) => setSearchIp(e.target.value)}
                    className="bg-transparent border-none focus:outline-none w-24 text-[11px]"
                  />
                </div>
                
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-[11px] text-slate-300"
                >
                  <option value="">All Severity</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>

                <select
                  value={attackFilter}
                  onChange={(e) => setAttackFilter(e.target.value)}
                  className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-[11px] text-slate-300"
                >
                  <option value="">All Attacks</option>
                  {getDistinctAttacks().map(a => (
                    <option key={a} value={a}>{a}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-500 font-mono text-[10px]">
                    <th className="py-2.5 px-2">ID</th>
                    <th className="py-2.5 px-2">ATTACK CLASS</th>
                    <th className="py-2.5 px-2">SEVERITY</th>
                    <th className="py-2.5 px-2">CONFIDENCE</th>
                    {filteredThreats[0]?.record_data?.Source_IP && <th className="py-2.5 px-2">SOURCE IP</th>}
                    {filteredThreats[0]?.record_data?.Destination_IP && <th className="py-2.5 px-2">DEST IP</th>}
                    <th className="py-2.5 px-2">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850">
                  {filteredThreats.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="text-center py-8 text-slate-500 italic">
                        No records matching filter rules found.
                      </td>
                    </tr>
                  ) : (
                    filteredThreats.map((threat) => {
                      const isSelected = selectedThreat?.id === threat.id;
                      let sevColor = 'text-slate-400 bg-slate-900';
                      if (threat.severity === 'Critical') sevColor = 'text-red-400 bg-red-950/20 border border-red-900/30';
                      if (threat.severity === 'High') sevColor = 'text-orange-400 bg-orange-950/20 border border-orange-900/30';
                      if (threat.severity === 'Medium') sevColor = 'text-amber-400 bg-amber-950/20 border border-amber-900/30';
                      if (threat.severity === 'Low') sevColor = 'text-emerald-400 bg-emerald-950/20 border border-emerald-900/30';
                      
                      return (
                        <tr 
                          key={threat.id} 
                          onClick={() => setSelectedThreat(threat)}
                          className={`hover:bg-slate-800/15 cursor-pointer text-slate-300 transition-colors ${
                            isSelected ? 'bg-slate-800/40 border-l-2 border-cyan-500 text-white font-medium' : ''
                          }`}
                        >
                          <td className="py-2.5 px-2 font-mono text-[10px]">#{threat.record_index}</td>
                          <td className="py-2.5 px-2 font-semibold">{threat.attack_type}</td>
                          <td className="py-2.5 px-2">
                            <span className={`px-2 py-0.5 rounded-full text-[9px] font-mono leading-none ${sevColor}`}>
                              {threat.severity}
                            </span>
                          </td>
                          <td className="py-2.5 px-2 font-mono">{(threat.confidence * 100).toFixed(1)}%</td>
                          {threat.record_data?.Source_IP && <td className="py-2.5 px-2 font-mono">{threat.record_data.Source_IP}</td>}
                          {threat.record_data?.Destination_IP && <td className="py-2.5 px-2 font-mono">{threat.record_data.Destination_IP}</td>}
                          <td className="py-2.5 px-2">
                            <div className="flex items-center gap-1.5">
                              <button className="text-[10px] text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-0.5">
                                Inspect <ArrowRight size={10} />
                              </button>
                              {onExplainThreat && (
                                <button
                                  onClick={(e) => { e.stopPropagation(); onExplainThreat(threat.id); }}
                                  className="text-[10px] text-violet-400 hover:text-violet-300 font-semibold flex items-center gap-0.5 border-l border-slate-700 pl-1.5"
                                  title="View feature contribution analysis"
                                >
                                  <Microscope size={10} /> Explain
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Incident Details drawer panel */}
          <div className="dark-panel p-6 space-y-5">
            <div className="flex justify-between items-center pb-2 border-b border-slate-800">
              <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">Threat Investigation</h3>
              {selectedThreat && (
                <button onClick={() => setSelectedThreat(null)} className="text-slate-500 hover:text-white">
                  <X size={14} />
                </button>
              )}
            </div>

            {selectedThreat ? (
              <div className="space-y-5 text-xs">
                {/* Meta details */}
                <div className="space-y-1.5 p-3 bg-slate-900 border border-slate-800 rounded">
                  <div className="flex justify-between">
                    <span className="text-slate-500">INCIDENT ID:</span>
                    <span className="font-mono text-white">#{selectedThreat.record_index}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">ATTACK VECTOR:</span>
                    <span className="font-semibold text-rose-400">{selectedThreat.attack_type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">SEVERITY RANK:</span>
                    <span className={`font-bold uppercase ${
                      selectedThreat.severity === 'Critical' ? 'text-red-500' :
                      selectedThreat.severity === 'High' ? 'text-orange-400' :
                      selectedThreat.severity === 'Medium' ? 'text-amber-400' : 'text-emerald-400'
                    }`}>{selectedThreat.severity}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">PROBABILITY CONFIDENCE:</span>
                    <span className="font-mono text-white">{(selectedThreat.confidence * 100).toFixed(1)}%</span>
                  </div>
                </div>

                {/* Explainability bullet points */}
                <div className="space-y-2">
                  <h4 className="text-[10px] font-semibold text-slate-400 font-mono uppercase tracking-wider flex items-center gap-1">
                    <Info size={11} className="text-cyan-500" />
                    Classification Rationale
                  </h4>
                  <div className="p-3 bg-slate-900/50 border border-slate-800/80 rounded space-y-2">
                    <p className="font-semibold text-slate-300 leading-snug">{selectedThreat.explanation?.summary}</p>
                    <ul className="list-disc list-inside space-y-1 font-mono text-[10px] text-slate-400 pl-1.5">
                      {selectedThreat.explanation?.details?.map((detail, dIdx) => (
                        <li key={dIdx} className="leading-relaxed">{detail}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Recommendations */}
                <div className="space-y-2">
                  <h4 className="text-[10px] font-semibold text-slate-400 font-mono uppercase tracking-wider flex items-center gap-1">
                    <Server size={11} className="text-cyan-500" />
                    Recommended Response
                  </h4>
                  <div className="space-y-1.5">
                    {selectedThreat.recommended_actions?.map((action, aIdx) => (
                      <div key={aIdx} className="flex gap-2 p-2 bg-slate-900 border border-slate-800/40 rounded leading-relaxed text-slate-300">
                        <span className="text-rose-500 font-mono font-bold">•</span>
                        <span>{action}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Raw attributes */}
                <div className="space-y-1.5">
                  <h4 className="text-[10px] font-semibold text-slate-400 font-mono uppercase tracking-wider">Raw Telemetry Attributes</h4>
                  <div className="p-3 bg-slate-950 rounded font-mono text-[9px] max-h-36 overflow-y-auto space-y-1 text-slate-400 scrollbar-thin">
                    {Object.entries(selectedThreat.record_data).map(([key, val]) => (
                      <div key={key} className="flex justify-between border-b border-slate-900/40 py-0.5">
                        <span className="text-slate-600 uppercase">{key.replace('_', ' ')}:</span>
                        <span className="text-slate-300 truncate max-w-[150px]">{val === null ? 'NaN' : String(val)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-20 text-slate-500 text-xs">
                Select an incident from the table grid to investigate threat parameters and mitigation guides.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
