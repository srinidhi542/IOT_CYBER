import React, { useState } from 'react';
import { Dataset, MLModel, DashboardAnalytics, PredictionExplanation } from '../types';
import { apiService } from '../services/api';
import { Database, Cpu, Activity, Play, CheckCircle, AlertCircle, Sparkles } from 'lucide-react';

interface DashboardProps {
  analytics: DashboardAnalytics | null;
  loading: boolean;
  refreshData: () => void;
  selectedDataset: Dataset | null;
  selectedModel: MLModel | null;
  latestPrediction: PredictionExplanation | null;
  setLatestPrediction: (p: PredictionExplanation | null) => void;
  onNavigateToExplainability: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ analytics, loading, selectedDataset, selectedModel, latestPrediction, setLatestPrediction, onNavigateToExplainability }) => {
  const defaultTestRecord = `{
  "Header_Length": 13.2,
  "Protocol Type": 17,
  "Time_To_Live": 111.8,
  "Rate": 100.0,
  "fin_flag_number": 0,
  "syn_flag_number": 0,
  "rst_flag_number": 0,
  "psh_flag_number": 0,
  "ack_flag_number": 0,
  "ece_flag_number": 0,
  "cwr_flag_number": 0,
  "ack_count": 0,
  "syn_count": 0,
  "fin_count": 0,
  "rst_count": 0,
  "HTTP": 0,
  "HTTPS": 0,
  "DNS": 0,
  "Telnet": 0,
  "SMTP": 0,
  "SSH": 0,
  "IRC": 0,
  "TCP": 0,
  "UDP": 1,
  "DHCP": 0,
  "ARP": 0,
  "ICMP": 0,
  "IGMP": 0,
  "IPv": 1,
  "LLC": 1,
  "Tot sum": 1000,
  "Min": 50,
  "Max": 1500,
  "AVG": 500,
  "Std": 100,
  "Tot size": 2000,
  "IAT": 0.05,
  "Number": 10,
  "Variance": 172681.38
}`;
  const [testRecord, setTestRecord] = useState<string>(defaultTestRecord);
  const [predicting, setPredicting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handlePredict = async () => {
    try {
      setPredicting(true);
      setErrorMsg(null);
      setLatestPrediction(null);
      const record = JSON.parse(testRecord);
      const data = await apiService.explainPrediction(record);
      setLatestPrediction(data);
    } catch (err: any) {
      setErrorMsg(err.message || "Invalid JSON or network error");
    } finally {
      setPredicting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-[70vh] gap-4">
        <div className="w-10 h-10 rounded-full border-4 border-slate-900 border-t-cyan-500 animate-spin" />
        <p className="text-slate-600 font-mono text-[10px] tracking-widest animate-pulse-subtle">ACQUIRING TELEMETRY…</p>
      </div>
    );
  }

  const modelReady = selectedModel && selectedModel.model_type === 'classifier';

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Dataset Info */}
        <div className="dark-panel p-6">
          <div className="flex items-center gap-2 mb-4">
            <Database className="text-cyan-500" size={20} />
            <h3 className="font-mono text-xs uppercase text-slate-300">Dataset Status</h3>
          </div>
          {selectedDataset ? (
            <div className="space-y-2 text-sm text-slate-400">
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Name:</span> <span className="text-white">{selectedDataset.name}</span>
              </div>
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Status:</span> <span className="text-emerald-400">{selectedDataset.status}</span>
              </div>
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Rows:</span> <span className="text-white">{selectedDataset.row_count}</span>
              </div>
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Features:</span> <span className="text-white">{selectedDataset.col_count}</span>
              </div>
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Target:</span> <span className="text-white">{selectedDataset.target_column}</span>
              </div>
              {selectedDataset.class_distribution && (
                <div className="mt-2 text-xs font-mono">
                  <span className="block mb-1">Class Distribution:</span>
                  {Object.entries(selectedDataset.class_distribution).map(([k, v]) => (
                    <div key={k} className="flex justify-between">
                      <span className="text-slate-500">{k}</span>
                      <span className="text-cyan-400">{v}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <p className="text-slate-500 text-sm">No dataset loaded.</p>
          )}
        </div>

        {/* Model Info */}
        <div className="dark-panel p-6">
          <div className="flex items-center gap-2 mb-4">
            <Cpu className="text-purple-500" size={20} />
            <h3 className="font-mono text-xs uppercase text-slate-300">Model Status</h3>
          </div>
          {selectedModel ? (
            <div className="space-y-2 text-sm text-slate-400">
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Algorithm:</span> <span className="text-white">{selectedModel.algorithm}</span>
              </div>
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Status:</span> <span className="text-emerald-400">Trained</span>
              </div>
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Accuracy:</span> <span className="text-white font-semibold">{((selectedModel.accuracy || 0) * 100).toFixed(2)}%</span>
              </div>
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Weighted F1:</span> <span className="text-cyan-400 font-semibold">{(((selectedModel.metrics_json?.weighted_f1 ?? selectedModel.f1_score) || 0) * 100).toFixed(2)}%</span>
              </div>
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Macro F1:</span> <span className="text-cyan-400 font-semibold">{(((selectedModel.metrics_json?.macro_f1 ?? selectedModel.f1_score) || 0) * 100).toFixed(2)}%</span>
              </div>
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Precision:</span> <span className="text-white">{((selectedModel.precision_score || 0) * 100).toFixed(2)}%</span>
              </div>
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Recall:</span> <span className="text-white">{((selectedModel.recall_score || 0) * 100).toFixed(2)}%</span>
              </div>
            </div>
          ) : (
            <p className="text-slate-500 text-sm">No model trained.</p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix */}
        <div className="dark-panel p-6 overflow-auto">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="text-rose-500" size={20} />
            <h3 className="font-mono text-xs uppercase text-slate-300">Confusion Matrix</h3>
          </div>
          {selectedModel && selectedModel.confusion_matrix && selectedModel.classes ? (
            <table className="w-full text-xs font-mono text-center">
              <thead>
                <tr>
                  <th className="p-2 border border-slate-800 bg-slate-900 text-slate-500">Actual \ Pred</th>
                  {selectedModel.classes.map(c => <th key={c} className="p-2 border border-slate-800 text-slate-300">{c}</th>)}
                </tr>
              </thead>
              <tbody>
                {selectedModel.confusion_matrix.map((row, i) => (
                  <tr key={i}>
                    <td className="p-2 border border-slate-800 font-bold text-slate-300">{selectedModel.classes![i]}</td>
                    {row.map((val, j) => (
                      <td key={j} className={`p-2 border border-slate-800 ${i === j && val > 0 ? 'bg-emerald-900/30 text-emerald-400' : val > 0 ? 'bg-rose-900/30 text-rose-400' : 'text-slate-600'}`}>
                        {val}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-slate-500 text-sm">Matrix not available.</p>
          )}
        </div>

        {/* Prediction Section */}
        <div className="dark-panel p-6">
          <div className="flex items-center gap-2 mb-4">
            <Play className="text-emerald-500" size={20} />
            <h3 className="font-mono text-xs uppercase text-slate-300">Test Prediction & SHAP Explainability</h3>
          </div>
          <div className="space-y-4">
            <div>
              <label className="text-xs font-mono text-slate-500 mb-2 block">Network Record (JSON):</label>
              <textarea
                value={testRecord}
                onChange={e => setTestRecord(e.target.value)}
                className="w-full h-32 bg-slate-900 border border-slate-800 rounded p-3 text-xs font-mono text-slate-300 focus:border-cyan-500 focus:outline-none"
                placeholder='{"feature1": 1.0, ...}'
              />
            </div>
            <button
              onClick={handlePredict}
              disabled={predicting || !modelReady}
              className="w-full bg-cyan-600 hover:bg-cyan-500 text-white rounded py-2 text-xs font-mono font-bold uppercase transition-colors disabled:opacity-50 flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/40"
            >
              {predicting ? (
                <>
                  <div className="w-3.5 h-3.5 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  <span>Computing SHAP Tree Attribution...</span>
                </>
              ) : (
                <>
                  <Sparkles size={14} />
                  <span>RUN PREDICTION</span>
                </>
              )}
            </button>
            {errorMsg && (
              <div className="text-rose-400 text-xs font-mono bg-rose-900/20 p-2.5 rounded border border-rose-800/40 flex items-center gap-2">
                <AlertCircle size={14} className="shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}

            {latestPrediction ? (
              <div className="space-y-3 pt-1">
                {/* Compact Prediction Result */}
                <div className="bg-slate-900/90 border border-emerald-800/50 p-4 rounded-lg text-xs font-mono">
                  <div className="flex justify-between items-center mb-2.5 pb-2 border-b border-slate-800/80">
                    <span className="text-slate-400">Predicted Attack Family:</span>
                    <span className="text-emerald-400 font-bold text-sm px-2.5 py-0.5 rounded bg-emerald-950/80 border border-emerald-700/50 tracking-wider">
                      {latestPrediction.label}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Classification Confidence:</span>
                    <span className="text-cyan-400 font-bold text-sm">
                      {(latestPrediction.confidence * 100).toFixed(2)}%
                    </span>
                  </div>
                </div>

                {/* Navigate to AI Explainability */}
                <button
                  onClick={onNavigateToExplainability}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-slate-900 border border-cyan-800/50 hover:border-cyan-500 hover:bg-cyan-950/30 text-cyan-400 hover:text-cyan-300 text-xs font-mono font-semibold uppercase transition-all group"
                >
                  <Sparkles size={14} className="group-hover:scale-110 transition-transform" />
                  <span>View AI Explanation & Attack Analysis</span>
                  <CheckCircle size={13} className="text-emerald-400 ml-auto" />
                </button>
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-slate-900/40 border border-dashed border-slate-800 text-center py-6 text-slate-500 text-xs font-mono">
                <Sparkles size={20} className="mx-auto text-slate-600 mb-2 opacity-60" />
                <span>Run a prediction to generate SHAP explanation.</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

