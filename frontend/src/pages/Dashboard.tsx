import React, { useState } from 'react';
import { Dataset, MLModel, DashboardAnalytics, PredictionExplanation, IncidentState, CaptureProcessResult } from '../types';
import { apiService } from '../services/api';
import { Database, Cpu, Play, CheckCircle, AlertCircle, Sparkles, Shield, ShieldAlert, TrendingUp, TrendingDown, ArrowRight, Activity, Network, Download, RotateCcw } from 'lucide-react';
import { PacketCapturePanel } from '../components/soc/PacketCapturePanel';

interface DashboardProps {
  analytics: DashboardAnalytics | null;
  loading: boolean;
  refreshData: () => void;
  selectedDataset: Dataset | null;
  selectedModel: MLModel | null;
  latestPrediction: PredictionExplanation | null;
  setLatestPrediction: (p: PredictionExplanation | null) => void;
  captureResult: CaptureProcessResult | null;
  setCaptureResult: (res: CaptureProcessResult | null) => void;
  onResetDetection: () => void;
  onNavigateToExplainability: () => void;
  onNavigateToIncidents: () => void;
  activeIncident: IncidentState | null;
  setActiveIncident: (inc: IncidentState | null) => void;
  setIncidentsList: React.Dispatch<React.SetStateAction<IncidentState[]>>;
}

const FEATURE_EXPLANATIONS: Record<string, string> = {
  'Rate': 'Packet rate per second. Sudden surges indicate automated flooding or scanning volume.',
  'Header_Length': 'Byte length of network packet headers. Irregular lengths indicate crafted or tunneled traffic.',
  'Time_To_Live': 'TTL hops remaining. Deviations indicate spoofed origins or routing manipulation.',
  'Protocol Type': 'Transport layer protocol numerical identifier (e.g. 6 for TCP, 17 for UDP).',
  'Variance': 'Packet size variance. Uniform or zero variance indicates automated flood scripting.',
  'Tot sum': 'Total accumulated byte payload across the bidirectional communication flow.',
  'Tot size': 'Aggregate byte size of packet headers and payload in the session.',
  'IAT': 'Inter-arrival time between packets. Abnormally low IAT indicates machine-speed packet blasting.',
  'Number': 'Total count of packets observed within this bidirectional flow window.',
  'AVG': 'Average packet size in bytes. Disproportionate averages reveal buffer exhaustion attempts.',
  'Std': 'Standard deviation of packet lengths. High variance suggests mixed command-and-control payloads.',
  'Min': 'Minimum observed packet length in bytes across the flow.',
  'Max': 'Maximum observed packet length in bytes across the flow.',
  'UDP': 'UDP datagram traffic indicator. Commonly abused in amplification and reflection DDoS.',
  'TCP': 'TCP stream indicator. Monitored for handshake anomalies and flag weaponization.',
  'HTTP': 'HTTP web application traffic indicator. Vulnerable to injection and path traversal.',
  'HTTPS': 'Encrypted TLS/SSL traffic indicator. Monitored for covert data exfiltration.',
  'DNS': 'Domain Name System port 53 query activity indicator.',
  'Telnet': 'Unencrypted remote shell management port 23 indicator. Prime target for Mirai botnet.',
  'SSH': 'Secure shell management port 22 indicator. Target for automated brute force.',
  'syn_flag_number': 'SYN flag presence. High ratio without ACK indicates SYN-flood resource starvation.',
  'ack_flag_number': 'ACK flag presence. Essential for tracking established connection states.',
  'rst_flag_number': 'RST connection reset flag. Abrupt resets signify scanner probes or server termination.',
  'fin_flag_number': 'FIN graceful connection close flag.',
  'psh_flag_number': 'PSH push flag indicating immediate data transmission to application buffers.'
};

export const Dashboard: React.FC<DashboardProps> = ({ 
  analytics, 
  loading, 
  selectedDataset, 
  selectedModel, 
  latestPrediction, 
  setLatestPrediction, 
  captureResult,
  setCaptureResult,
  onResetDetection,
  onNavigateToExplainability,
  onNavigateToIncidents,
  activeIncident,
  setActiveIncident,
  setIncidentsList
}) => {
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
  const [isProcessingSoc, setIsProcessingSoc] = useState<boolean>(false);

  const handlePredict = async () => {
    try {
      setPredicting(true);
      setErrorMsg(null);
      setLatestPrediction(null);
      setCaptureResult(null);
      setIsProcessingSoc(true);
      const record = JSON.parse(testRecord);

      // 1. Run detection explainability directly on the record
      const data = await apiService.explainPrediction(record);
      setLatestPrediction(data);

      // 2. Automatically process through full Multi-Agent SOC Pipeline
      const incident = await apiService.analyzeFlow(record);
      setActiveIncident(incident);
      setIncidentsList(prev => [incident, ...prev.filter(i => i.incident_id !== incident.incident_id)]);
    } catch (err: any) {
      setErrorMsg(err.message || "Invalid JSON or network error");
    } finally {
      setPredicting(false);
      setIsProcessingSoc(false);
    }
  };

  const handleCaptureProcessed = (res: CaptureProcessResult) => {
    setCaptureResult(res);
    if (res.overall_explainability) {
      setLatestPrediction(res.overall_explainability);
    }
    if (res.overall_incident) {
      setActiveIncident(res.overall_incident);
      setIncidentsList(prev => [res.overall_incident!, ...prev.filter(i => i.incident_id !== res.overall_incident!.incident_id)]);
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
  const maxShap = latestPrediction?.top_contributing_features
    ? Math.max(...latestPrediction.top_contributing_features.map(f => Math.abs(f.shap_value)), 0.001)
    : 1;

  return (
    <div className="space-y-8">
      {/* ═══════════════════════════════════════════════════
          1. NETWORK PACKET CAPTURE & PCAP INGESTION
      ═══════════════════════════════════════════════════ */}
      <PacketCapturePanel
        onIncidentsGenerated={(incs) => {
          if (incs && incs.length > 0) {
            setIncidentsList(incs);
            setActiveIncident(incs[0]);
          }
        }}
        onSingleIncidentGenerated={(inc) => {
          setActiveIncident(inc);
          setIncidentsList(prev => [inc, ...prev.filter(i => i.incident_id !== inc.incident_id)]);
        }}
        onCaptureProcessed={handleCaptureProcessed}
        isProcessing={isProcessingSoc}
        setIsProcessing={setIsProcessingSoc}
      />

      {/* ═══════════════════════════════════════════════════
          2. OVERALL TRAFFIC PREDICTION & TELEMETRY SUMMARY
      ═══════════════════════════════════════════════════ */}
      {(latestPrediction || captureResult) && (
        <div className="dark-panel p-6 border-l-4 border-l-cyan-500 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
            <div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
                <h3 className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold">
                  Overall Captured Network Assessment
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Aggregated 39-feature statistical profile analyzed across all captured flows through the 8-class XGBoost model.
              </p>
            </div>

            <div className="flex items-center gap-2.5 flex-wrap">
              <button
                onClick={onResetDetection}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-750 hover:border-slate-500 text-slate-300 hover:text-white font-mono text-xs font-semibold uppercase tracking-wider transition-all shadow-md shrink-0"
                title="Reset detection results and clear telemetry"
              >
                <RotateCcw size={13} className="text-slate-400" />
                <span>Reset Detection</span>
              </button>

              {activeIncident && (
                <>
                  {activeIncident.report && (
                    <button
                      onClick={() => {
                        const blob = new Blob([activeIncident.report!.markdown_content], { type: 'text/markdown;charset=utf-8' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `incident_report_${activeIncident.incident_id}.md`;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                      }}
                      className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold uppercase tracking-wider transition-all shadow-lg shadow-cyan-950/40 shrink-0"
                      title="Download structured Markdown SOC incident report"
                    >
                      <Download size={14} />
                      <span>Download Report (.md)</span>
                    </button>
                  )}
                  <button
                    onClick={onNavigateToIncidents}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-rose-950/80 border border-rose-600/70 hover:bg-rose-900 text-rose-200 font-mono text-xs font-semibold uppercase tracking-wider transition-all shadow-lg shadow-rose-950/40 shrink-0"
                  >
                    <ShieldAlert size={14} className="text-rose-400" />
                    <span>Open SOC Incident & Response Playbook</span>
                    <ArrowRight size={14} className="ml-1" />
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-4">
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Detected Class</span>
              <span className="text-base font-bold font-mono text-emerald-400">
                {latestPrediction?.label || captureResult?.overall_prediction?.label || 'Benign'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Confidence</span>
              <span className="text-base font-bold font-mono text-cyan-400">
                {((latestPrediction?.confidence || captureResult?.overall_prediction?.confidence || 0) * 100).toFixed(2)}%
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Extracted Flows</span>
              <span className="text-base font-bold font-mono text-white">
                {captureResult?.flows_extracted || captureResult?.capture_stats?.total_flows || '1'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Primary Protocol</span>
              <span className="text-base font-bold font-mono text-slate-300">
                {captureResult?.capture_stats?.Protocol_Name || (latestPrediction as any)?.raw_record?.Protocol_Name || 'TCP/UDP'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 col-span-2">
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Endpoints (Src → Dst)</span>
              <span className="text-xs font-mono text-slate-300 truncate block">
                {captureResult?.capture_stats?.Source_IP || '192.168.1.100'}:{captureResult?.capture_stats?.Source_Port || 'Dynamic'} → {captureResult?.capture_stats?.Destination_IP || '10.0.0.1'}:{captureResult?.capture_stats?.Destination_Port || '80'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════
          3. EMBEDDED AI EXPLAINABILITY (SHAP ATTRIBUTION)
      ═══════════════════════════════════════════════════ */}
      {latestPrediction && (
        <div className="dark-panel p-6 space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
            <div>
              <div className="flex items-center gap-2">
                <Sparkles size={16} className="text-cyan-400" />
                <h3 className="text-xs font-mono uppercase tracking-wider text-white font-bold">
                  AI Explainability (SHAP Tree Attribution on Captured Traffic)
                </h3>
                <span className="px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/50 text-[9px] font-mono text-cyan-400">
                  SHAP TreeExplainer
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Real-time feature impact attributions driving the model's classification for this captured traffic.
              </p>
            </div>

            <button
              onClick={onNavigateToExplainability}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 transition-colors"
            >
              <span>Full Threat Intelligence Knowledge Base</span>
              <ArrowRight size={13} />
            </button>
          </div>

          {/* Top Contributing Features Visualizer */}
          <div className="space-y-3">
            <h4 className="text-[10px] font-mono uppercase tracking-widest text-slate-500">
              Top Traffic Features Driving Classification ({latestPrediction.label})
            </h4>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {latestPrediction.top_contributing_features.map((feat, idx) => {
                const isPositive = feat.direction === 'increases';
                const barWidth = Math.min(100, Math.max(8, (Math.abs(feat.shap_value) / maxShap) * 100));
                const explanation = FEATURE_EXPLANATIONS[feat.feature] || 'Observed network flow metric evaluated by the tuned XGBoost model.';

                return (
                  <div 
                    key={idx} 
                    className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800/80 hover:border-slate-700 transition-all space-y-2"
                  >
                    <div className="flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-200 font-bold">{feat.feature}</span>
                        <span className="text-slate-500 text-[10px]">val: <b className="text-slate-300">{feat.value}</b></span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        {isPositive ? (
                          <span className="flex items-center gap-1 text-[10px] text-rose-400 font-bold bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800/40">
                            <TrendingUp size={11} />
                            <span>+{feat.shap_value.toFixed(3)} (Pushes Threat)</span>
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-[10px] text-cyan-400 font-bold bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
                            <TrendingDown size={11} />
                            <span>{feat.shap_value.toFixed(3)} (Pulls Benign)</span>
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Horizontal Bar */}
                    <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden flex">
                      <div
                        className={`h-full rounded-full transition-all duration-700 ${
                          isPositive 
                            ? 'bg-gradient-to-r from-amber-500 to-rose-500' 
                            : 'bg-gradient-to-r from-blue-500 to-cyan-400'
                        }`}
                        style={{ width: `${barWidth}%` }}
                      />
                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed font-light">
                      {explanation}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Probabilities Distribution */}
          {latestPrediction.probabilities && (
            <div className="pt-2 border-t border-slate-800/60">
              <span className="text-[10px] font-mono uppercase tracking-widest text-slate-500 block mb-2">
                Class Probability Distribution Across 8 Attack Families
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 font-mono text-[10px]">
                {Object.entries(latestPrediction.probabilities).map(([cls, prob]) => {
                  const pct = (prob * 100).toFixed(1);
                  const isTop = cls === latestPrediction.label;
                  return (
                    <div 
                      key={cls} 
                      className={`p-2 rounded text-center border transition-all ${
                        isTop 
                          ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200 font-bold' 
                          : 'bg-slate-900/50 border-slate-800/80 text-slate-400'
                      }`}
                    >
                      <span className="block truncate font-semibold" title={cls}>{cls}</span>
                      <span className={isTop ? 'text-cyan-300 font-bold' : 'text-slate-500'}>{pct}%</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══════════════════════════════════════════════════
          4. EXISTING DATASET & MODEL STATUS OVERVIEW
      ═══════════════════════════════════════════════════ */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Dataset Info */}
        <div className="dark-panel p-6">
          <div className="flex items-center gap-2 mb-4">
            <Database className="text-cyan-500" size={20} />
            <h3 className="font-mono text-xs uppercase text-slate-300 font-bold">Dataset Status</h3>
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
            <h3 className="font-mono text-xs uppercase text-slate-300 font-bold">Model Status</h3>
          </div>
          {selectedModel ? (
            <div className="space-y-2 text-sm text-slate-400">
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Algorithm:</span> <span className="text-white">{selectedModel.algorithm}</span>
              </div>
              <div className="flex justify-between border-b border-slate-800 pb-1">
                <span>Status:</span> <span className="text-emerald-400">Trained & Active</span>
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

      {/* ═══════════════════════════════════════════════════
          5. MANUAL RECORD TESTING (OPTIONAL JSON TESTING)
      ═══════════════════════════════════════════════════ */}
      <div className="dark-panel p-6">
        <div className="flex items-center gap-2 mb-4">
          <Play className="text-emerald-500" size={20} />
          <h3 className="font-mono text-xs uppercase text-slate-300 font-bold">
            Manual Network Record Testing & Attribution
          </h3>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs font-mono text-slate-500 mb-2 block">
              Network Record (JSON 39 features):
            </label>
            <textarea
              value={testRecord}
              onChange={e => setTestRecord(e.target.value)}
              className="w-full h-28 bg-slate-900 border border-slate-800 rounded p-3 text-xs font-mono text-slate-300 focus:border-cyan-500 focus:outline-none"
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
                <span>Computing SHAP Attribution & Multi-Agent SOC Assessment...</span>
              </>
            ) : (
              <>
                <Sparkles size={14} />
                <span>EVALUATE RECORD & UPDATE EXPLAINABILITY</span>
              </>
            )}
          </button>
          {errorMsg && (
            <div className="text-rose-400 text-xs font-mono bg-rose-900/20 p-2.5 rounded border border-rose-800/40 flex items-center gap-2">
              <AlertCircle size={14} className="shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
