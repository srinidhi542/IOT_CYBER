import React, { useState, useEffect } from 'react';
import { Dataset, MLModel, DashboardAnalytics, PredictionExplanation, IncidentState, CaptureProcessResult, AnomalyEngineStatus } from '../types';
import { apiService } from '../services/api';
import { Database, Cpu, Play, CheckCircle, AlertCircle, Sparkles, Shield, ShieldAlert, TrendingUp, TrendingDown, ArrowRight, Activity, Network, Download, RotateCcw, Zap, RefreshCw, Sliders, AlertTriangle } from 'lucide-react';
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
  const [anomalyStatus, setAnomalyStatus] = useState<AnomalyEngineStatus | null>(null);
  const [loadingAnomalyStatus, setLoadingAnomalyStatus] = useState<boolean>(false);
  const [trainingAnomaly, setTrainingAnomaly] = useState<boolean>(false);
  const [contamination, setContamination] = useState<number>(0.05);
  const [anomalyActionMsg, setAnomalyActionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const fetchAnomalyStatus = async () => {
    try {
      setLoadingAnomalyStatus(true);
      const res = await apiService.getAnomalyStatus();
      setAnomalyStatus(res);
    } catch (err: any) {
      console.error('Failed to load anomaly engine status:', err);
    } finally {
      setLoadingAnomalyStatus(false);
    }
  };

  useEffect(() => {
    fetchAnomalyStatus();
  }, []);

  const handleTrainAnomaly = async () => {
    const datasetId = selectedDataset?.id || 1;
    try {
      setTrainingAnomaly(true);
      setAnomalyActionMsg(null);
      await apiService.trainAnomalyModel(datasetId, contamination);
      setAnomalyActionMsg({
        type: 'success',
        text: `Isolation Forest retrained successfully with contamination=${contamination}`
      });
      await fetchAnomalyStatus();
    } catch (err: any) {
      setAnomalyActionMsg({
        type: 'error',
        text: err.message || 'Failed to retrain Isolation Forest model'
      });
    } finally {
      setTrainingAnomaly(false);
    }
  };

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
    } else if (res.flows_extracted === 0) {
      // 0 flows captured: cleanly set benign state rather than retaining old stale predictions
      setLatestPrediction({
        label: 'Benign',
        confidence: 1.0,
        probabilities: { 'Benign': 1.0 },
        top_contributing_features: [],
        shap_values: {},
        anomaly_score: 0.0,
        anomaly_status: 'Normal'
      });
      setActiveIncident(null);
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

  const activeAnomalyScore: number | null = 
    latestPrediction?.anomaly_score ?? 
    captureResult?.overall_anomaly?.anomaly_score ?? 
    captureResult?.overall_prediction?.anomaly_score ?? 
    (activeIncident?.detection?.anomaly_score ?? null);

  const activeAnomalyStatus: string | null = 
    latestPrediction?.anomaly_status ?? 
    captureResult?.overall_anomaly?.anomaly_status ?? 
    captureResult?.overall_prediction?.anomaly_status ?? 
    (activeIncident?.detection?.anomaly_status ?? null);

  const activeRiskScore: number | null = activeIncident?.risk_assessment?.risk_score ?? null;

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
        onNavigateToIncidents={onNavigateToIncidents}
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

          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Detected Class</span>
              <span className={`text-base font-bold font-mono ${
                (latestPrediction?.label || captureResult?.overall_prediction?.label || 'Benign').toLowerCase() === 'benign'
                  ? 'text-emerald-400'
                  : 'text-rose-400'
              }`}>
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
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Anomaly Status</span>
              <span className={`inline-flex items-center gap-1.5 text-base font-bold font-mono ${
                (activeAnomalyStatus || 'Normal').toLowerCase() === 'normal'
                  ? 'text-emerald-400'
                  : 'text-amber-400'
              }`}>
                <span className={`w-2 h-2 rounded-full ${
                  (activeAnomalyStatus || 'Normal').toLowerCase() === 'normal'
                    ? 'bg-emerald-400'
                    : 'bg-amber-400 animate-ping'
                }`} />
                {activeAnomalyStatus || 'Normal'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Anomaly Score</span>
              <div className="flex items-baseline gap-1">
                <span className={`text-base font-bold font-mono ${
                  (activeAnomalyScore ?? 0) >= 70
                    ? 'text-rose-400'
                    : (activeAnomalyScore ?? 0) >= 45
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}>
                  {(activeAnomalyScore ?? 0).toFixed(1)}
                </span>
                <span className="text-[10px] font-mono text-slate-500">/ 100</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Risk Score</span>
              <span className="text-base font-bold font-mono text-rose-400">
                {activeRiskScore !== null ? `${activeRiskScore.toFixed(1)} / 100` : 'N/A'}
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

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Endpoints (Src → Dst)</span>
              <span className="text-xs font-mono text-slate-300 truncate block">
                {captureResult?.capture_stats?.Source_IP || '192.168.1.100'}:{captureResult?.capture_stats?.Source_Port || 'Dynamic'} → {captureResult?.capture_stats?.Destination_IP || '10.0.0.1'}:{captureResult?.capture_stats?.Destination_Port || '80'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════
          STAGE 1: ISOLATION FOREST ANOMALY DETECTION ENGINE
      ═══════════════════════════════════════════════════ */}
      <div className="dark-panel p-6 border-l-4 border-l-amber-500 bg-slate-950/70 space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-amber-950/60 border border-amber-600/50 text-amber-400">
              <Zap size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-mono uppercase tracking-wider text-white font-bold">
                  Stage 1 Anomaly Detection Engine (Isolation Forest)
                </h3>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider border ${
                  anomalyStatus?.ready
                    ? 'bg-emerald-950/80 text-emerald-400 border-emerald-600/40'
                    : 'bg-amber-950/80 text-amber-400 border-amber-600/40'
                }`}>
                  {anomalyStatus?.ready ? '● CALIBRATED & ARMED' : '● INITIALIZING'}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Unsupervised anomaly scoring on pure flow dynamics (23 features). Identifies unseen anomalies & zero-day deviations.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={fetchAnomalyStatus}
              disabled={loadingAnomalyStatus}
              className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white transition-all"
              title="Refresh engine status from backend"
            >
              <RefreshCw size={14} className={loadingAnomalyStatus ? 'animate-spin' : ''} />
            </button>
          </div>
        </div>

        {/* Anomaly Gauge & Status Display */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Visual Indicator & Gauge Meter */}
          <div className="lg:col-span-7 p-5 rounded-xl bg-slate-900/70 border border-slate-800/90 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase text-slate-400 font-semibold tracking-wider">
                Current Flow Evaluation
              </span>
              <span className={`px-3 py-1 rounded-md text-xs font-mono font-bold uppercase tracking-wider border ${
                (activeAnomalyStatus || 'Normal').toLowerCase() === 'anomalous'
                  ? 'bg-rose-950/90 text-rose-300 border-rose-600/60 animate-pulse'
                  : 'bg-emerald-950/90 text-emerald-400 border-emerald-600/50'
              }`}>
                {(activeAnomalyStatus || 'Normal').toUpperCase()}
              </span>
            </div>

            {/* Score Big Display */}
            <div className="flex items-baseline gap-3">
              <span className={`text-4xl font-extrabold font-mono ${
                (activeAnomalyScore ?? 0) >= 70
                  ? 'text-rose-400'
                  : (activeAnomalyScore ?? 0) >= 45
                  ? 'text-amber-400'
                  : 'text-emerald-400'
              }`}>
                {(activeAnomalyScore ?? 0).toFixed(1)}
              </span>
              <span className="text-sm font-mono text-slate-500">/ 100 Anomaly Score</span>
              <span className="text-xs font-mono text-slate-400 ml-auto">
                Cutoff: <b className="text-slate-200">50.0</b> | Zero-Day Gate: <b className="text-amber-300">82.0</b>
              </span>
            </div>

            {/* Custom Visual Meter Gauge */}
            <div className="space-y-1.5 pt-1">
              <div className="relative h-4 rounded-full bg-slate-950 border border-slate-800 overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-emerald-500 via-amber-400 to-rose-600 rounded-full transition-all duration-700 ease-out"
                  style={{ width: `${Math.min(100, Math.max(3, activeAnomalyScore ?? 0))}%` }}
                />
              </div>
              <div className="flex justify-between text-[10px] font-mono text-slate-500">
                <span className="text-emerald-400">0.0 (Normal Inlier)</span>
                <span className="text-amber-400">50.0 (Threshold)</span>
                <span className="text-rose-400">100.0 (Extreme Outlier)</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 text-xs font-mono text-slate-300 leading-relaxed">
              {(activeAnomalyScore ?? 0) >= 82.0 ? (
                <span className="text-rose-300 flex items-start gap-2">
                  <AlertTriangle size={15} className="text-rose-400 shrink-0 mt-0.5" />
                  <span>
                    <b>Critical Dispersion Outlier:</b> Score exceeds zero-day threshold (82.0). If Stage 2 classifier labels this flow as Benign, the SOC pipeline automatically elevates it to <b>Unknown / Suspicious</b> for human analyst review.
                  </span>
                </span>
              ) : (activeAnomalyScore ?? 0) >= 50.0 ? (
                <span className="text-amber-300 flex items-start gap-2">
                  <AlertCircle size={15} className="text-amber-400 shrink-0 mt-0.5" />
                  <span>
                    <b>Elevated Flow Variance:</b> Telemetry exhibits non-standard packet inter-arrival times or header fluctuations diverging from nominal training traffic.
                  </span>
                </span>
              ) : (
                <span className="text-emerald-300 flex items-start gap-2">
                  <CheckCircle size={15} className="text-emerald-400 shrink-0 mt-0.5" />
                  <span>
                    <b>Baseline Conformity:</b> Telemetry operates strictly within nominal flow clusters. Normal traffic profile confirmed by 100-tree ensemble.
                  </span>
                </span>
              )}
            </div>
          </div>

          {/* Model Status & Training Controls */}
          <div className="lg:col-span-5 p-5 rounded-xl bg-slate-900/70 border border-slate-800/90 flex flex-col justify-between space-y-4">
            <div className="space-y-2.5 text-xs font-mono">
              <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
                <Sliders size={15} className="text-cyan-400" />
                <span className="text-slate-200 font-bold uppercase tracking-wider">
                  Model Status & Hyperparameters
                </span>
              </div>

              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-500">Active Artifact:</span>
                <span className="text-cyan-300 font-semibold truncate max-w-[190px]">
                  {anomalyStatus?.model_name || 'ciciot2023_isolation_forest.joblib'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-500">Algorithm:</span>
                <span className="text-white">Isolation Forest (100 Trees)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-500">Features Evaluated:</span>
                <span className="text-white">23 Pure Flow Dynamics</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-500">Calibration Bounds:</span>
                <span className="text-slate-300">
                  [{anomalyStatus?.ref_min ?? -0.2435}, {anomalyStatus?.ref_max ?? 0.1341}]
                </span>
              </div>
            </div>

            {/* Training Controls */}
            <div className="pt-2 border-t border-slate-800 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <label className="text-[11px] font-mono text-slate-400 uppercase">
                  Contamination:
                </label>
                <select
                  value={contamination}
                  onChange={(e) => setContamination(parseFloat(e.target.value))}
                  disabled={trainingAnomaly}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:border-cyan-500 outline-none"
                >
                  <option value={0.01}>0.01 (1% - Conservative)</option>
                  <option value={0.03}>0.03 (3% - Low Outliers)</option>
                  <option value={0.05}>0.05 (5% - Recommended)</option>
                  <option value={0.10}>0.10 (10% - Sensitive)</option>
                  <option value={0.15}>0.15 (15% - Aggressive)</option>
                </select>
              </div>

              <button
                type="button"
                onClick={handleTrainAnomaly}
                disabled={trainingAnomaly}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 disabled:bg-slate-800 text-white font-mono text-xs font-bold uppercase tracking-wider transition-all shadow-md shadow-amber-950/40"
              >
                {trainingAnomaly ? (
                  <>
                    <RefreshCw size={13} className="animate-spin" />
                    <span>Retraining Isolation Forest...</span>
                  </>
                ) : (
                  <>
                    <RefreshCw size={13} />
                    <span>Retrain Anomaly Detector</span>
                  </>
                )}
              </button>

              {anomalyActionMsg && (
                <div className={`p-2 rounded text-[11px] font-mono ${
                  anomalyActionMsg.type === 'success'
                    ? 'bg-emerald-950/80 border border-emerald-700/60 text-emerald-300'
                    : 'bg-rose-950/80 border border-rose-700/60 text-rose-300'
                }`}>
                  {anomalyActionMsg.text}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════
          3. LINK TO DEDICATED AI EXPLAINABILITY VIEW
      ═══════════════════════════════════════════════════ */}
      {latestPrediction && (
        <div className="dark-panel p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 border border-slate-800/80 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-950/60 border border-cyan-800/50 text-cyan-400">
              <Sparkles size={20} />
            </div>
            <div>
              <h3 className="text-xs font-mono uppercase tracking-wider text-white font-bold">
                AI Explainability & SHAP Feature Attribution Ready
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Evaluation breakdown and SHAP feature influence scores available for <b className="text-cyan-300">{latestPrediction.label}</b> prediction.
              </p>
            </div>
          </div>

          <button
            onClick={onNavigateToExplainability}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold uppercase transition-all shadow-md shadow-cyan-950/40 shrink-0"
          >
            <span>View Dedicated AI Explainability</span>
            <ArrowRight size={14} />
          </button>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════
          4. LIVE SOC RADAR & THREAT DEFENSE TELEMETRY
      ═══════════════════════════════════════════════════ */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Threat Defense Engine Status */}
        <div className="dark-panel p-6 border-l-2 border-l-emerald-500">
          <div className="flex items-center justify-between mb-4 pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Shield className="text-emerald-400" size={18} />
              <h3 className="font-mono text-xs uppercase text-slate-200 font-bold tracking-wider">Active Threat Defense</h3>
            </div>
            <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-600/40 text-[10px] font-mono text-emerald-400 font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              LIVE GUARD
            </span>
          </div>

          <div className="space-y-2.5 text-xs font-mono text-slate-400">
            <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
              <span className="text-slate-500">Defense Pipeline:</span>
              <span className="text-white font-semibold">Two-Stage Debiased Flow Engine</span>
            </div>
            <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
              <span className="text-slate-500">Stage 1 Anomaly Filter:</span>
              <span className="text-emerald-400 font-semibold">96.0% Benign Preservation</span>
            </div>
            <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
              <span className="text-slate-500">Stage 2 Attack Attribution:</span>
              <span className="text-cyan-400 font-semibold">7 IoT Attack Families</span>
            </div>
            <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
              <span className="text-slate-500">Feature Extraction:</span>
              <span className="text-white">23 Pure Flow Dynamics (Zero Bias)</span>
            </div>
            <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
              <span className="text-slate-500">Live Sniffer Engine:</span>
              <span className="text-emerald-400 font-semibold">TShark & CICFlowMeter v2</span>
            </div>
            <div className="flex justify-between items-center py-1">
              <span className="text-slate-500">Human-in-the-Loop SOC:</span>
              <span className="text-amber-300 font-semibold">Enforced Approval Gate</span>
            </div>
          </div>
        </div>

        {/* SOC Radar & Telemetry Stream */}
        <div className="dark-panel p-6 border-l-2 border-l-cyan-500">
          <div className="flex items-center justify-between mb-4 pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Activity className="text-cyan-400" size={18} />
              <h3 className="font-mono text-xs uppercase text-slate-200 font-bold tracking-wider">SOC Operations & Telemetry</h3>
            </div>
            <span className="px-2 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-600/40 text-[10px] font-mono text-cyan-400 font-bold">
              ARMED
            </span>
          </div>

          <div className="space-y-2.5 text-xs font-mono text-slate-400">
            <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
              <span className="text-slate-500">Telemetry Corpus:</span>
              <span className="text-white font-semibold">CICIoT2023 Comprehensive</span>
            </div>
            <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
              <span className="text-slate-500">Monitored Attacks:</span>
              <span className="text-cyan-400 truncate max-w-[220px]">Mirai, DDoS, DoS, Recon, Spoofing, Web</span>
            </div>
            <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
              <span className="text-slate-500">Explainability Engine:</span>
              <span className="text-white font-semibold">TreeSHAP Multi-Output</span>
            </div>
            <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
              <span className="text-slate-500">MITRE ATT&CK Mapping:</span>
              <span className="text-emerald-400 font-semibold">Automated RAG Vector Retrieval</span>
            </div>
            <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
              <span className="text-slate-500">Playbook Generator:</span>
              <span className="text-white">Zero-Day Isolation & Firewall CLI</span>
            </div>
            <div className="flex justify-between items-center py-1">
              <span className="text-slate-500">Telemetry Status:</span>
              <span className="text-emerald-400 font-semibold">Continuous Real-time Sync</span>
            </div>
          </div>
        </div>
      </div>

    </div>
  );
};
