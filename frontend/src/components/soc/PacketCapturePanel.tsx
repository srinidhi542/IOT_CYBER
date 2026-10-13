import React, { useState, useEffect, useRef } from 'react';
import { apiService } from '../../services/api';
import { NetworkInterface, CaptureStatus, IncidentState, CaptureProcessResult } from '../../types';
import { 
  Wifi, 
  Play, 
  Square, 
  Upload, 
  Radio, 
  CheckCircle, 
  AlertTriangle, 
  Sparkles, 
  ShieldAlert, 
  Terminal,
  Clock,
  HardDrive,
  RotateCw,
  Download,
  ArrowRight
} from 'lucide-react';

interface PacketCapturePanelProps {
  onIncidentsGenerated: (incidents: IncidentState[]) => void;
  onSingleIncidentGenerated: (incident: IncidentState) => void;
  onCaptureProcessed?: (result: CaptureProcessResult) => void;
  isProcessing: boolean;
  setIsProcessing: (v: boolean) => void;
  onNavigateToIncidents?: () => void;
}

export const PacketCapturePanel: React.FC<PacketCapturePanelProps> = ({
  onIncidentsGenerated,
  onSingleIncidentGenerated,
  onCaptureProcessed,
  isProcessing,
  setIsProcessing,
  onNavigateToIncidents
}) => {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedIface, setSelectedIface] = useState<string>('');
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus | null>(null);
  const [capturing, setCapturing] = useState<boolean>(false);
  const [durationTimer, setDurationTimer] = useState<number>(0);
  const [captureDurationLimit, setCaptureDurationLimit] = useState<number>(10);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadedPcapPath, setUploadedPcapPath] = useState<string | null>(null);
  const [loadingInterfaces, setLoadingInterfaces] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [processingStatus, setProcessingStatus] = useState<string | null>(null);
  const [processedResult, setProcessedResult] = useState<CaptureProcessResult | null>(null);
  const timerRef = useRef<any>(null);

  // Load interfaces and initial status
  useEffect(() => {
    loadInterfaces();
    checkStatus();
  }, []);

  const loadInterfaces = async () => {
    setLoadingInterfaces(true);
    try {
      const list = await apiService.getCaptureInterfaces();
      setInterfaces(list);

      // Check if user configured a persistent default in Settings
      let defaultFromSettings = '';
      try {
        const platformSettings = await apiService.getPlatformSettings();
        if (platformSettings?.settings?.network_capture?.default_interface) {
          defaultFromSettings = platformSettings.settings.network_capture.default_interface;
        }
      } catch (err) {
        // Fallback silently if settings endpoint not ready
      }

      if (list.length > 0) {
        const match = list.find(i => i.name === defaultFromSettings);
        if (match) {
          setSelectedIface(match.name);
        } else {
          // Prioritize active Wi-Fi or physical Ethernet over virtual adapters like "Local Area Connection* 2"
          const wifiOrEthernet = list.find(i => i.is_up && !i.is_loopback && (i.name.toLowerCase().includes('wi-fi') || i.name.toLowerCase().includes('wifi') || i.name.toLowerCase() === 'ethernet'));
          const best = wifiOrEthernet || list.find(i => i.is_up && !i.is_loopback && !i.name.includes('*')) || list.find(i => i.is_up && !i.is_loopback) || list[0];
          setSelectedIface(best.name);
        }
      }
    } catch (e: any) {
      console.warn("Failed to enumerate network interfaces:", e);
      // Auto-retry after 3s if backend was still starting up
      setTimeout(() => {
        loadInterfaces();
      }, 3000);
    } finally {
      setLoadingInterfaces(false);
    }
  };

  const checkStatus = async () => {
    try {
      const st = await apiService.getCaptureStatus();
      setCaptureStatus(st);
      setCapturing(st.is_capturing);
      if (st.is_capturing) {
        setDurationTimer(st.duration);
      }
    } catch (e) {
      // silent
    }
  };

  // Timer while capturing with auto-stop support
  useEffect(() => {
    if (capturing) {
      timerRef.current = setInterval(() => {
        setDurationTimer(prev => prev + 1);
      }, 1000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [capturing]);

  useEffect(() => {
    if (capturing && captureDurationLimit > 0 && durationTimer >= captureDurationLimit) {
      handleStopAndAnalyze();
    }
  }, [capturing, durationTimer, captureDurationLimit]);

  const handleStartCapture = async () => {
    try {
      setErrorMsg(null);
      setSuccessMsg(null);
      setDurationTimer(0);
      const res = await apiService.startCapture(selectedIface || "Default", captureDurationLimit, 0);
      setCapturing(true);
      setCaptureStatus(res as any);
      setSuccessMsg(`Capture initiated on adapter: ${selectedIface || "Default"}${captureDurationLimit > 0 ? ` (Auto-stop in ${captureDurationLimit}s)` : ''}`);
    } catch (err: any) {
      const msg = err.message || "";
      if (msg.includes("ECONNREFUSED") || msg.includes("Failed to fetch") || msg.includes("proxy error")) {
        setErrorMsg("Backend server is starting up or unavailable. Please wait a few seconds and try again.");
      } else {
        setErrorMsg(msg || "Failed to start capture");
      }
    }
  };

  const handleStopAndAnalyze = async () => {
    try {
      setIsProcessing(true);
      setErrorMsg(null);
      setSuccessMsg(null);
      setCapturing(false);
      setProcessingStatus("Stopping live packet capture & generating PCAP trace...");
      const stopRes = await apiService.stopCapture();
      setCaptureStatus(stopRes as any);

      const pcapFile = stopRes.output_pcap;
      if (pcapFile) {
        setProcessingStatus(`Extracting 39-feature flows from ${stopRes.packet_count || 0} packets & running 6-Agent AI SOC pipeline...`);
        const procResult = await apiService.processPcap(pcapFile, 6);
        setProcessedResult(procResult);
        if (onCaptureProcessed) {
          onCaptureProcessed(procResult);
        }
        if (procResult.overall_incident) {
          onSingleIncidentGenerated(procResult.overall_incident);
        }
        if (procResult.incidents && procResult.incidents.length > 0) {
          onIncidentsGenerated(procResult.incidents);
          setSuccessMsg(`Analysis complete: Extracted ${procResult.flows_extracted} flows (${procResult.packets_analyzed || stopRes.packet_count || 0} packets). Classified as ${procResult.overall_prediction?.label || 'Analyzed'}.`);
        } else if (procResult.flows_extracted === 0) {
          setSuccessMsg(`Captured ${stopRes.packet_count || 0} packets (0 active flows). No malicious activity detected (Benign).`);
        } else {
          setSuccessMsg(`Analysis complete: Extracted ${procResult.flows_extracted} flows. Classified as ${procResult.overall_prediction?.label || 'Benign'}.`);
        }
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Capture processing failed");
    } finally {
      setIsProcessing(false);
      setProcessingStatus(null);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const file = e.target.files[0];
    setSelectedFile(file);
    setProcessedResult(null);
    try {
      setIsProcessing(true);
      setErrorMsg(null);
      setSuccessMsg(null);
      setProcessingStatus(`Uploading ${file.name}...`);
      const res = await apiService.uploadPcap(file);
      setUploadedPcapPath(res.filepath);
      setSuccessMsg(`Uploaded ${file.name} (${(res.file_size / 1024).toFixed(1)} KB) successfully. Ready to process through SOC.`);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to upload PCAP file");
    } finally {
      setIsProcessing(false);
      setProcessingStatus(null);
    }
  };

  const handleAnalyzeUploadedPcap = async () => {
    if (!uploadedPcapPath) return;
    try {
      setIsProcessing(true);
      setErrorMsg(null);
      setSuccessMsg(null);
      setProcessingStatus(`Executing CICFlowMeter extraction & 6-Agent AI SOC Pipeline on ${selectedFile?.name || 'PCAP'}...`);
      const procResult = await apiService.processPcap(uploadedPcapPath, 6);
      setProcessedResult(procResult);
      if (onCaptureProcessed) {
        onCaptureProcessed(procResult);
      }
      if (procResult.overall_incident) {
        onSingleIncidentGenerated(procResult.overall_incident);
      }
      if (procResult.incidents && procResult.incidents.length > 0) {
        onIncidentsGenerated(procResult.incidents);
        setSuccessMsg(`Analysis complete for ${selectedFile?.name || 'PCAP'}: Parsed ${procResult.flows_extracted} flows (${procResult.packets_analyzed || 0} packets). Classified as ${procResult.overall_prediction?.label || 'Analyzed'}.`);
      } else {
        setSuccessMsg(`Analysis complete for ${selectedFile?.name || 'PCAP'}: Parsed ${procResult.flows_extracted} flows. Classified as ${procResult.overall_prediction?.label || 'Benign'}.`);
      }
    } catch (err: any) {
      setErrorMsg(err.message || "PCAP processing failed");
    } finally {
      setIsProcessing(false);
      setProcessingStatus(null);
    }
  };

  const activeAdapter = interfaces.find(i => i.name === selectedIface);

  return (
    <div className="dark-panel p-6 relative overflow-hidden border border-cyan-900/40 bg-slate-950/70 shadow-xl backdrop-blur-md">
      {/* Ambient background glow */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-inner">
            <Radio size={18} className={capturing ? "animate-pulse text-rose-400" : "text-cyan-400"} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-mono text-xs uppercase tracking-wider text-slate-200 font-bold">
                Network Packet Capture & PCAP Ingestion
              </h3>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase tracking-wider ${
                capturing 
                  ? 'bg-rose-950/60 text-rose-400 border-rose-600/60 animate-pulse' 
                  : 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40'
              }`}>
                {capturing ? '● CAPTURING LIVE' : '● READY'}
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              TShark / Scapy Packet Sniffer → CICFlowMeter 39-Feature Extractor → Multi-Agent SOC Pipeline
            </p>
          </div>
        </div>

        {/* TShark detection badge */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-500">Capture Engine:</span>
          {captureStatus?.tshark_available ? (
            <span className="px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-700/50 text-cyan-300 font-medium">
              TShark Active
            </span>
          ) : (
            <span className="px-2 py-0.5 rounded bg-purple-950/60 border border-purple-700/50 text-purple-300 font-medium">
              Native IoT Stream
            </span>
          )}
        </div>
      </div>

      {/* Main Controls Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Col 1: Adapter Selector & Details */}
        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-mono text-slate-400 flex items-center gap-2">
                <Wifi size={13} className="text-cyan-400" />
                <span>Target Network Interface:</span>
              </label>
              <button
                type="button"
                onClick={loadInterfaces}
                disabled={capturing || isProcessing || loadingInterfaces}
                title="Refresh network interfaces"
                className="text-slate-400 hover:text-cyan-400 disabled:opacity-40 transition-colors p-0.5 rounded"
              >
                <RotateCw size={12} className={loadingInterfaces ? "animate-spin text-cyan-400" : ""} />
              </button>
            </div>
            <select
              value={selectedIface}
              onChange={e => setSelectedIface(e.target.value)}
              disabled={capturing || isProcessing || loadingInterfaces}
              className="w-full bg-slate-900/90 border border-slate-700/80 rounded-lg p-2.5 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none transition-colors"
            >
              {interfaces.length === 0 ? (
                <option value="">{loadingInterfaces ? "Discovering interfaces..." : "No interfaces found (click refresh)"}</option>
              ) : (
                interfaces.map(iface => (
                  <option key={iface.name} value={iface.name}>
                    {iface.name} {iface.ip_address ? `(${iface.ip_address})` : ''}
                  </option>
                ))
              )}
            </select>
          </div>

          {/* Adapter Telemetry Card */}
          <div className="p-3.5 rounded-lg bg-slate-900/70 border border-slate-800 text-xs font-mono space-y-1.5">
            <div className="flex justify-between text-slate-400">
              <span>Adapter IP:</span>
              <span className="text-cyan-400">{activeAdapter?.ip_address || "None / DHCP"}</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Link Status:</span>
              <span className={activeAdapter?.is_up ? "text-emerald-400" : "text-slate-500"}>
                {activeAdapter?.is_up ? "Connected (Up)" : "Down"}
              </span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Hardware MAC:</span>
              <span className="text-slate-300">{activeAdapter?.mac_address || "N/A"}</span>
            </div>
          </div>
        </div>

        {/* Col 2: Live Capture Control & Telemetry */}
        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-mono text-slate-400 flex items-center gap-2">
                <Terminal size={13} className="text-cyan-400" />
                <span>Live Sniffer Controls:</span>
              </label>
              <select
                value={captureDurationLimit}
                onChange={e => setCaptureDurationLimit(Number(e.target.value))}
                disabled={capturing || isProcessing}
                className="bg-slate-900 border border-slate-700/80 text-cyan-300 text-[10px] font-mono rounded px-2 py-0.5 focus:outline-none focus:border-cyan-500 cursor-pointer"
                title="Select capture duration limit"
              >
                <option value={10}>Auto: 10s</option>
                <option value={20}>Auto: 20s</option>
                <option value={30}>Auto: 30s</option>
                <option value={0}>Manual Stop</option>
              </select>
            </div>
            <div className="flex gap-2">
              {!capturing ? (
                <button
                  onClick={handleStartCapture}
                  disabled={isProcessing}
                  className="flex-1 bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold py-2.5 px-4 rounded-lg flex items-center justify-center gap-2 transition-all shadow-lg shadow-cyan-950/50 disabled:opacity-50"
                >
                  <Play size={14} />
                  <span>START CAPTURE</span>
                </button>
              ) : (
                <button
                  onClick={handleStopAndAnalyze}
                  disabled={isProcessing}
                  className="flex-1 bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-bold py-2.5 px-4 rounded-lg flex items-center justify-center gap-2 transition-all shadow-lg shadow-rose-950/50 animate-pulse"
                >
                  <Square size={14} />
                  <span>STOP & RUN SOC PIPELINE</span>
                </button>
              )}
            </div>

            {/* Real-time status / guidance tip */}
            {capturing && (
              <p className="text-[11px] font-mono text-amber-300/90 mt-1.5 flex items-center gap-1.5 animate-pulse">
                <span>● Sniffing packets live. {captureDurationLimit > 0 ? `Auto-finishing in ${Math.max(0, captureDurationLimit - durationTimer)}s or click STOP now.` : 'Click STOP & RUN SOC PIPELINE to analyze.'}</span>
              </p>
            )}
            {isProcessing && (
              <p className="text-[11px] font-mono text-cyan-400 mt-1.5 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                <span>Extracting flows & running 6-Agent AI SOC Pipeline...</span>
              </p>
            )}
          </div>

          {/* Live Telemetry Meters */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800 text-center font-mono">
              <div className="flex items-center justify-center gap-1 text-[11px] text-slate-500 mb-0.5">
                <Clock size={12} />
                <span>DURATION</span>
              </div>
              <span className="text-lg font-bold text-cyan-400">
                {Math.floor(durationTimer / 60)}:{(durationTimer % 60).toString().padStart(2, '0')}s
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800 text-center font-mono">
              <div className="flex items-center justify-center gap-1 text-[11px] text-slate-500 mb-0.5">
                <HardDrive size={12} />
                <span>PACKETS</span>
              </div>
              <span className="text-lg font-bold text-purple-400">
                {captureStatus?.packet_count || 0}
              </span>
            </div>
          </div>
        </div>

        {/* Col 3: PCAP File Ingestion */}
        <div className="space-y-4">
          <div>
            <label className="text-xs font-mono text-slate-400 mb-1.5 flex items-center gap-2">
              <Upload size={13} className="text-cyan-400" />
              <span>Or Ingest Existing PCAP / PCAPNG:</span>
            </label>
            <div className="relative">
              <input
                type="file"
                accept=".pcap,.pcapng"
                onChange={handleFileUpload}
                disabled={capturing || isProcessing}
                className="hidden"
                id="pcap-file-input"
              />
              <label
                htmlFor="pcap-file-input"
                className={`w-full flex items-center justify-center gap-2 p-2.5 rounded-lg border border-dashed text-xs font-mono cursor-pointer transition-colors ${
                  selectedFile 
                    ? 'bg-slate-900 border-cyan-500/70 text-cyan-300'
                    : 'bg-slate-900/50 border-slate-700 hover:border-slate-500 text-slate-400'
                }`}
              >
                <Upload size={14} />
                <span className="truncate max-w-[200px]">
                  {selectedFile ? selectedFile.name : "Select .pcap / .pcapng"}
                </span>
              </label>
            </div>
          </div>

          <button
            onClick={handleAnalyzeUploadedPcap}
            disabled={!uploadedPcapPath || isProcessing || capturing}
            className="w-full bg-slate-900 hover:bg-slate-800 text-cyan-400 border border-cyan-800/60 hover:border-cyan-500 font-mono text-xs font-semibold py-2.5 px-4 rounded-lg flex items-center justify-center gap-2 transition-all disabled:opacity-40 shadow-md"
          >
            <Sparkles size={14} />
            <span>PROCESS PCAP THROUGH SOC</span>
          </button>
        </div>
      </div>

      {/* Status, Loading & Results Cards */}
      {isProcessing && processingStatus && (
        <div className="mt-4 p-4 rounded-xl bg-cyan-950/40 border border-cyan-500/50 text-cyan-300 text-xs font-mono flex items-center gap-3 animate-pulse shadow-lg">
          <div className="w-5 h-5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin shrink-0" />
          <div className="flex-1">
            <span className="font-bold text-white block text-sm">{processingStatus}</span>
            <span className="text-[11px] text-cyan-400/80">Running Detection, Threat Intel, Risk Scoring, Firewall Playbook & Reporting agents...</span>
          </div>
        </div>
      )}

      {errorMsg && (
        <div className="mt-4 p-3.5 rounded-lg bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs font-mono flex items-center gap-2.5">
          <AlertTriangle size={16} className="shrink-0 text-rose-400" />
          <span>{errorMsg}</span>
        </div>
      )}

      {successMsg && (
        <div className="mt-4 p-3.5 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs font-mono flex items-center gap-2.5">
          <CheckCircle size={16} className="shrink-0 text-emerald-400" />
          <span className="font-medium">{successMsg}</span>
        </div>
      )}

      {/* Inline Analysis Results Card */}
      {processedResult && processedResult.overall_prediction && (
        <div className="mt-4 p-5 rounded-xl bg-slate-900/90 border border-cyan-500/50 shadow-2xl space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-3 border-b border-slate-800">
            <div className="flex items-center gap-3 flex-wrap">
              <span className={`px-3 py-1 rounded-md text-xs font-mono font-bold uppercase tracking-wider ${
                processedResult.overall_prediction.label.toLowerCase() === 'benign'
                  ? 'bg-emerald-950/90 text-emerald-400 border border-emerald-600/60'
                  : 'bg-rose-950/90 text-rose-300 border border-rose-600/70'
              }`}>
                ● {processedResult.overall_prediction.label}
              </span>
              <span className="text-xs font-mono text-cyan-400 font-semibold">
                {((processedResult.overall_prediction.confidence || 0) * 100).toFixed(2)}% Confidence
              </span>
              <span className="text-xs font-mono text-slate-400">
                ({processedResult.flows_extracted} flows, {processedResult.packets_analyzed || 0} packets)
              </span>
            </div>

            <div className="flex items-center gap-2.5 flex-wrap">
              {processedResult.overall_incident && onNavigateToIncidents && (
                <button
                  type="button"
                  onClick={onNavigateToIncidents}
                  className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-bold uppercase transition-all shadow-md shadow-rose-950/50"
                >
                  <ShieldAlert size={14} />
                  <span>Open SOC Incident & Playbook</span>
                  <ArrowRight size={13} className="ml-0.5" />
                </button>
              )}
              {processedResult.overall_incident?.report && (
                <button
                  type="button"
                  onClick={() => {
                    const blob = new Blob([processedResult.overall_incident!.report!.markdown_content], { type: 'text/markdown;charset=utf-8' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `incident_report_${processedResult.overall_incident!.incident_id}.md`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                  }}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyan-700 hover:bg-cyan-600 text-white font-mono text-xs font-semibold uppercase transition-all shadow-md shadow-cyan-950/40"
                  title="Download full SOC Incident Report (.md)"
                >
                  <Download size={14} />
                  <span>Report (.md)</span>
                </button>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Incident ID</span>
              <span className="text-cyan-300 font-bold truncate block">{processedResult.overall_incident?.incident_id || 'N/A'}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Risk Score</span>
              <span className="text-amber-400 font-bold">
                {processedResult.overall_incident?.risk_assessment?.risk_score ?? '0.0'} / 100
                <span className="text-[10px] text-slate-400 ml-1">({processedResult.overall_incident?.risk_assessment?.severity || 'Low'})</span>
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Status</span>
              <span className="text-emerald-400 font-semibold">{processedResult.overall_incident?.overall_status || 'COMPLETE'}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Generated By</span>
              <span className="text-emerald-400 font-semibold uppercase">
                {processedResult.overall_incident?.report?.generated_by || 'LLM'} ({processedResult.overall_incident?.report?.llm_model || 'llama3.2'})
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
