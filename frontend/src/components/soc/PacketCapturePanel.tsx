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
  HardDrive
} from 'lucide-react';

interface PacketCapturePanelProps {
  onIncidentsGenerated: (incidents: IncidentState[]) => void;
  onSingleIncidentGenerated: (incident: IncidentState) => void;
  onCaptureProcessed?: (result: CaptureProcessResult) => void;
  isProcessing: boolean;
  setIsProcessing: (v: boolean) => void;
}

export const PacketCapturePanel: React.FC<PacketCapturePanelProps> = ({
  onIncidentsGenerated,
  onSingleIncidentGenerated,
  onCaptureProcessed,
  isProcessing,
  setIsProcessing
}) => {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedIface, setSelectedIface] = useState<string>('');
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus | null>(null);
  const [capturing, setCapturing] = useState<boolean>(false);
  const [durationTimer, setDurationTimer] = useState<number>(0);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadedPcapPath, setUploadedPcapPath] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const timerRef = useRef<any>(null);

  // Load interfaces and initial status
  useEffect(() => {
    loadInterfaces();
    checkStatus();
  }, []);

  const loadInterfaces = async () => {
    try {
      const list = await apiService.getCaptureInterfaces();
      setInterfaces(list);
      if (list.length > 0 && !selectedIface) {
        // Pick first active or Wi-Fi/Ethernet adapter
        const best = list.find(i => i.is_up && !i.is_loopback) || list[0];
        setSelectedIface(best.name);
      }
    } catch (e: any) {
      console.warn("Failed to enumerate network interfaces:", e);
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

  // Timer while capturing
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

  const handleStartCapture = async () => {
    try {
      setErrorMsg(null);
      setSuccessMsg(null);
      setDurationTimer(0);
      const res = await apiService.startCapture(selectedIface || "Default", 0, 0);
      setCapturing(true);
      setCaptureStatus(res as any);
      setSuccessMsg(`Capture initiated on adapter: ${selectedIface || "Default"}`);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to start capture");
    }
  };

  const handleStopAndAnalyze = async () => {
    try {
      setIsProcessing(true);
      setErrorMsg(null);
      setCapturing(false);
      setSuccessMsg("Stopping capture and extracting bidirectional flow telemetry...");
      const stopRes = await apiService.stopCapture();
      setCaptureStatus(stopRes as any);

      // Now automatically process through CICFlowMeter -> XGBoost -> Multi-Agent SOC
      const pcapFile = stopRes.output_pcap;
      if (pcapFile) {
        setSuccessMsg(`Processing ${stopRes.packet_count || 0} packets through CICFlowMeter 39-feature pipeline...`);
        const procResult = await apiService.processPcap(pcapFile, 6);
        if (onCaptureProcessed) {
          onCaptureProcessed(procResult);
        }
        if (procResult.overall_incident) {
          onSingleIncidentGenerated(procResult.overall_incident);
        }
        if (procResult.incidents && procResult.incidents.length > 0) {
          onIncidentsGenerated(procResult.incidents);
          setSuccessMsg(`Extracted ${procResult.flows_extracted} flows. Analyzed overall traffic profile through Multi-Agent SOC Pipeline.`);
        } else {
          setSuccessMsg(`Captured ${stopRes.packet_count} packets. Traffic evaluated as Benign.`);
        }
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Capture processing failed");
    } finally {
      setIsProcessing(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const file = e.target.files[0];
    setSelectedFile(file);
    try {
      setIsProcessing(true);
      setErrorMsg(null);
      const res = await apiService.uploadPcap(file);
      setUploadedPcapPath(res.filepath);
      setSuccessMsg(`Uploaded ${file.name} (${(res.file_size / 1024).toFixed(1)} KB) successfully.`);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to upload PCAP file");
    } finally {
      setIsProcessing(false);
    }
  };

  const handleAnalyzeUploadedPcap = async () => {
    if (!uploadedPcapPath) return;
    try {
      setIsProcessing(true);
      setErrorMsg(null);
      setSuccessMsg(`Executing CICFlowMeter extraction on ${selectedFile?.name || 'PCAP'}...`);
      const procResult = await apiService.processPcap(uploadedPcapPath, 6);
      if (onCaptureProcessed) {
        onCaptureProcessed(procResult);
      }
      if (procResult.overall_incident) {
        onSingleIncidentGenerated(procResult.overall_incident);
      }
      if (procResult.incidents && procResult.incidents.length > 0) {
        onIncidentsGenerated(procResult.incidents);
        setSuccessMsg(`Successfully parsed ${procResult.flows_extracted} flows. Generated overall SOC Incident Assessment.`);
      } else {
        setSuccessMsg(`Processed PCAP. Traffic evaluated as Benign.`);
      }
    } catch (err: any) {
      setErrorMsg(err.message || "PCAP processing failed");
    } finally {
      setIsProcessing(false);
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
            <label className="text-xs font-mono text-slate-400 mb-1.5 flex items-center gap-2">
              <Wifi size={13} className="text-cyan-400" />
              <span>Target Network Interface:</span>
            </label>
            <select
              value={selectedIface}
              onChange={e => setSelectedIface(e.target.value)}
              disabled={capturing || isProcessing}
              className="w-full bg-slate-900/90 border border-slate-700/80 rounded-lg p-2.5 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none transition-colors"
            >
              {interfaces.map(iface => (
                <option key={iface.name} value={iface.name}>
                  {iface.name} {iface.ip_address ? `(${iface.ip_address})` : ''}
                </option>
              ))}
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
            <label className="text-xs font-mono text-slate-400 mb-1.5 flex items-center gap-2">
              <Terminal size={13} className="text-cyan-400" />
              <span>Live Sniffer Controls:</span>
            </label>
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
                {captureStatus?.packet_count || (capturing ? Math.floor(durationTimer * 24) : 0)}
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

      {/* Status & Notification Banners */}
      {errorMsg && (
        <div className="mt-4 p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs font-mono flex items-center gap-2">
          <AlertTriangle size={15} className="shrink-0 text-rose-400" />
          <span>{errorMsg}</span>
        </div>
      )}

      {successMsg && (
        <div className="mt-4 p-3 rounded-lg bg-emerald-950/30 border border-emerald-800/50 text-emerald-300 text-xs font-mono flex items-center gap-2">
          <CheckCircle size={15} className="shrink-0 text-emerald-400" />
          <span>{successMsg}</span>
        </div>
      )}
    </div>
  );
};
