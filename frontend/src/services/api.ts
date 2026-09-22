import { 
  Dataset, 
  MLModel, 
  DetectionResult, 
  Threat, 
  SecurityReport, 
  SystemStatus, 
  DashboardAnalytics,
  PreprocessConfig,
  MLModelTrainRequest,
  PredictionExplanation,
  NetworkInterface,
  CaptureStatus,
  IncidentState,
  CaptureProcessResult,
  PlatformSettings,
  PlatformSettingsResponse
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let errorDetail = 'An error occurred while calling the API';
    try {
      const errorJson = await response.json();
      errorDetail = errorJson.detail || errorDetail;
    } catch {
      // response is not JSON
    }
    throw new Error(errorDetail);
  }
  return response.json() as Promise<T>;
}

export const apiService = {
  // System status
  async getSystemStatus(): Promise<SystemStatus> {
    const res = await fetch(`${API_BASE_URL}/system/status`);
    return handleResponse<SystemStatus>(res);
  },

  // Datasets
  async uploadDataset(file: File): Promise<Dataset> {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE_URL}/dataset/upload`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse<Dataset>(res);
  },

  async getDatasets(): Promise<Dataset[]> {
    const res = await fetch(`${API_BASE_URL}/datasets`);
    return handleResponse<Dataset[]>(res);
  },

  async getDataset(id: number): Promise<Dataset> {
    const res = await fetch(`${API_BASE_URL}/dataset/${id}`);
    return handleResponse<Dataset>(res);
  },

  async getDatasetPreview(id: number, limit = 15): Promise<Record<string, any>[]> {
    const res = await fetch(`${API_BASE_URL}/dataset/${id}/preview?limit=${limit}`);
    return handleResponse<Record<string, any>[]>(res);
  },

  async preprocessDataset(id: number, config: PreprocessConfig): Promise<Record<string, any>> {
    const res = await fetch(`${API_BASE_URL}/preprocess/${id}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(config),
    });
    return handleResponse<Record<string, any>>(res);
  },

  // Models
  async trainModel(payload: MLModelTrainRequest): Promise<MLModel> {
    const res = await fetch(`${API_BASE_URL}/model/train`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    return handleResponse<MLModel>(res);
  },

  async trainAnomalyModel(datasetId: number, contamination: number): Promise<MLModel> {
    const res = await fetch(`${API_BASE_URL}/anomaly/train`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ dataset_id: datasetId, contamination }),
    });
    return handleResponse<MLModel>(res);
  },

  async getModels(): Promise<MLModel[]> {
    const res = await fetch(`${API_BASE_URL}/models`);
    return handleResponse<MLModel[]>(res);
  },

  async getModel(id: number): Promise<MLModel> {
    const res = await fetch(`${API_BASE_URL}/model/${id}`);
    return handleResponse<MLModel>(res);
  },

  // Detection
  async runDetection(datasetId: number, modelId: number, anomalyModelId?: number): Promise<DetectionResult> {
    const res = await fetch(`${API_BASE_URL}/detect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ 
        dataset_id: datasetId, 
        model_id: modelId,
        anomaly_model_id: anomalyModelId
      }),
    });
    return handleResponse<DetectionResult>(res);
  },

  async getThreats(jobId?: number, severity?: string): Promise<Threat[]> {
    let url = `${API_BASE_URL}/threats`;
    const params = new URLSearchParams();
    if (jobId) params.append('detection_job_id', jobId.toString());
    if (severity) params.append('severity', severity);
    
    const queryString = params.toString();
    if (queryString) url += `?${queryString}`;

    const res = await fetch(url);
    return handleResponse<Threat[]>(res);
  },

  async getThreatDetails(id: number): Promise<Threat> {
    const res = await fetch(`${API_BASE_URL}/threats/${id}`);
    return handleResponse<Threat>(res);
  },

  // Reports
  async generateReport(detectionJobId: number): Promise<SecurityReport> {
    const res = await fetch(`${API_BASE_URL}/reports/generate?detection_job_id=${detectionJobId}`, {
      method: 'POST',
    });
    return handleResponse<SecurityReport>(res);
  },

  async getReports(): Promise<SecurityReport[]> {
    const res = await fetch(`${API_BASE_URL}/reports`);
    return handleResponse<SecurityReport[]>(res);
  },

  getReportDownloadUrl(id: number): string {
    return `${API_BASE_URL}/report/${id}/download`;
  },

  // Dashboard Analytics
  async getAnalytics(): Promise<DashboardAnalytics> {
    const res = await fetch(`${API_BASE_URL}/analytics`);
    return handleResponse<DashboardAnalytics>(res);
  },

  // Delete Dataset (cascades to models, jobs, threats, reports)
  async deleteDataset(id: number): Promise<void> {
    const res = await fetch(`${API_BASE_URL}/dataset/${id}`, { method: 'DELETE' });
    if (!res.ok) {
      let detail = 'Failed to delete dataset';
      try { const j = await res.json(); detail = j.detail || detail; } catch {}
      throw new Error(detail);
    }
  },

  // Explainability — per-record feature contributions
  async explainThreat(id: number): Promise<Record<string, any>> {
    const res = await fetch(`${API_BASE_URL}/threats/${id}/explain`);
    return handleResponse<Record<string, any>>(res);
  },

  // Real-time SHAP Prediction Explanation
  async explainPrediction(record: Record<string, any>): Promise<PredictionExplanation> {
    const res = await fetch(`${API_BASE_URL}/predict/explain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(record),
    });
    return handleResponse<PredictionExplanation>(res);
  },

  async predict(record: Record<string, any>): Promise<{ label: string; confidence: number; probabilities: Record<string, number> }> {
    const res = await fetch(`${API_BASE_URL}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(record),
    });
    return handleResponse<{ label: string; confidence: number; probabilities: Record<string, number> }>(res);
  },

  // ═══════════════════════════════════════════════════
  // NETWORK PACKET CAPTURE & PCAP MANAGEMENT
  // ═══════════════════════════════════════════════════
  async getCaptureInterfaces(): Promise<NetworkInterface[]> {
    const res = await fetch(`${API_BASE_URL}/capture/interfaces`);
    return handleResponse<NetworkInterface[]>(res);
  },

  async getCaptureStatus(): Promise<CaptureStatus> {
    const res = await fetch(`${API_BASE_URL}/capture/status`);
    return handleResponse<CaptureStatus>(res);
  },

  async startCapture(iface: string, durationLimit = 0, packetLimit = 0): Promise<Record<string, any>> {
    const res = await fetch(`${API_BASE_URL}/capture/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        interface: iface,
        duration_limit: durationLimit,
        packet_limit: packetLimit
      }),
    });
    return handleResponse<Record<string, any>>(res);
  },

  async stopCapture(): Promise<Record<string, any>> {
    const res = await fetch(`${API_BASE_URL}/capture/stop`, {
      method: 'POST',
    });
    return handleResponse<Record<string, any>>(res);
  },

  async uploadPcap(file: File): Promise<{ filename: string; filepath: string; file_size: number }> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE_URL}/capture/upload`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse<{ filename: string; filepath: string; file_size: number }>(res);
  },

  async processPcap(pcapPath?: string, maxFlows = 5): Promise<CaptureProcessResult> {
    const res = await fetch(`${API_BASE_URL}/capture/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pcap_path: pcapPath,
        max_flows_to_analyze: maxFlows
      }),
    });
    return handleResponse<CaptureProcessResult>(res);
  },

  // ═══════════════════════════════════════════════════
  // MULTI-AGENT SOC PIPELINE
  // ═══════════════════════════════════════════════════
  async analyzeFlow(record: Record<string, any>, networkContext?: Record<string, any>): Promise<IncidentState> {
    const res = await fetch(`${API_BASE_URL}/agents/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ record, network_context: networkContext }),
    });
    return handleResponse<IncidentState>(res);
  },

  async getSocIncidents(): Promise<IncidentState[]> {
    const res = await fetch(`${API_BASE_URL}/agents/incidents`);
    return handleResponse<IncidentState[]>(res);
  },

  async getSocIncident(incidentId: string): Promise<IncidentState> {
    const res = await fetch(`${API_BASE_URL}/agents/incident/${incidentId}`);
    return handleResponse<IncidentState>(res);
  },

  async reviewIncidentResponse(incidentId: string, approved: boolean, analystName = "SOC Analyst", notes?: string): Promise<IncidentState> {
    const res = await fetch(`${API_BASE_URL}/agents/incident/${incidentId}/approval`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        approved,
        analyst_name: analystName,
        notes
      }),
    });
    return handleResponse<IncidentState>(res);
  },

  async getIncidentReportMarkdown(incidentId: string): Promise<string> {
    const res = await fetch(`${API_BASE_URL}/agents/incident/${incidentId}/report`);
    if (!res.ok) throw new Error("Failed to fetch markdown report");
    return res.text();
  },

  // ═══════════════════════════════════════════════════
  // PLATFORM CONFIGURATION & SETTINGS
  // ═══════════════════════════════════════════════════
  async getPlatformSettings(): Promise<PlatformSettingsResponse> {
    const res = await fetch(`${API_BASE_URL}/settings`);
    return handleResponse<PlatformSettingsResponse>(res);
  },

  async updatePlatformSettings(settings: Partial<PlatformSettings>): Promise<PlatformSettingsResponse> {
    const res = await fetch(`${API_BASE_URL}/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings),
    });
    return handleResponse<PlatformSettingsResponse>(res);
  }
};
