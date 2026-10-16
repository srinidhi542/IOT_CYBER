export interface Dataset {
  id: number;
  name: string;
  filepath: string;
  row_count: number | null;
  col_count: number | null;
  columns: string[] | null;
  column_types: Record<string, string> | null;
  target_column: string | null;
  class_distribution: Record<string, number> | null;
  missing_counts: Record<string, number> | null;
  status: string;
  created_at: string;
}

export interface PreprocessConfig {
  target_column: string;
  train_test_split: number;
}

export interface MLModel {
  id: number;
  name: string;
  algorithm: string;
  model_type: string;  // "classifier" or "anomaly"
  dataset_id: number;
  contamination: number | null;
  training_date: string;
  features: string[];
  classes: string[] | null;
  accuracy: number | null;
  precision_score: number | null;
  recall_score: number | null;
  f1_score: number | null;
  metrics_json: Record<string, any> | null;
  confusion_matrix: number[][] | Record<string, any> | null;
  feature_importance: Record<string, number> | null;
  created_at: string;
}

export interface MLModelTrainRequest {
  dataset_id: number;
  algorithm: string;
  train_split: number;
}

export interface AnomalyModelTrainRequest {
  dataset_id: number;
  contamination: number;
}

export interface Threat {
  id: number;
  detection_job_id: number;
  record_index: number;
  record_data: Record<string, any>;
  attack_type: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  confidence: number;
  anomaly_score: number | null;
  risk_score: number | null;
  anomaly_status: 'Anomalous' | 'Normal' | null;
  explanation: {
    summary: string;
    details: string[];
  };
  recommended_actions: string[];
  detection_reason: string[] | null;
  created_at: string;
}

export interface DetectionJob {
  id: number;
  dataset_id: number;
  model_id: number;
  anomaly_model_id?: number | null;
  total_records: number;
  benign_count: number;
  malicious_count: number;
  suspicious_count?: number;
  critical_count: number;
  avg_confidence: number;
  avg_risk_score?: number;
  created_at: string;
}

export interface DetectionResult {
  job: DetectionJob;
  threats: Threat[];
}

export interface SecurityReport {
  id: number;
  detection_job_id: number;
  title: string;
  summary: {
    generated_at: string;
    dataset_name: string;
    model_name: string;
    model_algorithm: string;
    model_accuracy: number;
    total_records: number;
    benign_records: number;
    malicious_records: number;
    critical_records: number;
    attack_distribution: Record<string, number>;
    severity_distribution: Record<string, number>;
    key_findings: string[];
    recommendations: Record<string, string[]>;
  };
  filepath: string | null;
  created_at: string;
}

export interface ComponentStatus {
  name: string;
  status: 'Operational' | 'Ready' | 'Error' | 'Not Configured';
  details: string | null;
}

export interface SystemStatus {
  api: ComponentStatus;
  ml_engine: ComponentStatus;
  dataset_engine: ComponentStatus;
  detection_engine: ComponentStatus;
}

export interface DashboardAnalytics {
  total_records: number;
  threats_detected: number;
  suspicious_detected: number;
  critical_threats: number;
  avg_confidence: number;
  avg_risk_score: number;
  benign_count: number;
  malicious_count: number;
  total_datasets: number;
  total_models: number;
  current_model: string | null;
  last_analysis_time: string | null;
  threat_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  risk_distribution: Record<string, number>;
  dual_detection: {
    ClassifierOnly: number;
    AnomalousOnly: number;
    Both: number;
    TotalAnomalies: number;
  };
  detection_trend: Array<{ range: string; threats: number }>;
}

export interface ShapContribution {
  feature: string;
  value: number;
  shap_value: number;
  direction: 'increases' | 'decreases';
}

export interface PredictionExplanation {
  label: string;
  confidence: number;
  probabilities: Record<string, number>;
  top_contributing_features: ShapContribution[];
  shap_values: Record<string, number>;
  anomaly_score?: number | null;
  anomaly_status?: 'Anomalous' | 'Normal' | null;
  anomaly_model?: string | null;
  anomaly_raw_score?: number | null;
}

// ═══════════════════════════════════════════════════
// MULTI-AGENT SOC & PACKET CAPTURE TYPES
// ═══════════════════════════════════════════════════

export interface NetworkInterface {
  id: string;
  name: string;
  description: string;
  ip_address: string | null;
  mac_address: string | null;
  is_up: boolean;
  is_loopback: boolean;
  tshark_supported: boolean;
}

export interface CaptureStatus {
  session_id: string | null;
  interface: string | null;
  output_pcap: string | null;
  is_capturing: boolean;
  duration: number;
  packet_count: number;
  file_size: number;
  error?: string | null;
  tshark_available: boolean;
  tshark_path?: string | null;
}

export interface NetworkContext {
  timestamp?: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
}

export interface MitreAttackItem {
  id: string;
  name: string;
  tactic: string;
  description: string;
  url: string;
  similarity_score?: number;
}

export interface CveItem {
  cve_id: string;
  affected_systems: string;
  cvss_score: number;
  severity: string;
  description: string;
  url: string;
  similarity_score?: number;
}

export interface CisaAdvisoryItem {
  id: string;
  title: string;
  release_date: string;
  summary: string;
  url: string;
  similarity_score?: number;
}

export interface ThreatIntelData {
  mitre_attack: MitreAttackItem[];
  cve_list: CveItem[];
  cisa_advisories: CisaAdvisoryItem[];
  iot_threat_context: string;
  retrieval_confidence: number;
  sources: string[];
  generated_by?: string;
  llm_model?: string;
  latency_ms?: number;
}

export interface RiskAssessmentData {
  risk_score: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  priority: string;
  impact: string;
  likelihood: string;
  reasoning: string[];
  anomaly_score?: number | null;
  anomaly_status?: 'Anomalous' | 'Normal' | null;
  generated_by?: string;
  llm_model?: string;
  latency_ms?: number;
}

export interface FirewallCommand {
  firewall_type: string;
  command: string;
  description: string;
}

export interface ResponsePlanData {
  containment: string[];
  recovery: string[];
  prevention: string[];
  firewall_commands: FirewallCommand[];
  approval_required: boolean;
  approval_status: 'PENDING_ANALYST_APPROVAL' | 'APPROVED' | 'REJECTED';
  reviewed_by?: string | null;
  review_timestamp?: string | null;
  review_notes?: string | null;
  generated_by?: string;
  llm_model?: string;
  latency_ms?: number;
}

export interface TimelineEvent {
  timestamp: string;
  agent: string;
  action: string;
  details: string;
  status: string;
}

export interface IncidentReportData {
  incident_id: string;
  generated_at: string;
  title: string;
  executive_summary: string;
  attack_type: string;
  severity: string;
  priority: string;
  risk_score: number;
  timeline: TimelineEvent[];
  markdown_content: string;
  generated_by?: string;
  llm_model?: string;
  latency_ms?: number;
}

export interface AgentError {
  agent: string;
  error: string;
  timestamp: string;
}

export interface IncidentState {
  incident_id: string;
  created_at: string;
  status: string;
  overall_status?: 'COMPLETE' | 'PARTIAL' | 'FAILED' | string;
  detection: {
    attack_type: string;
    confidence: number;
    probabilities: Record<string, number>;
    network_context: NetworkContext;
    top_contributing_features: ShapContribution[];
    shap_values: Record<string, number>;
    raw_record: Record<string, any>;
    analyst_explanation?: string;
    anomaly_score?: number | null;
    anomaly_status?: 'Anomalous' | 'Normal' | null;
    generated_by?: string;
    llm_model?: string;
    latency_ms?: number;
  };
  threat_intel?: ThreatIntelData | null;
  risk_assessment?: RiskAssessmentData | null;
  response?: ResponsePlanData | null;
  report?: IncidentReportData | null;
  timeline: TimelineEvent[];
  agent_status?: Record<string, string>;
  errors?: AgentError[];
  correlation_note?: string;
}

export interface AnomalyEngineStatus {
  status: string;
  active_model_id: number | null;
  model_name: string | null;
  algorithm: string | null;
  contamination: number | null;
  training_date: string | null;
  is_trained: boolean;
  ready: boolean;
  ref_min: number | null;
  ref_max: number | null;
  n_features: number | null;
}

export interface CaptureProcessResult {
  pcap_path: string;
  flows_extracted: number;
  packets_analyzed?: number;
  capture_stats?: {
    Timestamp?: string;
    Source_IP?: string;
    Destination_IP?: string;
    Source_Port?: number;
    Destination_Port?: number;
    Protocol_Name?: string;
    total_flows?: number;
    unique_source_ips?: string[];
    unique_destination_ips?: string[];
    observed_protocols?: string[];
  };
  overall_prediction?: {
    label: string;
    confidence: number;
    probabilities: Record<string, number>;
    anomaly_score?: number | null;
    anomaly_status?: 'Anomalous' | 'Normal' | null;
  };
  overall_anomaly?: {
    anomaly_score: number;
    anomaly_status: 'Anomalous' | 'Normal';
    raw_score?: number;
    is_outlier?: boolean;
    model?: string;
  } | null;
  overall_explainability?: PredictionExplanation;
  overall_incident?: IncidentState;
  incidents: IncidentState[];
}

export interface PlatformSettings {
  network_capture: {
    default_interface: string;
    capture_duration: number;
    auto_stop: boolean;
    pcap_storage_path: string;
  };
  flow_extraction: {
    flow_timeout: number;
    output_directory: string;
    auto_process_pcap: boolean;
  };
  detection_engine: {
    active_model_id: number;
    confidence_threshold: number;
    shap_top_k: number;
  };
  multi_agent_pipeline: {
    execution_mode: 'coordinated' | 'sequential';
    analyst_approval_required: boolean;
  };
  threat_intelligence: {
    enable_mitre: boolean;
    enable_nvd_cve: boolean;
    enable_cisa: boolean;
    rag_top_k: number;
  };
  data_storage: {
    pcap_path: string;
    flow_csv_path: string;
    report_path: string;
    retention_days: number;
  };
  llm?: {
    enabled: boolean;
    provider: string;
    model: string;
    temperature: number;
    agent_toggles?: Record<string, boolean>;
  };
  rag?: {
    enabled: boolean;
    vector_store: string;
    embedding_model: string;
    hybrid_alpha: number;
    min_relevance_score: number;
    auto_refresh_hours: number;
    persist_directory?: string;
    cache_directory?: string;
  };
}

export interface PlatformSettingsResponse {
  settings: PlatformSettings;
  health: Record<string, { name: string; status: string; details?: string }>;
  agents_health: Record<string, { name: string; status: string; details?: string }>;
}

export interface PersistentReport {
  report_id: string;
  incident_id: string;
  title: string;
  created_at: string;
  updated_at: string;
  source: string;
  filename: string;
  filepath: string;
  file_size: number;
  mime_type: string;
  file_exists?: boolean;
  attack_classification: string;
  confidence: number;
  probabilities: Record<string, number>;
  flow_statistics: {
    source_ip?: string;
    source_port?: number;
    destination_ip?: string;
    destination_port?: number;
    protocol?: string;
    timestamp?: string;
    total_packets?: number;
    total_flows?: number;
  };
  shap_explanations: {
    top_contributing_features: Array<{
      feature: string;
      value: number;
      shap_value: number;
      direction: string;
    }>;
    shap_values: Record<string, number>;
  };
  agent_findings: {
    executive_summary?: string;
    mitre_attack?: Record<string, any>;
    threat_category?: string;
    nvd_cves?: Array<{ cve_id: string; description: string; cvss: number }>;
    cisa_known_exploited?: boolean;
    iot_threat_context?: string;
    risk_score: number;
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
    priority: string;
    contributing_factors?: string[];
  };
  mitigation_recommendations: {
    actions?: string[];
    firewall_rules?: string[];
    requires_human_authorization?: boolean;
    recommendations?: string[];
  };
  timeline?: Array<{
    timestamp: string;
    agent_name: string;
    action: string;
    details: string;
  }>;
  markdown_content?: string;
}

export interface StorageStatus {
  mongodb_connected: boolean;
  mongodb_uri: string;
  mongodb_database: string;
  storage_directory: string;
  directory_exists: boolean;
  total_files_on_disk: number;
  total_records_in_db: number;
}


