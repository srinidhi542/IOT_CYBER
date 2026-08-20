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
  confusion_matrix: number[][] | null;
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
