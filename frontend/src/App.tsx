import React, { useState, useEffect } from 'react';
import { Layout } from './layouts/Layout';
import { Dashboard } from './pages/Dashboard';
import { DatasetAnalysis } from './pages/DatasetAnalysis';
import { ModelPerformance } from './pages/ModelPerformance';
import { ThreatDetection } from './pages/ThreatDetection';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { Login } from './pages/Login';
import { AnomalyAnalysis } from './pages/AnomalyAnalysis';
import { Explainability } from './pages/Explainability';
import { Dataset, MLModel, DetectionJob, SystemStatus, DashboardAnalytics } from './types';
import { apiService } from './services/api';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    return localStorage.getItem('iotshield_auth') === 'true';
  });
  const [activePage, setActivePage] = useState<string>('dashboard');
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [selectedDataset, setSelectedDataset] = useState<Dataset | null>(null);
  const [selectedModel, setSelectedModel] = useState<MLModel | null>(null);
  const [selectedThreatId, setSelectedThreatId] = useState<number | null>(null);
  
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [models, setModels] = useState<MLModel[]>([]);
  const [detectionJobs, setDetectionJobs] = useState<DetectionJob[]>([]);
  const [analytics, setAnalytics] = useState<DashboardAnalytics | null>(null);
  const [analyticsLoading, setAnalyticsLoading] = useState<boolean>(false);

  // Load system and configuration metadata
  const fetchStatusAndData = async () => {
    try {
      const status = await apiService.getSystemStatus();
      setSystemStatus(status);
    } catch (err) {
      console.error("Failed to check system health status", err);
    }

    try {
      const dList = await apiService.getDatasets();
      setDatasets(dList);
      
      // If we don't have a dataset selected, set the first one as active default
      if (dList.length > 0 && !selectedDataset) {
        setSelectedDataset(dList[0]);
      }
    } catch (err) {
      console.error("Failed to load dataset list", err);
    }

    try {
      const mList = await apiService.getModels();
      setModels(mList);
      
      // Select first model as active default
      if (mList.length > 0 && !selectedModel) {
        setSelectedModel(mList[0]);
      }
    } catch (err) {
      console.error("Failed to load models list", err);
    }
  };

  // Load dashboard metrics
  const loadDashboardAnalytics = async () => {
    setAnalyticsLoading(true);
    try {
      const data = await apiService.getAnalytics();
      setAnalytics(data);
      
      // Parse detection jobs list from report endpoints or threat job history if available
      // For simplicity, we can inspect database reports or mock the active job if one exists
      if (data.total_records > 0) {
        // Build a mock detection jobs list based on dashboard statistics
        // In endpoints.py, we can also fetch jobs, but here we can just create a basic history
        // list so that the Reports page is fully functional.
        // We fetch reports to find available detection run IDs!
        const repList = await apiService.getReports();
        const jobs: DetectionJob[] = repList.map(r => ({
          id: r.detection_job_id,
          dataset_id: selectedDataset?.id || 1,
          model_id: selectedModel?.id || 1,
          total_records: r.summary.total_records,
          benign_count: r.summary.benign_records,
          malicious_count: r.summary.malicious_records,
          critical_count: r.summary.critical_records,
          avg_confidence: 0.95, // default approximation
          created_at: r.created_at
        }));
        
        // Remove duplicate job entries
        const uniqueJobs = Array.from(new Map(jobs.map(item => [item.id, item])).values());
        setDetectionJobs(uniqueJobs);
      }
    } catch (err) {
      console.error("Failed to load dashboard statistics", err);
    } finally {
      setAnalyticsLoading(false);
    }
  };

  // On mount
  useEffect(() => {
    fetchStatusAndData();
    loadDashboardAnalytics();
    
    // Set a health check poll every 30 seconds
    const interval = setInterval(async () => {
      try {
        const status = await apiService.getSystemStatus();
        setSystemStatus(status);
      } catch (err) {
        // silent fail
      }
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  // Sync selection defaults
  useEffect(() => {
    if (selectedDataset) {
      // Refresh list to sync modifications (like status changes)
      apiService.getDatasets().then(setDatasets).catch(() => {});
    }
  }, [selectedDataset]);

  // Callbacks
  const handlePreprocessSuccess = async () => {
    await fetchStatusAndData();
  };

  const handleTrainSuccess = async () => {
    await fetchStatusAndData();
  };

  const handleDetectionSuccess = async (job: DetectionJob) => {
    await loadDashboardAnalytics();
    // Add job to list immediately
    setDetectionJobs(prev => {
      if (prev.some(j => j.id === job.id)) return prev;
      return [job, ...prev];
    });
  };

  if (!isAuthenticated) {
    return <Login onLogin={() => {
      setIsAuthenticated(true);
      localStorage.setItem('iotshield_auth', 'true');
    }} />;
  }

  return (
    <Layout
      activePage={activePage}
      setActivePage={setActivePage}
      systemStatus={systemStatus}
      selectedDataset={selectedDataset}
      selectedModel={selectedModel}
    >
      {activePage === 'dashboard' && (
        <Dashboard
          analytics={analytics}
          loading={analyticsLoading}
          refreshData={loadDashboardAnalytics}
        />
      )}
      
      {activePage === 'dataset' && (
        <DatasetAnalysis
          selectedDataset={selectedDataset}
          setSelectedDataset={setSelectedDataset}
          onPreprocessSuccess={handlePreprocessSuccess}
        />
      )}

      {activePage === 'anomaly' && (
        <AnomalyAnalysis />
      )}

      {activePage === 'explain' && (
        <Explainability
          threatId={selectedThreatId}
          onSelectThreat={(id: number) => setSelectedThreatId(id)}
        />
      )}

      {activePage === 'detection' && (
        <ThreatDetection
          datasets={datasets}
          models={models}
          onDetectionSuccess={handleDetectionSuccess}
          onExplainThreat={(id: number) => {
            setSelectedThreatId(id);
            setActivePage('explain');
          }}
        />
      )}

      {activePage === 'performance' && (
        <ModelPerformance
          selectedModel={selectedModel}
          setSelectedModel={setSelectedModel}
          datasets={datasets}
          onTrainSuccess={handleTrainSuccess}
        />
      )}

      {activePage === 'reports' && (
        <Reports
          detectionJobs={detectionJobs}
          datasets={datasets}
        />
      )}

      {activePage === 'settings' && (
        <Settings
          systemStatus={systemStatus}
        />
      )}
    </Layout>
  );
}

export default App;
