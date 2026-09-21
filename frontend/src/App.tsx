import React, { useState, useEffect } from 'react';
import { Layout } from './layouts/Layout';
import { Dashboard } from './pages/Dashboard';
import { DatasetAnalysis } from './pages/DatasetAnalysis';
import { ModelPerformance } from './pages/ModelPerformance';
import { Settings } from './pages/Settings';
import { Login } from './pages/Login';
import { AIExplainability } from './pages/Explainability';
import { Incidents } from './pages/Incidents';
import { Dataset, MLModel, SystemStatus, DashboardAnalytics, PredictionExplanation, IncidentState, CaptureProcessResult } from './types';
import { apiService } from './services/api';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    return localStorage.getItem('iotshield_auth') === 'true';
  });
  const [activePage, setActivePage] = useState<string>('dashboard');
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [selectedDataset, setSelectedDataset] = useState<Dataset | null>(null);
  const [selectedModel, setSelectedModel] = useState<MLModel | null>(null);
  
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [models, setModels] = useState<MLModel[]>([]);
  const [analytics, setAnalytics] = useState<DashboardAnalytics | null>(null);
  const [analyticsLoading, setAnalyticsLoading] = useState<boolean>(false);
  
  // Persistent detection & packet capture results across page navigation & reload
  const [captureResult, setCaptureResult] = useState<CaptureProcessResult | null>(() => {
    try {
      const saved = sessionStorage.getItem('iotshield_last_capture');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [latestPrediction, setLatestPrediction] = useState<PredictionExplanation | null>(() => {
    try {
      const saved = sessionStorage.getItem('iotshield_latest_pred');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [activeIncident, setActiveIncident] = useState<IncidentState | null>(null);
  const [incidentsList, setIncidentsList] = useState<IncidentState[]>([]);

  // Sync state to sessionStorage
  useEffect(() => {
    try {
      if (captureResult) {
        sessionStorage.setItem('iotshield_last_capture', JSON.stringify(captureResult));
      } else {
        sessionStorage.removeItem('iotshield_last_capture');
      }
    } catch (e) {
      console.warn("Could not persist capture result to sessionStorage", e);
    }
  }, [captureResult]);

  useEffect(() => {
    try {
      if (latestPrediction) {
        sessionStorage.setItem('iotshield_latest_pred', JSON.stringify(latestPrediction));
      } else {
        sessionStorage.removeItem('iotshield_latest_pred');
      }
    } catch (e) {
      console.warn("Could not persist prediction to sessionStorage", e);
    }
  }, [latestPrediction]);

  const handleResetDetection = () => {
    setLatestPrediction(null);
    setCaptureResult(null);
    try {
      sessionStorage.removeItem('iotshield_last_capture');
      sessionStorage.removeItem('iotshield_latest_pred');
    } catch (e) {}
  };

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
    loadIncidents();
    
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

  const loadIncidents = async () => {
    try {
      const list = await apiService.getSocIncidents();
      if (list && list.length > 0) {
        setIncidentsList(list);
        if (!activeIncident) {
          setActiveIncident(list[0]);
        }
      }
    } catch (err) {
      // silent
    }
  };

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

  const handleLogout = () => {
    localStorage.removeItem('iotshield_auth');
    setIsAuthenticated(false);
    setSelectedDataset(null);
    setSelectedModel(null);
    setActivePage('dashboard');
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
          selectedDataset={selectedDataset}
          selectedModel={selectedModel}
          latestPrediction={latestPrediction}
          setLatestPrediction={setLatestPrediction}
          captureResult={captureResult}
          setCaptureResult={setCaptureResult}
          onResetDetection={handleResetDetection}
          onNavigateToExplainability={() => setActivePage('explainability')}
          onNavigateToIncidents={() => setActivePage('incidents')}
          activeIncident={activeIncident}
          setActiveIncident={setActiveIncident}
          setIncidentsList={setIncidentsList}
        />
      )}

      {activePage === 'incidents' && (
        <Incidents
          activeIncident={activeIncident}
          incidentsList={incidentsList}
          setActiveIncident={setActiveIncident}
          setIncidentsList={setIncidentsList}
          onNavigateToDashboard={() => setActivePage('dashboard')}
          refreshIncidents={loadIncidents}
        />
      )}
      
      {activePage === 'dataset' && (
        <DatasetAnalysis
          selectedDataset={selectedDataset}
          setSelectedDataset={setSelectedDataset}
          onPreprocessSuccess={handlePreprocessSuccess}
        />
      )}

      {activePage === 'performance' && (
        <ModelPerformance
          selectedModel={selectedModel}
          setSelectedModel={setSelectedModel}
        />
      )}

      {activePage === 'explainability' && (
        <AIExplainability
          latestPrediction={latestPrediction}
          onNavigateToPrediction={() => setActivePage('dashboard')}
        />
      )}

      {activePage === 'settings' && (
        <Settings
          systemStatus={systemStatus}
          onLogout={handleLogout}
        />
      )}
    </Layout>
  );
}

export default App;
