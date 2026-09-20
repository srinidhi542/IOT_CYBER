import React, { useState, useEffect } from 'react';
import { Layout } from './layouts/Layout';
import { Dashboard } from './pages/Dashboard';
import { DatasetAnalysis } from './pages/DatasetAnalysis';
import { ModelPerformance } from './pages/ModelPerformance';
import { Settings } from './pages/Settings';
import { Login } from './pages/Login';
import { AIExplainability } from './pages/Explainability';
import { Dataset, MLModel, SystemStatus, DashboardAnalytics, PredictionExplanation } from './types';
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
  const [latestPrediction, setLatestPrediction] = useState<PredictionExplanation | null>(null);

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
          onNavigateToExplainability={() => setActivePage('explainability')}
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
