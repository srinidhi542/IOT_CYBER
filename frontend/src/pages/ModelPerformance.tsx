import React, { useState, useEffect } from 'react';
import { 
  TrendingUp, 
  Activity, 
  Cpu, 
  Settings, 
  Play, 
  CheckCircle, 
  AlertCircle,
  HelpCircle
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  Cell 
} from 'recharts';
import { MLModel, Dataset } from '../types';
import { apiService } from '../services/api';

interface ModelPerformanceProps {
  selectedModel: MLModel | null;
  setSelectedModel: (model: MLModel | null) => void;
  datasets: Dataset[];
  onTrainSuccess: () => void;
}

export const ModelPerformance: React.FC<ModelPerformanceProps> = ({
  selectedModel,
  setSelectedModel,
  datasets,
  onTrainSuccess
}) => {
  const [models, setModels] = useState<MLModel[]>([]);
  const [training, setTraining] = useState(false);
  const [selectedDatasetId, setSelectedDatasetId] = useState<number>(0);
  const [algorithm, setAlgorithm] = useState<string>('XGBoost');
  const [trainSplit, setTrainSplit] = useState<number>(0.8);
  const [contamination, setContamination] = useState<number>(0.05);
  const [factoryMode, setFactoryMode] = useState<'classifier' | 'anomaly'>('classifier');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Load models
  async function loadModels() {
    try {
      const list = await apiService.getModels();
      setModels(list);
    } catch (err: any) {
      console.error(err);
    }
  }

  useEffect(() => {
    loadModels();
  }, [selectedModel]);

  // Set default dataset if list loaded
  useEffect(() => {
    if (datasets.length > 0 && selectedDatasetId === 0) {
      const preprocessed = datasets.find(d => d.status === 'preprocessed');
      setSelectedDatasetId(preprocessed ? preprocessed.id : datasets[0].id);
    }
  }, [datasets]);

  // Handle model training
  const handleTrainModel = async () => {
    if (selectedDatasetId === 0) {
      setErrorMsg("Please select a valid dataset.");
      return;
    }

    setTraining(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      if (factoryMode === 'classifier') {
        const payload = {
          dataset_id: selectedDatasetId,
          algorithm: algorithm,
          train_split: trainSplit
        };
        const model = await apiService.trainModel(payload);
        setSelectedModel(model);
        setSuccessMsg(`Supervised classifier model trained successfully!`);
      } else {
        const model = await apiService.trainAnomalyModel(selectedDatasetId, contamination);
        setSelectedModel(model);
        setSuccessMsg(`Unsupervised Isolation Forest anomaly model trained successfully!`);
      }
      await loadModels();
      onTrainSuccess();
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.message || "Model training execution failed.");
    } finally {
      setTraining(false);
    }
  };

  // Format Feature Importance data for Recharts
  const formatFeatureImportance = (importance: Record<string, number> | null) => {
    if (!importance) return [];
    // Convert to array of {name, value} and take top 10
    return Object.entries(importance)
      .map(([name, value]) => ({
        name: name.replace('_', ' ').replace('Total', '').trim(),
        value
      }))
      .slice(0, 8);
  };

  const importanceData = formatFeatureImportance(selectedModel?.feature_importance || null);

  // Helper to color matrix cells based on correct prediction
  const getMatrixCellColor = (value: number, rowIdx: number, colIdx: number, maxVal: number) => {
    if (maxVal === 0) return 'bg-slate-900';
    const intensity = Math.min(90, Math.max(10, Math.round((value / maxVal) * 90)));
    
    if (rowIdx === colIdx) {
      // Correct predictions (diagonal)
      return `bg-emerald-500/${intensity} text-white font-semibold`;
    } else {
      // Mistakes / False positives
      return value > 0 
        ? `bg-rose-500/${intensity} text-rose-200` 
        : 'bg-slate-900/40 text-slate-600';
    }
  };

  // Find max value in confusion matrix for scaling intensity
  const getMaxMatrixValue = (matrix: number[][] | null | undefined) => {
    if (!matrix || matrix.length === 0) return 0;
    return Math.max(...matrix.map(row => Math.max(...row)));
  };

  const maxMatrixVal = getMaxMatrixValue(selectedModel?.confusion_matrix);

  return (
    <div className="space-y-8">
      {/* ALERTS */}
      {errorMsg && (
        <div className="flex items-center gap-3 p-4 bg-rose-500/10 border border-rose-900/30 rounded-lg text-rose-400 text-xs font-mono">
          <AlertCircle size={16} />
          <span>{errorMsg}</span>
        </div>
      )}
      {successMsg && (
        <div className="flex items-center gap-3 p-4 bg-emerald-500/10 border border-emerald-900/30 rounded-lg text-emerald-400 text-xs font-mono">
          <CheckCircle size={16} />
          <span>{successMsg}</span>
        </div>
      )}

      {/* ACTIVE MODEL AND TRAINING ROW */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Model Training Selector */}
        <div className="dark-panel p-6 lg:col-span-2 space-y-4 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2">Model Pipeline Training</h3>
            
            {/* Factory Mode Tabs */}
            <div className="flex gap-2 border-b border-slate-800 pb-2 mb-3">
              <button 
                onClick={() => setFactoryMode('classifier')}
                className={`px-3 py-1 font-mono text-[10px] uppercase rounded transition-colors ${
                  factoryMode === 'classifier' ? 'bg-cyan-600 text-white' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                Supervised
              </button>
              <button 
                onClick={() => setFactoryMode('anomaly')}
                className={`px-3 py-1 font-mono text-[10px] uppercase rounded transition-colors ${
                  factoryMode === 'anomaly' ? 'bg-cyan-600 text-white' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                Unsupervised
              </button>
            </div>

            <div className="space-y-3 text-xs">
              {/* Dataset select */}
              <div className="space-y-1.5">
                <label className="text-[10px] text-slate-500 font-mono">CHOOSE DATASET:</label>
                <select
                  value={selectedDatasetId}
                  onChange={(e) => setSelectedDatasetId(parseInt(e.target.value))}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value={0}>-- Select Preprocessed Dataset --</option>
                  {datasets.map(d => (
                    <option key={d.id} value={d.id}>
                      {d.name} ({d.status})
                    </option>
                  ))}
                </select>
              </div>

              {factoryMode === 'classifier' ? (
                <>
                  {/* Algorithm select */}
                  <div className="space-y-1.5">
                    <label className="text-[10px] text-slate-500 font-mono">ALGORITHM SELECT:</label>
                    <select
                      value={algorithm}
                      onChange={(e) => setAlgorithm(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                    >
                      <option value="XGBoost">XGBoost Classifier (Default)</option>
                      <option value="Random Forest">Random Forest Classifier (Fallback)</option>
                    </select>
                  </div>

                  {/* Split */}
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-[10px] font-mono text-slate-500">
                      <span>TRAIN/TEST SPLIT RATIO:</span>
                      <span className="text-cyan-400 font-semibold">{Math.round(trainSplit*100)}/20</span>
                    </div>
                    <input 
                      type="range" 
                      min={0.5} 
                      max={0.9} 
                      step={0.05} 
                      value={trainSplit} 
                      onChange={(e) => setTrainSplit(parseFloat(e.target.value))}
                      className="w-full accent-cyan-500 bg-slate-900 border border-slate-800 rounded h-1 cursor-pointer"
                    />
                  </div>
                </>
              ) : (
                <>
                  {/* Anomaly parameters */}
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-[10px] font-mono text-slate-500">
                      <span>CONTAMINATION PARAMETER:</span>
                      <span className="text-cyan-400 font-semibold">{Math.round(contamination*100)}%</span>
                    </div>
                    <input 
                      type="range" 
                      min={0.01} 
                      max={0.15} 
                      step={0.01} 
                      value={contamination} 
                      onChange={(e) => setContamination(parseFloat(e.target.value))}
                      className="w-full accent-cyan-500 bg-slate-900 border border-slate-800 rounded h-1 cursor-pointer"
                    />
                  </div>
                </>
              )}
            </div>
          </div>

          <button
            onClick={handleTrainModel}
            disabled={training || selectedDatasetId === 0}
            className="w-full mt-4 flex items-center justify-center gap-2 py-2.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {training ? (
              <>
                <div className="w-4 h-4 rounded-full border-2 border-slate-800 border-t-white animate-spin" />
                <span>Training ML Pipeline...</span>
              </>
            ) : (
              <>
                <Play size={14} />
                <span>Train New Model</span>
              </>
            )}
          </button>
        </div>

        {/* Available Models Library */}
        <div className="dark-panel p-6 lg:col-span-3 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-3">Model Library Vault</h3>
            
            <div className="flex-1 overflow-y-auto space-y-3 pr-2 max-h-[190px] text-xs scrollbar-thin">
              {/* Classifiers list */}
              <div>
                <p className="text-[9px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">Supervised Classifiers</p>
                <div className="space-y-1">
                  {models.filter(m => m.model_type !== 'anomaly').length === 0 ? (
                    <p className="text-slate-600 italic pl-2 text-[10px]">No trained classifiers yet.</p>
                  ) : (
                    models.filter(m => m.model_type !== 'anomaly').map((m) => (
                      <button
                        key={m.id}
                        onClick={() => setSelectedModel(m)}
                        className={`flex items-center justify-between w-full px-3 py-1.5 rounded text-left border transition-all ${
                          selectedModel?.id === m.id 
                            ? 'bg-slate-800/80 border-cyan-600 text-white font-semibold' 
                            : 'border-slate-800/60 text-slate-400 hover:bg-slate-900/50'
                        }`}
                      >
                        <div className="flex items-center gap-1.5">
                          <Cpu size={12} className="text-cyan-500" />
                          <span>{m.name}</span>
                        </div>
                        <div className="flex items-center gap-2 font-mono text-[9px]">
                          <span className="text-slate-500">ACC: <b className="text-slate-300">{m.accuracy ? Math.round(m.accuracy*100) : 0}%</b></span>
                          <span className="px-1 py-0.5 rounded bg-slate-950 text-slate-400 text-[8px] uppercase">
                            {m.algorithm}
                          </span>
                        </div>
                      </button>
                    ))
                  )}
                </div>
              </div>

              {/* Anomaly list */}
              <div className="mt-3">
                <p className="text-[9px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">Unsupervised Anomaly Detectors</p>
                <div className="space-y-1">
                  {models.filter(m => m.model_type === 'anomaly').length === 0 ? (
                    <p className="text-slate-600 italic pl-2 text-[10px]">No trained anomaly models yet.</p>
                  ) : (
                    models.filter(m => m.model_type === 'anomaly').map((m) => (
                      <button
                        key={m.id}
                        onClick={() => setSelectedModel(m)}
                        className={`flex items-center justify-between w-full px-3 py-1.5 rounded text-left border transition-all ${
                          selectedModel?.id === m.id 
                            ? 'bg-slate-800/80 border-cyan-600 text-white font-semibold' 
                            : 'border-slate-800/60 text-slate-400 hover:bg-slate-900/50'
                        }`}
                      >
                        <div className="flex items-center gap-1.5">
                          <Cpu size={12} className="text-cyan-500 animate-pulse" />
                          <span>{m.name}</span>
                        </div>
                        <div className="flex items-center gap-2 font-mono text-[9px]">
                          <span className="text-slate-500">CONTAM: <b className="text-slate-300">{m.contamination ? Math.round(m.contamination*100) : 5}%</b></span>
                          <span className="px-1 py-0.5 rounded bg-slate-950 text-slate-400 text-[8px] uppercase">
                            {m.algorithm}
                          </span>
                        </div>
                      </button>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* METRICS VIEWPORTS */}
      {selectedModel ? (
        selectedModel.model_type === 'anomaly' ? (
          <div className="space-y-8">
            {/* KPI METRIC CARDS */}
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-slate-500 font-mono tracking-wider block">F1 SCORE (EVAL)</span>
                <span className="text-lg font-bold text-white mt-1 block">
                  {selectedModel.metrics_json?.ground_truth_evaluation?.f1_score 
                    ? (selectedModel.metrics_json.ground_truth_evaluation.f1_score * 100).toFixed(1) + '%' 
                    : 'N/A'
                  }
                </span>
              </div>
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-slate-500 font-mono tracking-wider block">CONTAMINATION</span>
                <span className="text-lg font-bold text-slate-300 mt-1 block">
                  {selectedModel.contamination ? (selectedModel.contamination * 100).toFixed(1) + '%' : '5.0%'}
                </span>
              </div>
              <div className="dark-panel p-4 text-center bg-cyan-950/10 border-l-2 border-l-cyan-600">
                <span className="text-[10px] text-cyan-400 font-mono tracking-wider block">ANOMALIES COUNT</span>
                <span className="text-lg font-bold text-white mt-1 block">
                  {selectedModel.metrics_json?.num_anomalies?.toLocaleString() || '0'}
                </span>
              </div>
              <div className="dark-panel p-4 text-center bg-cyan-950/10 border-l-2 border-l-cyan-600">
                <span className="text-[10px] text-cyan-400 font-mono tracking-wider block">ANOMALY RATE</span>
                <span className="text-lg font-bold text-white mt-1 block">
                  {selectedModel.metrics_json?.anomaly_percentage?.toFixed(2) || '0.00'}%
                </span>
              </div>
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-slate-500 font-mono tracking-wider block">AVG SCORE</span>
                <span className="text-lg font-bold text-slate-300 mt-1 block">
                  {selectedModel.metrics_json?.score_distribution?.mean?.toFixed(1) || '0.0'}
                </span>
              </div>
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-slate-500 font-mono tracking-wider block font-semibold text-rose-400">PEAK SCORE</span>
                <span className="text-lg font-bold text-rose-400 mt-1 block">
                  {selectedModel.metrics_json?.score_distribution?.max?.toFixed(1) || '0.0'}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* SCORE DISTRIBUTION QUANTILES */}
              <div className="dark-panel p-6 flex flex-col justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2">Score Quantile Distribution</h3>
                  <p className="text-[11px] text-slate-400 font-light mb-4">Percentile thresholds of anomaly scores calculated by Isolation Forest.</p>
                </div>

                <div className="space-y-2.5 font-mono text-xs">
                  <div className="flex justify-between border-b border-slate-800/60 pb-1">
                    <span className="text-slate-500">MINIMUM SCORE (MOST NORMAL):</span>
                    <span className="text-white font-semibold">{selectedModel.metrics_json?.score_distribution?.min?.toFixed(2) || '0.00'}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/60 pb-1">
                    <span className="text-slate-500">25TH PERCENTILE (Q1):</span>
                    <span className="text-white font-semibold">{selectedModel.metrics_json?.score_distribution?.q25?.toFixed(2) || '0.00'}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/60 pb-1">
                    <span className="text-slate-500">50TH PERCENTILE (MEDIAN):</span>
                    <span className="text-cyan-400 font-semibold">{selectedModel.metrics_json?.score_distribution?.q50?.toFixed(2) || '0.00'}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/60 pb-1">
                    <span className="text-slate-500">75TH PERCENTILE (Q3):</span>
                    <span className="text-white font-semibold">{selectedModel.metrics_json?.score_distribution?.q75?.toFixed(2) || '0.00'}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/60 pb-1">
                    <span className="text-slate-500">MAXIMUM SCORE (MOST ANOMALOUS):</span>
                    <span className="text-rose-400 font-semibold">{selectedModel.metrics_json?.score_distribution?.max?.toFixed(2) || '0.00'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">STANDARD DEVIATION:</span>
                    <span className="text-white font-semibold">{selectedModel.metrics_json?.score_distribution?.std?.toFixed(2) || '0.00'}</span>
                  </div>
                </div>
              </div>

              {/* GROUND TRUTH BENCHMARK */}
              <div className="dark-panel p-6">
                <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2">Ground-Truth Intrusion Benchmark</h3>
                <p className="text-[11px] text-slate-400 font-light mb-4">Comparison of unsupervised outliers against labeled datasets.</p>
                
                {selectedModel.metrics_json?.ground_truth_evaluation ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
                      <div className="bg-slate-900 border border-slate-800 p-2.5 rounded">
                        <p className="text-[9px] text-slate-500">PRECISION</p>
                        <p className="text-sm font-bold text-white mt-1">
                          {(selectedModel.metrics_json.ground_truth_evaluation.precision * 100).toFixed(1)}%
                        </p>
                      </div>
                      <div className="bg-slate-900 border border-slate-800 p-2.5 rounded">
                        <p className="text-[9px] text-slate-500">RECALL</p>
                        <p className="text-sm font-bold text-white mt-1">
                          {(selectedModel.metrics_json.ground_truth_evaluation.recall * 100).toFixed(1)}%
                        </p>
                      </div>
                      <div className="bg-slate-900 border border-slate-800 p-2.5 rounded">
                        <p className="text-[9px] text-slate-500">F1-SCORE</p>
                        <p className="text-sm font-bold text-cyan-400 mt-1">
                          {(selectedModel.metrics_json.ground_truth_evaluation.f1_score * 100).toFixed(1)}%
                        </p>
                      </div>
                    </div>
                    <div className="bg-slate-900/50 border border-slate-800/80 p-3 rounded">
                      <p className="text-[10px] text-slate-500 font-mono uppercase mb-1">Methodology:</p>
                      <p className="text-[10px] text-slate-400 leading-relaxed font-sans">
                        {selectedModel.metrics_json.ground_truth_evaluation.methodology}
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="text-center text-xs py-12 text-slate-500 font-mono">
                    No ground-truth labels available for outlier benchmarking.
                  </div>
                )}
              </div>
            </div>

            {/* FEATURES USED */}
            <div className="dark-panel p-6">
              <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2">Anomaly Feature Columns</h3>
              <p className="text-[11px] text-slate-400 font-light mb-4">Standardized numeric features selected to construct the Isolation Forest tree nodes.</p>
              
              <div className="flex flex-wrap gap-2 text-xs font-mono">
                {selectedModel.features.map(f => (
                  <span key={f} className="px-2.5 py-1 bg-slate-900 border border-slate-800 text-slate-300 rounded uppercase text-[10px]">
                    {f.replace('_', ' ')}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-8">
            {/* KPI METRIC CARDS */}
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-slate-500 font-mono tracking-wider block">ACCURACY</span>
                <span className="text-lg font-bold text-white mt-1 block">{selectedModel.accuracy ? (selectedModel.accuracy * 100).toFixed(2) : '0.00'}%</span>
              </div>
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-slate-500 font-mono tracking-wider block">WEIGHTED PRECISION</span>
                <span className="text-lg font-bold text-slate-300 mt-1 block">{selectedModel.precision_score ? (selectedModel.precision_score * 100).toFixed(2) : '0.00'}%</span>
              </div>
              <div className="dark-panel p-4 border-l-2 border-l-cyan-600 text-center bg-cyan-950/10">
                <span className="text-[10px] text-cyan-400 font-mono tracking-wider block flex items-center justify-center gap-1">
                  WEIGHTED RECALL
                  <span title="Extremely critical metric. Higher recall indicates less missed intrusions."><HelpCircle size={10} /></span>
                </span>
                <span className="text-lg font-bold text-white mt-1 block">{selectedModel.recall_score ? (selectedModel.recall_score * 100).toFixed(2) : '0.00'}%</span>
              </div>
              <div className="dark-panel p-4 border-l-2 border-l-cyan-600 text-center bg-cyan-950/10">
                <span className="text-[10px] text-cyan-400 font-mono tracking-wider block flex items-center justify-center gap-1">
                  WEIGHTED F1
                  <span title="Harmonic mean of precision and recall. Best single measure of model balance."><HelpCircle size={10} /></span>
                </span>
                <span className="text-lg font-bold text-white mt-1 block">{selectedModel.f1_score ? (selectedModel.f1_score * 100).toFixed(2) : '0.00'}%</span>
              </div>
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-slate-500 font-mono tracking-wider block">MACRO F1</span>
                <span className="text-lg font-bold text-slate-300 mt-1 block">
                  {selectedModel.metrics_json?.['macro avg']?.['f1-score'] 
                    ? (selectedModel.metrics_json['macro avg']['f1-score'] * 100).toFixed(2)
                    : 'N/A'
                  }%
                </span>
              </div>
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-slate-500 font-mono tracking-wider block">FEATURES SIZE</span>
                <span className="text-lg font-bold text-white mt-1 block">{selectedModel.features.length}</span>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* HEATMAP / CONFUSION MATRIX */}
              <div className="dark-panel p-6 flex flex-col justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2">Confusion Matrix Heatmap</h3>
                  <p className="text-[11px] text-slate-400 font-light mb-4">Actual Categories (rows) vs Predicted Categories (columns).</p>
                </div>

                {selectedModel.confusion_matrix && selectedModel.confusion_matrix.length > 0 ? (
                  <div className="overflow-x-auto py-2">
                    <div className="min-w-[400px] grid grid-cols-12 gap-1 text-center font-mono text-[10px]">
                      {/* Header corner */}
                      <div className="col-span-3 py-2 text-right pr-2 text-slate-500 font-semibold uppercase">Actual / Pred</div>
                      
                      {/* Headers */}
                      {selectedModel.classes && selectedModel.classes.map((cls, idx) => (
                        <div key={idx} className="col-span-1 py-2 text-slate-400 font-semibold truncate" title={cls}>
                          {cls.substring(0, 5)}
                        </div>
                      ))}
                      
                      {/* Rows */}
                      {selectedModel.confusion_matrix.map((row, rIdx) => (
                        <React.Fragment key={rIdx}>
                          {/* Row label */}
                          <div className="col-span-3 py-2.5 text-right pr-2 font-semibold text-slate-300 truncate" title={selectedModel.classes?.[rIdx]}>
                            {selectedModel.classes?.[rIdx]}
                          </div>
                          
                          {/* Cells */}
                          {row.map((val, cIdx) => (
                            <div
                              key={cIdx}
                              className={`col-span-1 py-2.5 rounded flex items-center justify-center cursor-default transition-all duration-150 ${getMatrixCellColor(
                                val,
                                rIdx,
                                cIdx,
                                maxMatrixVal
                              )}`}
                              title={`Actual: ${selectedModel.classes?.[rIdx]}, Predicted: ${selectedModel.classes?.[cIdx]} -> Count: ${val}`}
                            >
                              {val}
                            </div>
                          ))}
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="text-center text-xs py-12 text-slate-500">Matrix grid unavailable.</div>
                )}
              </div>

              {/* CLASSIFICATION REPORT TABLE */}
              <div className="dark-panel p-6">
                <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-4">Per-Class Classification Report</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-500 text-[10px]">
                        <th className="py-2">ATTACK CLASS</th>
                        <th className="py-2 text-right">PRECISION</th>
                        <th className="py-2 text-right">RECALL</th>
                        <th className="py-2 text-right">F1-SCORE</th>
                        <th className="py-2 text-right">SUPPORT</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-850">
                      {selectedModel.classes && selectedModel.classes.map((cls) => {
                        const classMetrics = selectedModel.metrics_json?.[cls];
                        if (!classMetrics) return null;
                        return (
                          <tr key={cls} className="text-slate-300 hover:bg-slate-900/30">
                            <td className="py-2 font-semibold text-white">{cls}</td>
                            <td className="py-2 text-right">{(classMetrics.precision * 100).toFixed(1)}%</td>
                            <td className="py-2 text-right font-medium text-cyan-400">{(classMetrics.recall * 100).toFixed(1)}%</td>
                            <td className="py-2 text-right font-medium text-cyan-400">{(classMetrics['f1-score'] * 100).toFixed(1)}%</td>
                            <td className="py-2 text-right text-slate-500">{classMetrics.support}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* FEATURE IMPORTANCE */}
            <div className="dark-panel p-6">
              <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-4">Model Feature Importance Indicators</h3>
              
              {importanceData.length > 0 ? (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={importanceData} layout="vertical" margin={{ top: 5, right: 30, left: 100, bottom: 5 }}>
                      <XAxis type="number" stroke="#64748b" fontSize={10} tickLine={false} />
                      <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }}
                        formatter={(val: any) => [`${(val * 100).toFixed(2)}%`, 'Contribution Score']}
                      />
                      <Bar dataKey="value" fill="#0284c7" radius={[0, 4, 4, 0]}>
                        {importanceData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={index === 0 ? '#06b6d4' : '#6366f1'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="text-center text-xs py-12 text-slate-500">Feature importance weights not generated.</div>
              )}
            </div>
          </div>
        )
      ) : (
        <div className="dark-panel p-12 text-center max-w-2xl mx-auto">
          <Activity size={32} className="text-slate-600 mx-auto mb-3" />
          <p className="text-xs text-slate-400">
            Please train or select a trained model from the library above to inspect performance evaluation diagnostic metrics.
          </p>
        </div>
      )}
    </div>
  );
};
