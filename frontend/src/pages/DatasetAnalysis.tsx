import React, { useState, useEffect } from 'react';
import { 
  Upload, 
  FileSpreadsheet, 
  Settings, 
  ChevronRight, 
  AlertCircle, 
  CheckCircle,
  Database,
  BarChart2,
  Trash2
} from 'lucide-react';
import { Dataset, PreprocessConfig } from '../types';
import { apiService } from '../services/api';

interface DatasetAnalysisProps {
  selectedDataset: Dataset | null;
  setSelectedDataset: (dataset: Dataset | null) => void;
  onPreprocessSuccess: () => void;
}

export const DatasetAnalysis: React.FC<DatasetAnalysisProps> = ({
  selectedDataset,
  setSelectedDataset,
  onPreprocessSuccess
}) => {
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [uploading, setUploading] = useState(false);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [previewRows, setPreviewRows] = useState<Record<string, any>[]>([]);
  const [targetColumn, setTargetColumn] = useState<string>('');
  const [trainSplit, setTrainSplit] = useState<number>(0.8);
  const [preprocessing, setPreprocessing] = useState(false);
  const [summary, setSummary] = useState<Record<string, any> | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);

  // Load list of datasets
  async function loadDatasets() {
    try {
      const list = await apiService.getDatasets();
      setDatasets(list);
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.message || "Failed to load datasets.");
    }
  }

  useEffect(() => {
    loadDatasets();
  }, []);

  // Fetch preview when selected dataset changes
  useEffect(() => {
    if (selectedDataset) {
      const datasetId = selectedDataset.id;
      setTargetColumn(selectedDataset.target_column || '');
      setSummary(null);
      setErrorMsg(null);
      
      async function loadPreview() {
        setLoadingPreview(true);
        try {
          const preview = await apiService.getDatasetPreview(datasetId);
          setPreviewRows(preview);
        } catch (err: any) {
          console.error(err);
          setErrorMsg(err.message || "Failed to load preview rows.");
        } finally {
          setLoadingPreview(false);
        }
      }
      loadPreview();
    } else {
      setPreviewRows([]);
    }
  }, [selectedDataset]);

  // Upload handler
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setErrorMsg(null);
    try {
      const ds = await apiService.uploadDataset(file);
      setSelectedDataset(ds);
      await loadDatasets();
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.message || "File upload failed.");
    } finally {
      setUploading(false);
    }
  };

  // Delete dataset handler
  const handleDeleteDataset = async (id: number) => {
    setDeletingId(id);
    setConfirmDeleteId(null);
    setErrorMsg(null);
    try {
      await apiService.deleteDataset(id);
      if (selectedDataset?.id === id) setSelectedDataset(null);
      await loadDatasets();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to delete dataset.');
    } finally {
      setDeletingId(null);
    }
  };

  // Run preprocessing pipeline
  const handlePreprocess = async () => {
    if (!selectedDataset) return;
    if (!targetColumn) {
      setErrorMsg("Please select a target classification column.");
      return;
    }

    setPreprocessing(true);
    setErrorMsg(null);
    try {
      const config: PreprocessConfig = {
        target_column: targetColumn,
        train_test_split: trainSplit
      };
      const res = await apiService.preprocessDataset(selectedDataset.id, config);
      setSummary(res);
      
      // Update local dataset status
      const updated = await apiService.getDataset(selectedDataset.id);
      setSelectedDataset(updated);
      await loadDatasets();
      
      onPreprocessSuccess();
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.message || "Preprocessing execution failed.");
    } finally {
      setPreprocessing(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* ERROR BANNER */}
      {errorMsg && (
        <div className="flex items-center gap-3 p-4 bg-rose-500/10 border border-rose-900/30 rounded-lg text-rose-400 text-xs">
          <AlertCircle size={16} className="shrink-0" />
          <span className="font-mono">{errorMsg}</span>
        </div>
      )}

      {/* UPLOAD & SELECT ZONE */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Upload card */}
        <div className="dark-panel p-6 flex flex-col justify-between min-h-[220px]">
          <div>
            <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2">Upload Network Dataset</h3>
            <p className="text-xs text-slate-400 font-light mb-4">Select or drag an IoT traffic record CSV file to begin analysis.</p>
          </div>
          
          <label className="flex flex-col items-center justify-center border-2 border-dashed border-slate-800 hover:border-cyan-500/50 rounded-lg p-6 bg-slate-900/40 cursor-pointer transition-all duration-200">
            <Upload size={32} className={`mb-2 ${uploading ? 'text-cyan-500 animate-bounce' : 'text-slate-500'}`} />
            <span className="text-xs font-semibold text-slate-300">
              {uploading ? 'Uploading and scanning...' : 'Select CSV File'}
            </span>
            <span className="text-[10px] text-slate-500 font-mono mt-1">MAX SIZE: 150MB</span>
            <input 
              type="file" 
              accept=".csv" 
              className="hidden" 
              onChange={handleFileUpload} 
              disabled={uploading} 
            />
          </label>
        </div>

        {/* Middle: Library selection */}
        <div className="dark-panel p-6 flex flex-col min-h-[220px]">
          <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2">Dataset Library</h3>
          <p className="text-xs text-slate-400 font-light mb-3">Load previously uploaded telemetry files.</p>
          
          <div className="flex-1 overflow-y-auto space-y-1.5 pr-2 max-h-[140px] text-xs">
            {datasets.length === 0 ? (
              <p className="text-slate-500 italic py-4 text-center">No datasets in database.</p>
            ) : (
              datasets.map((ds) => (
                <div key={ds.id} className="space-y-1">
                  <div className={`flex items-center justify-between w-full px-3 py-2 rounded text-left border transition-all ${
                    selectedDataset?.id === ds.id
                      ? 'bg-slate-800/80 border-cyan-600 text-white font-medium shadow-inner'
                      : 'border-slate-800 text-slate-400 hover:bg-slate-900'
                  }`}>
                    <button
                      className="flex items-center gap-2 truncate flex-1 text-left"
                      onClick={() => setSelectedDataset(ds)}
                    >
                      <FileSpreadsheet size={14} className="shrink-0 text-cyan-500" />
                      <span className="truncate">{ds.name}</span>
                      <span className="text-[9px] font-mono text-slate-500 uppercase px-1 bg-slate-950 rounded ml-auto shrink-0">
                        {ds.status}
                      </span>
                    </button>
                    {/* Delete button */}
                    {confirmDeleteId === ds.id ? (
                      <div className="flex items-center gap-1 ml-2 shrink-0">
                        <button
                          onClick={() => handleDeleteDataset(ds.id)}
                          disabled={deletingId === ds.id}
                          className="px-2 py-0.5 rounded bg-rose-600 hover:bg-rose-500 text-white text-[10px] font-mono transition-all"
                        >
                          {deletingId === ds.id ? '...' : 'CONFIRM'}
                        </button>
                        <button
                          onClick={() => setConfirmDeleteId(null)}
                          className="px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-300 text-[10px] font-mono transition-all"
                        >
                          CANCEL
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={(e) => { e.stopPropagation(); setConfirmDeleteId(ds.id); }}
                        disabled={deletingId === ds.id}
                        className="ml-2 shrink-0 p-1 rounded text-slate-600 hover:text-rose-400 hover:bg-rose-500/10 transition-all"
                        title="Remove dataset"
                      >
                        <Trash2 size={13} />
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: Dataset Stats */}
        <div className="dark-panel p-6 flex flex-col justify-between min-h-[220px]">
          <div>
            <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-3">Dataset Inventory</h3>
            {selectedDataset ? (
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between border-b border-slate-800/40 pb-1.5">
                  <span className="text-slate-500">ROWS COUNT:</span>
                  <span className="text-white font-semibold">{selectedDataset.row_count?.toLocaleString()}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800/40 pb-1.5">
                  <span className="text-slate-500">COLUMNS COUNT:</span>
                  <span className="text-white font-semibold">{selectedDataset.col_count}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800/40 pb-1.5">
                  <span className="text-slate-500">TARGET LABEL:</span>
                  <span className="text-cyan-400 font-semibold">{selectedDataset.target_column || 'Not Configured'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">STATUS:</span>
                  <span className={`font-semibold ${selectedDataset.status === 'preprocessed' ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {selectedDataset.status.toUpperCase()}
                  </span>
                </div>
              </div>
            ) : (
              <div className="text-center py-6 text-xs text-slate-500 italic">
                No active dataset selected.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* PREVIEW CONTAINER */}
      {selectedDataset && (
        <div className="dark-panel p-6 space-y-4">
          <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">Raw Telemetry Preview (First 10 Rows)</h3>
          
          {loadingPreview ? (
            <div className="flex justify-center py-12">
              <div className="w-8 h-8 rounded-full border-2 border-slate-800 border-t-cyan-500 animate-spin" />
            </div>
          ) : previewRows.length === 0 ? (
            <div className="text-center py-6 text-xs text-slate-500">
              No preview data available for this dataset.
            </div>
          ) : (
            <div className="overflow-x-auto border border-slate-800/50 rounded max-h-80">
              <table className="w-full text-left text-[11px] font-mono border-collapse">
                <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 sticky top-0">
                  <tr>
                    {Object.keys(previewRows[0]).map((col) => (
                      <th key={col} className="py-2 px-3 border-r border-slate-800/40 whitespace-nowrap">
                        {col}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/40">
                  {previewRows.map((row, rIdx) => (
                    <tr key={rIdx} className="hover:bg-slate-900/50 text-slate-300">
                      {Object.values(row).map((val, cIdx) => (
                        <td key={cIdx} className="py-2 px-3 border-r border-slate-800/20 whitespace-nowrap">
                          {val === null ? 'NaN' : typeof val === 'number' ? val.toLocaleString(undefined, {maximumFractionDigits: 4}) : String(val)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* PIPELINE PREPROCESSING ENGINE */}
      {selectedDataset && (
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          {/* Config panel */}
          <div className="dark-panel p-6 lg:col-span-2 space-y-4">
            <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider flex items-center gap-1.5">
              <Settings size={14} className="text-cyan-500" />
              Configure Pipeline Preprocessing
            </h3>
            
            {/* Target Select */}
            <div className="space-y-1.5">
              <label className="text-[10px] text-slate-500 font-mono">TARGET LABEL / CLASSIFICATION COLUMN:</label>
              <select
                value={targetColumn}
                onChange={(e) => setTargetColumn(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="">-- Choose target column --</option>
                {selectedDataset.columns?.map((col) => (
                  <option key={col} value={col}>
                    {col}
                  </option>
                ))}
              </select>
            </div>

            {/* Split ratio */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-[10px] font-mono">
                <span className="text-slate-500">TRAIN / TEST SPLIT RATIO:</span>
                <span className="text-cyan-400 font-semibold">{Math.round(trainSplit * 100)}% / {Math.round((1 - trainSplit) * 100)}%</span>
              </div>
              <input 
                type="range" 
                min={0.5} 
                max={0.95} 
                step={0.05} 
                value={trainSplit} 
                onChange={(e) => setTrainSplit(parseFloat(e.target.value))}
                className="w-full accent-cyan-500 bg-slate-900 border border-slate-800 rounded h-1 cursor-pointer"
              />
            </div>

            {/* Trigger Button */}
            <button
              onClick={handlePreprocess}
              disabled={preprocessing || !targetColumn}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {preprocessing ? (
                <>
                  <div className="w-4 h-4 rounded-full border-2 border-slate-800 border-t-white animate-spin" />
                  <span>Preprocessing Pipeline...</span>
                </>
              ) : (
                <>
                  <ChevronRight size={14} />
                  <span>Execute Preprocessing</span>
                </>
              )}
            </button>
          </div>

          {/* Preprocessing Summary / Log */}
          <div className="dark-panel p-6 lg:col-span-3 flex flex-col justify-between">
            <div>
              <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-3">Preprocessing Logs & Metrics</h3>
              
              {summary ? (
                <div className="space-y-3 font-mono text-[11px] text-slate-300">
                  <div className="flex items-center gap-2 p-2 bg-emerald-500/10 border border-emerald-900/30 rounded text-emerald-400 mb-2">
                    <CheckCircle size={14} className="shrink-0" />
                    <span>Data clean pipeline completed successfully. Columns verified.</span>
                  </div>

                  <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 max-h-[140px] overflow-y-auto">
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">ORIGINAL RECORDS:</span>
                      <span className="text-white font-semibold">{summary.original_records.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">REMOVED DUPLICATES:</span>
                      <span className="text-white font-semibold">{summary.removed_duplicates.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">NULLS IMMUTATED:</span>
                      <span className="text-white font-semibold">{summary.missing_values_handled.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">FEATURES EXTRAPOLATED:</span>
                      <span className="text-cyan-400 font-semibold">{summary.features_used}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">TARGET LABEL:</span>
                      <span className="text-white font-semibold">{summary.target_column}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">UNIQUE ATTACK TYPES:</span>
                      <span className="text-white font-semibold">{summary.classes.length}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">TRAINING SPLIT:</span>
                      <span className="text-white font-semibold">{summary.training_records.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">TEST EVALUATION SPLIT:</span>
                      <span className="text-white font-semibold">{summary.testing_records.toLocaleString()}</span>
                    </div>
                  </div>

                  <div className="mt-3 bg-slate-900 border border-slate-800 rounded p-2 text-[10px] text-slate-400">
                    <span className="text-cyan-400">DROPPED IDENTIFIERS:</span> {summary.dropped_identifiers.join(', ') || 'None detected'}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-slate-500 text-xs">
                  <Database size={24} className="mb-2 text-slate-600" />
                  <span>Execute preprocessing configurations to generate telemetry indicators.</span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
