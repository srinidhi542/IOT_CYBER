import React, { useState, useEffect, lazy, Suspense } from 'react';
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
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
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
    setSuccessMsg(null);
    try {
      const ds = await apiService.uploadDataset(file);
      setSelectedDataset(ds);
      setTargetColumn(ds.target_column || '');
      await loadDatasets();
      setSuccessMsg(`Dataset "${file.name}" uploaded! Target column set to "${ds.target_column}". Click "Execute Preprocessing" below to process.`);
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
    setSuccessMsg(null);
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
      
      setSuccessMsg(`Dataset preprocessed successfully! ${res.features_used} features extracted, ${res.classes?.length || 0} classes detected.`);
      onPreprocessSuccess();
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.message || "Preprocessing execution failed.");
    } finally {
      setPreprocessing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* ERROR BANNER */}
      {errorMsg && (
        <div className="flex items-center gap-3 p-4 bg-rose-500/10 border border-rose-900/30 rounded-lg text-rose-400 text-xs">
          <AlertCircle size={16} className="shrink-0" />
          <span className="font-mono">{errorMsg}</span>
        </div>
      )}

      {/* SUCCESS BANNER */}
      {successMsg && (
        <div className="flex items-center justify-between p-4 bg-emerald-500/10 border border-emerald-900/30 rounded-lg text-emerald-400 text-xs">
          <div className="flex items-center gap-3">
            <CheckCircle size={16} className="shrink-0" />
            <span className="font-mono">{successMsg}</span>
          </div>
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
                      <span className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded ml-auto shrink-0 ${
                        ds.status === 'preprocessed' 
                          ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/50' 
                          : 'bg-slate-950 text-amber-400 border border-amber-800/30'
                      }`}>
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
            
            {selectedDataset && selectedDataset.name === "CICIoT2023_Full" && (
              <div className="mb-4 bg-slate-900/50 p-2 rounded border border-slate-800 text-[10px] font-mono text-slate-400">
                <p><strong>Source:</strong> 309 raw CSV files</p>
                <p><strong>Total Available:</strong> 46,776,697 records</p>
                <p><strong>Features:</strong> 39 network flow metrics</p>
                <p><strong>Mapping:</strong> 34 original attack classes grouped into 8 macro families</p>
              </div>
            )}

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
                  <span className="text-slate-500">MISSING VALUES:</span>
                  <span className="text-white font-semibold">
                    {selectedDataset.missing_counts 
                      ? Object.values(selectedDataset.missing_counts).reduce((a, b) => a + b, 0)
                      : 0}
                  </span>
                </div>
                {selectedDataset.class_distribution && Object.keys(selectedDataset.class_distribution).length > 0 && (
                  <div className="border-b border-slate-800/40 pb-1.5 pt-1">
                    <span className="text-slate-500 block mb-1 text-[10px]">CLASS DISTRIBUTION:</span>
                    {Object.entries(selectedDataset.class_distribution).map(([cls, count]) => (
                      <div key={cls} className="flex justify-between text-[10px] pl-2">
                        <span className="text-slate-400">{cls}</span>
                        <span className="text-cyan-400">{count.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                )}
                <div className="flex justify-between border-b border-slate-800/40 pb-1.5 pt-1">
                  <span className="text-slate-500">TARGET LABEL:</span>
                  <span className="text-cyan-400 font-semibold">{selectedDataset.target_column || 'Not Configured'}</span>
                </div>
                <div className="flex justify-between items-center pt-0.5">
                  <span className="text-slate-500">STATUS:</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                    selectedDataset.status === 'preprocessed' 
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' 
                      : 'bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse'
                  }`}>
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

          {selectedDataset && selectedDataset.status !== 'preprocessed' && (
            <button
              onClick={handlePreprocess}
              disabled={preprocessing || !targetColumn}
              className="mt-3 w-full flex items-center justify-center gap-2 py-2 rounded bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-xs shadow-lg shadow-cyan-900/30 transition-all disabled:opacity-50"
            >
              <span>{preprocessing ? 'Executing Preprocessing...' : `⚡ Execute Preprocessing Now`}</span>
            </button>
          )}
        </div>
      </div>

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
                    {col} {col === selectedDataset.target_column ? '(Auto-Detected Target)' : ''}
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
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-md shadow-cyan-900/20"
            >
              {preprocessing ? (
                <>
                  <div className="w-4 h-4 rounded-full border-2 border-slate-800 border-t-white animate-spin" />
                  <span>Executing Pipeline Preprocessing...</span>
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
                      <span className="text-slate-500">NULLS IMPUTED:</span>
                      <span className="text-white font-semibold">{summary.missing_values_handled.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">FEATURES EXTRACTED:</span>
                      <span className="text-cyan-400 font-semibold">{summary.features_used}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">TARGET LABEL:</span>
                      <span className="text-white font-semibold">{summary.target_column}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">UNIQUE ATTACK TYPES:</span>
                      <span className="text-white font-semibold">{summary.classes?.length || 0}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">TRAINING SPLIT:</span>
                      <span className="text-white font-semibold">{summary.training_records.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500">TEST SPLIT:</span>
                      <span className="text-white font-semibold">{summary.testing_records.toLocaleString()}</span>
                    </div>
                  </div>

                  <div className="mt-3 bg-slate-900 border border-slate-800 rounded p-2 text-[10px] text-slate-400">
                    <span className="text-cyan-400">DROPPED IDENTIFIERS:</span> {summary.dropped_identifiers?.join(', ') || 'None detected'}
                  </div>
                </div>
              ) : selectedDataset.status === 'preprocessed' ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
                  <div className="md:col-span-2 space-y-3 font-mono text-[11px] text-slate-300">
                    <div className="flex items-center gap-2 p-2 bg-emerald-500/10 border border-emerald-900/30 rounded text-emerald-400">
                      <CheckCircle size={14} className="shrink-0" />
                      <span>Dataset is preprocessed and feature distributions are configured.</span>
                    </div>
                    <p className="text-xs text-slate-400 font-sans">
                      All features and class distributions have been extracted and validated against the production schema.
                    </p>
                  </div>
                  <div className="h-28 w-full flex flex-col items-center justify-center rounded-lg border border-emerald-900/30 bg-slate-950/40 text-emerald-400 p-3 text-center">
                    <CheckCircle size={28} className="mb-1 text-emerald-400" />
                    <span className="font-mono text-[10px] tracking-wider uppercase font-semibold">Preprocessed</span>
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
                  <div className="md:col-span-2 flex flex-col justify-center py-6 text-slate-500 text-xs">
                    <Database size={24} className="mb-2 text-slate-600" />
                    <span>Configure target label on the left and click &quot;Execute Preprocessing&quot;.</span>
                  </div>
                  <div className="h-28 w-full flex flex-col items-center justify-center rounded-lg border border-slate-800 bg-slate-950/40 text-slate-500 p-3 text-center">
                    <Database size={28} className="mb-1 text-slate-600" />
                    <span className="font-mono text-[10px] tracking-wider uppercase font-semibold">Awaiting Preprocessing</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* PREVIEW CONTAINER */}
      {selectedDataset && (
        <div className="dark-panel p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">
              Raw Telemetry Preview (First 10 Rows)
            </h3>
            <span className="text-[10px] font-mono text-slate-500">
              {selectedDataset.col_count} columns • {selectedDataset.row_count?.toLocaleString()} total records
            </span>
          </div>
          
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
                      <th key={col} className={`py-2 px-3 border-r border-slate-800/40 whitespace-nowrap ${
                        col === selectedDataset.target_column ? 'text-cyan-400 bg-cyan-950/30' : ''
                      }`}>
                        {col} {col === selectedDataset.target_column ? '(Target)' : ''}
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
    </div>
  );
};
