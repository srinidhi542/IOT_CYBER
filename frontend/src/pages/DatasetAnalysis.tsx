import React, { useState, useEffect } from 'react';
import { 
  FileSpreadsheet, 
  Database, 
  Trash2,
  Table
} from 'lucide-react';
import { Dataset } from '../types';
import { apiService } from '../services/api';

interface DatasetAnalysisProps {
  selectedDataset: Dataset | null;
  setSelectedDataset: (dataset: Dataset | null) => void;
  onPreprocessSuccess?: () => void;
}

export const DatasetAnalysis: React.FC<DatasetAnalysisProps> = ({
  selectedDataset,
  setSelectedDataset,
}) => {
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [previewRows, setPreviewRows] = useState<Record<string, any>[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);

  // Load list of datasets
  async function loadDatasets() {
    try {
      const list = await apiService.getDatasets();
      setDatasets(list);
      if (list.length > 0 && !selectedDataset) {
        setSelectedDataset(list[0]);
      }
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.message || "Failed to load dataset library.");
    }
  }

  useEffect(() => {
    loadDatasets();
  }, []);

  // Fetch preview when selected dataset changes
  useEffect(() => {
    if (selectedDataset) {
      const datasetId = selectedDataset.id;
      setErrorMsg(null);
      
      async function loadPreview() {
        setLoadingPreview(true);
        try {
          const preview = await apiService.getDatasetPreview(datasetId);
          setPreviewRows(preview);
        } catch (err: any) {
          console.error(err);
          setErrorMsg(err.message || "Failed to load telemetry records.");
        } finally {
          setLoadingPreview(false);
        }
      }
      loadPreview();
    } else {
      setPreviewRows([]);
    }
  }, [selectedDataset]);

  // Delete dataset handler
  const handleDeleteDataset = async (id: number) => {
    setDeletingId(id);
    setConfirmDeleteId(null);
    setErrorMsg(null);
    try {
      await apiService.deleteDataset(id);
      if (selectedDataset?.id === id) {
        const remaining = datasets.filter(d => d.id !== id);
        setSelectedDataset(remaining.length > 0 ? remaining[0] : null);
      }
      await loadDatasets();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to remove dataset.');
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* TOP BAR: DATASET SELECTION & OVERVIEW METADATA */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Dataset Library */}
        <div className="dark-panel p-6 flex flex-col justify-between min-h-[220px]">
          <div>
            <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2 flex items-center gap-2">
              <Database size={15} className="text-cyan-400" />
              Dataset Library
            </h3>
            <p className="text-xs text-slate-400 font-light mb-3">
              Select a telemetry dataset to inspect its raw network features and traffic distribution.
            </p>
          </div>
          
          <div className="flex-1 overflow-y-auto space-y-1.5 pr-2 max-h-[160px] text-xs">
            {datasets.length === 0 ? (
              <p className="text-slate-500 italic py-4 text-center font-mono">No telemetry files in database.</p>
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
                      <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded ml-auto shrink-0 bg-emerald-950/80 text-emerald-400 border border-emerald-800/50">
                        {ds.row_count?.toLocaleString()} rows
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
            <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-3">
              Telemetry Inventory & Details
            </h3>

            {selectedDataset ? (
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between border-b border-slate-800/40 pb-1.5">
                  <span className="text-slate-500">DATASET NAME:</span>
                  <span className="text-white font-semibold">{selectedDataset.name}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800/40 pb-1.5">
                  <span className="text-slate-500">TOTAL RECORDS:</span>
                  <span className="text-cyan-400 font-semibold">{selectedDataset.row_count?.toLocaleString()}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800/40 pb-1.5">
                  <span className="text-slate-500">FEATURE COLUMNS:</span>
                  <span className="text-white font-semibold">{selectedDataset.col_count}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800/40 pb-1.5">
                  <span className="text-slate-500">TARGET CLASSIFICATION:</span>
                  <span className="text-emerald-400 font-semibold">{selectedDataset.target_column || 'Label'}</span>
                </div>
                {selectedDataset.class_distribution && Object.keys(selectedDataset.class_distribution).length > 0 && (
                  <div className="pt-1">
                    <span className="text-slate-500 block mb-1 text-[10px] uppercase">Class Distribution:</span>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                      {Object.entries(selectedDataset.class_distribution).map(([cls, count]) => (
                        <div key={cls} className="flex justify-between text-[10px] pl-2 border-l border-slate-800">
                          <span className="text-slate-400 truncate">{cls}</span>
                          <span className="text-cyan-400 font-semibold ml-2">{count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-8 text-xs text-slate-500 italic font-mono">
                Loading telemetry details...
              </div>
            )}
          </div>
        </div>
      </div>

      {/* PROMINENT RAW TELEMETRY DATA TABLE */}
      {selectedDataset && (
        <div className="dark-panel p-6 space-y-4 border border-slate-800">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
            <div className="flex items-center gap-2">
              <Table size={16} className="text-cyan-400" />
              <h3 className="text-xs font-semibold text-white font-mono uppercase tracking-wider">
                Raw Telemetry Traffic Data
              </h3>
            </div>
            <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
              Showing Preview Records • {selectedDataset.col_count} Features Extracted
            </span>
          </div>
          
          {loadingPreview ? (
            <div className="flex justify-center py-16">
              <div className="w-8 h-8 rounded-full border-2 border-slate-800 border-t-cyan-500 animate-spin" />
            </div>
          ) : previewRows.length === 0 ? (
            <div className="text-center py-10 text-xs text-slate-500 font-mono">
              Loading raw telemetry records...
            </div>
          ) : (
            <div className="overflow-x-auto border border-slate-800/60 rounded-lg max-h-[500px]">
              <table className="w-full text-left text-[11px] font-mono border-collapse">
                <thead className="bg-slate-900/90 border-b border-slate-800 text-slate-300 sticky top-0 backdrop-blur-md">
                  <tr>
                    <th className="py-2.5 px-3 border-r border-slate-800/50 text-slate-500 text-[10px]">#</th>
                    {Object.keys(previewRows[0]).map((col) => (
                      <th key={col} className={`py-2.5 px-3 border-r border-slate-800/40 whitespace-nowrap ${
                        col === selectedDataset.target_column ? 'text-cyan-400 bg-cyan-950/40 font-bold' : ''
                      }`}>
                        {col} {col === selectedDataset.target_column ? '(Target)' : ''}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/40">
                  {previewRows.map((row, rIdx) => (
                    <tr key={rIdx} className="hover:bg-slate-900/60 text-slate-300 transition-colors">
                      <td className="py-2 px-3 border-r border-slate-800/20 text-slate-600 text-[10px]">{rIdx + 1}</td>
                      {Object.entries(row).map(([col, val], cIdx) => (
                        <td key={cIdx} className={`py-2 px-3 border-r border-slate-800/20 whitespace-nowrap ${
                          col === selectedDataset.target_column ? 'text-emerald-400 font-semibold bg-emerald-950/10' : ''
                        }`}>
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
