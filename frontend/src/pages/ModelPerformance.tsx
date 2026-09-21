import React, { useState, useEffect } from 'react';
import { Activity, Cpu, BarChart3, TrendingUp, Layers } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, Legend, CartesianGrid } from 'recharts';
import { MLModel } from '../types';
import { apiService } from '../services/api';

interface ModelPerformanceProps {
  selectedModel: MLModel | null;
  setSelectedModel: (model: MLModel | null) => void;
}

export const ModelPerformance: React.FC<ModelPerformanceProps> = ({
  selectedModel,
  setSelectedModel,
}) => {
  const [models, setModels] = useState<MLModel[]>([]);

  async function loadModels() {
    try {
      const list = await apiService.getModels();
      setModels(list);
      if (list.length > 0 && !selectedModel) {
        setSelectedModel(list[0]);
      }
    } catch (err: any) {
      console.error(err);
    }
  }

  useEffect(() => {
    loadModels();
  }, [selectedModel]);

  const formatFeatureImportance = (importance: Record<string, number> | null) => {
    if (!importance) return [];
    return Object.entries(importance)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, value]) => ({ name: name.replace('_', ' ').replace('Total', '').trim(), value }));
  };

  const importanceData = formatFeatureImportance(selectedModel?.feature_importance || null);

  const perClassData = (selectedModel?.classes || []).map(cls => {
    const classReport = selectedModel?.metrics_json?.classification_report || selectedModel?.metrics_json;
    const metrics = classReport?.[cls];
    return {
      name: cls,
      Precision: metrics ? Number((metrics.precision * 100).toFixed(1)) : 0,
      Recall: metrics ? Number((metrics.recall * 100).toFixed(1)) : 0,
      'F1-Score': metrics ? Number((metrics['f1-score'] * 100).toFixed(1)) : 0,
      support: metrics ? metrics.support : 0
    };
  });

  const getMatrixCellColor = (value: number, rowIdx: number, colIdx: number, maxVal: number) => {
    if (maxVal === 0) return 'bg-slate-900';
    const intensity = Math.min(90, Math.max(10, Math.round((value / maxVal) * 90)));
    if (rowIdx === colIdx) return `bg-emerald-500/${intensity} text-white font-semibold`;
    return value > 0 ? `bg-rose-500/${intensity} text-rose-200` : 'bg-slate-900/40 text-slate-600';
  };

  const getMaxMatrixValue = (matrix: number[][] | null | undefined) => {
    if (!matrix || matrix.length === 0) return 0;
    return Math.max(...matrix.map(row => Math.max(...row)));
  };
  const maxMatrixVal = getMaxMatrixValue(selectedModel?.confusion_matrix);

  return (
    <div className="space-y-8">

      {/* MODEL LIBRARY */}
      <div className="dark-panel p-6">
        <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-3">Model Library Vault</h3>
        <div className="space-y-4">
          <div>
            <p className="text-[9px] font-mono text-slate-500 uppercase tracking-widest mb-2">Supervised Classifiers</p>
            <div className="space-y-1">
              {models.filter(m => m.model_type !== 'anomaly').length === 0 ? (
                <p className="text-slate-600 italic pl-2 text-[10px]">No classifiers available.</p>
              ) : (
                models.filter(m => m.model_type !== 'anomaly').map((m) => (
                  <button
                    key={m.id}
                    onClick={() => setSelectedModel(m)}
                    className={`flex items-center justify-between w-full px-3 py-2 rounded text-left border transition-all ${
                      selectedModel?.id === m.id
                        ? 'bg-slate-800/80 border-cyan-600 text-white font-semibold'
                        : 'border-slate-800/60 text-slate-400 hover:bg-slate-900/50'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <Cpu size={12} className="text-cyan-500" />
                      <span className="text-xs">{m.name}</span>
                      {selectedModel?.id === m.id && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-emerald-900/40 text-emerald-400 border border-emerald-800/40">ACTIVE</span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 font-mono text-[10px]">
                      <span className="text-slate-500">ACC: <b className="text-slate-200">{m.accuracy ? (m.accuracy * 100).toFixed(2) : '0'}%</b></span>
                      <span className="px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 text-[9px] uppercase">{m.algorithm}</span>
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>
          <div>
            <p className="text-[9px] font-mono text-slate-500 uppercase tracking-widest mb-2">Unsupervised Anomaly Detectors</p>
            <div className="space-y-1">
              {models.filter(m => m.model_type === 'anomaly').length === 0 ? (
                <p className="text-slate-600 italic pl-2 text-[10px]">No anomaly models available.</p>
              ) : (
                models.filter(m => m.model_type === 'anomaly').map((m) => (
                  <button
                    key={m.id}
                    onClick={() => setSelectedModel(m)}
                    className={`flex items-center justify-between w-full px-3 py-2 rounded text-left border transition-all ${
                      selectedModel?.id === m.id
                        ? 'bg-slate-800/80 border-cyan-600 text-white font-semibold'
                        : 'border-slate-800/60 text-slate-400 hover:bg-slate-900/50'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <Cpu size={12} className="text-cyan-500 animate-pulse" />
                      <span className="text-xs">{m.name}</span>
                    </div>
                    <div className="flex items-center gap-3 font-mono text-[10px]">
                      <span className="text-slate-500">CONTAM: <b className="text-slate-200">{m.contamination ? (m.contamination * 100).toFixed(1) : '5.0'}%</b></span>
                      <span className="px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 text-[9px] uppercase">{m.algorithm}</span>
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* METRICS */}
      {selectedModel ? (
        selectedModel.model_type === 'anomaly' ? (
          <div className="space-y-8">
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-slate-500 font-mono tracking-wider block">F1 SCORE (EVAL)</span>
                <span className="text-lg font-bold text-white mt-1 block">
                  {selectedModel.metrics_json?.ground_truth_evaluation?.f1_score ? (selectedModel.metrics_json.ground_truth_evaluation.f1_score * 100).toFixed(1) + '%' : 'N/A'}
                </span>
              </div>
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-slate-500 font-mono tracking-wider block">CONTAMINATION</span>
                <span className="text-lg font-bold text-slate-300 mt-1 block">{selectedModel.contamination ? (selectedModel.contamination * 100).toFixed(1) + '%' : '5.0%'}</span>
              </div>
              <div className="dark-panel p-4 text-center bg-cyan-950/10 border-l-2 border-l-cyan-600">
                <span className="text-[10px] text-cyan-400 font-mono tracking-wider block">ANOMALIES COUNT</span>
                <span className="text-lg font-bold text-white mt-1 block">{selectedModel.metrics_json?.num_anomalies?.toLocaleString() || '0'}</span>
              </div>
              <div className="dark-panel p-4 text-center bg-cyan-950/10 border-l-2 border-l-cyan-600">
                <span className="text-[10px] text-cyan-400 font-mono tracking-wider block">ANOMALY RATE</span>
                <span className="text-lg font-bold text-white mt-1 block">{selectedModel.metrics_json?.anomaly_percentage?.toFixed(2) || '0.00'}%</span>
              </div>
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-slate-500 font-mono tracking-wider block">AVG SCORE</span>
                <span className="text-lg font-bold text-slate-300 mt-1 block">{selectedModel.metrics_json?.score_distribution?.mean?.toFixed(1) || '0.0'}</span>
              </div>
              <div className="dark-panel p-4 text-center">
                <span className="text-[10px] text-rose-400 font-mono tracking-wider block">PEAK SCORE</span>
                <span className="text-lg font-bold text-rose-400 mt-1 block">{selectedModel.metrics_json?.score_distribution?.max?.toFixed(1) || '0.0'}</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-8">
            {selectedModel.metrics_json?.cross_validation && (
              <div className="p-4 rounded-lg bg-gradient-to-r from-cyan-950/40 via-slate-900/60 to-slate-900/40 border border-cyan-800/40">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                      <h4 className="text-xs font-mono font-bold uppercase text-cyan-300 tracking-wider">5-Fold Stratified Cross-Validation</h4>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1">Performed strictly on training data without touching the test set.</p>
                  </div>
                  <div className="flex items-center gap-6 font-mono">
                    <div className="text-right">
                      <span className="text-[9px] text-slate-500 uppercase block">CV Mean Accuracy</span>
                      <span className="text-base font-bold text-white">{(selectedModel.metrics_json.cross_validation.mean_accuracy * 100).toFixed(2)}%</span>
                    </div>
                    <div className="text-right">
                      <span className="text-[9px] text-slate-500 uppercase block">Std Deviation</span>
                      <span className="text-base font-bold text-cyan-400">±{(selectedModel.metrics_json.cross_validation.std_accuracy * 100).toFixed(2)}%</span>
                    </div>
                  </div>
                </div>
                {selectedModel.metrics_json.cross_validation.scores && (
                  <div className="flex items-center gap-2 mt-3 pt-2.5 border-t border-slate-800/60 font-mono text-[10px]">
                    <span className="text-slate-500 uppercase">Fold Scores:</span>
                    {selectedModel.metrics_json.cross_validation.scores.map((sc: number, idx: number) => (
                      <span key={idx} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                        Fold {idx + 1}: <b className="text-white">{(sc * 100).toFixed(1)}%</b>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono">
              <div className="dark-panel p-4 flex flex-col justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">ACCURACY</span>
                <div className="my-2 space-y-1">
                  <div className="flex justify-between text-xs"><span className="text-slate-400">Train:</span><span className="text-emerald-400 font-bold">{selectedModel.metrics_json?.train_metrics?.accuracy ? (selectedModel.metrics_json.train_metrics.accuracy * 100).toFixed(2) + '%' : '100.00%'}</span></div>
                  <div className="flex justify-between text-xs"><span className="text-slate-400">Test:</span><span className="text-cyan-400 font-bold">{selectedModel.accuracy ? (selectedModel.accuracy * 100).toFixed(2) + '%' : '0.00%'}</span></div>
                </div>
                <div className="pt-2 border-t border-slate-800/60 flex justify-between text-[10px]">
                  <span className="text-slate-500">Gap (Overfit):</span>
                  <span className="text-amber-400 font-bold">{selectedModel.metrics_json?.performance_gap !== undefined ? (selectedModel.metrics_json.performance_gap * 100).toFixed(2) + '%' : selectedModel.accuracy ? ((1 - selectedModel.accuracy) * 100).toFixed(2) + '%' : '0.00%'}</span>
                </div>
              </div>
              <div className="dark-panel p-4 flex flex-col justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">WEIGHTED PRECISION</span>
                <div className="my-2 space-y-1">
                  <div className="flex justify-between text-xs"><span className="text-slate-400">Train:</span><span className="text-emerald-400 font-bold">{selectedModel.metrics_json?.train_metrics?.precision ? (selectedModel.metrics_json.train_metrics.precision * 100).toFixed(2) + '%' : '100.00%'}</span></div>
                  <div className="flex justify-between text-xs"><span className="text-slate-400">Test:</span><span className="text-cyan-400 font-bold">{selectedModel.precision_score ? (selectedModel.precision_score * 100).toFixed(2) + '%' : '0.00%'}</span></div>
                </div>
                <div className="pt-2 border-t border-slate-800/60 flex justify-between text-[10px]">
                  <span className="text-slate-500">Confidence:</span>
                  <span className="text-slate-300 font-bold">{selectedModel.metrics_json?.avg_confidence ? (selectedModel.metrics_json.avg_confidence * 100).toFixed(1) + '%' : 'N/A'}</span>
                </div>
              </div>
              <div className="dark-panel p-4 flex flex-col justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">WEIGHTED RECALL</span>
                <div className="my-2 space-y-1">
                  <div className="flex justify-between text-xs"><span className="text-slate-400">Train:</span><span className="text-emerald-400 font-bold">{selectedModel.metrics_json?.train_metrics?.recall ? (selectedModel.metrics_json.train_metrics.recall * 100).toFixed(2) + '%' : '100.00%'}</span></div>
                  <div className="flex justify-between text-xs"><span className="text-slate-400">Test:</span><span className="text-cyan-400 font-bold">{selectedModel.recall_score ? (selectedModel.recall_score * 100).toFixed(2) + '%' : '0.00%'}</span></div>
                </div>
              </div>
              <div className="dark-panel p-4 flex flex-col justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">WEIGHTED F1-SCORE</span>
                <div className="my-2 space-y-1">
                  <div className="flex justify-between text-xs"><span className="text-slate-400">Train:</span><span className="text-emerald-400 font-bold">{selectedModel.metrics_json?.train_metrics?.f1 ? (selectedModel.metrics_json.train_metrics.f1 * 100).toFixed(2) + '%' : '100.00%'}</span></div>
                  <div className="flex justify-between text-xs"><span className="text-slate-400">Test:</span><span className="text-cyan-400 font-bold">{selectedModel.f1_score ? (selectedModel.f1_score * 100).toFixed(2) + '%' : '0.00%'}</span></div>
                </div>
                <div className="pt-2 border-t border-slate-800/60 flex justify-between text-[10px]">
                  <span className="text-slate-500">Macro F1:</span>
                  <span className="text-slate-300 font-bold">{selectedModel.metrics_json?.['macro avg']?.['f1-score'] ? (selectedModel.metrics_json['macro avg']['f1-score'] * 100).toFixed(2) + '%' : selectedModel.f1_score ? (selectedModel.f1_score * 100).toFixed(2) + '%' : 'N/A'}</span>
                </div>
              </div>
            </div>

            {/* PER-CLASS VISUAL PERFORMANCE COMPARISON CHART */}
            {perClassData.length > 0 && (
              <div className="dark-panel p-6 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800/80">
                  <div className="flex items-center gap-2">
                    <BarChart3 size={16} className="text-cyan-400" />
                    <div>
                      <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">
                        Per-Class Attack Detection Benchmarks (Precision / Recall / F1)
                      </h3>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        Comparative performance evaluation across all 8 evaluated IoT attack categories.
                      </p>
                    </div>
                  </div>
                  <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/40 text-cyan-400 uppercase shrink-0">
                    Interactive Multi-Metric Chart
                  </span>
                </div>

                <div className="h-72 w-full pt-2">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={perClassData} margin={{ top: 10, right: 20, left: -10, bottom: 25 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.6} />
                      <XAxis 
                        dataKey="name" 
                        stroke="#64748b" 
                        fontSize={11} 
                        tickLine={false} 
                        interval={0}
                        angle={-15}
                        textAnchor="end"
                      />
                      <YAxis 
                        stroke="#64748b" 
                        fontSize={10} 
                        tickLine={false} 
                        domain={[0, 100]} 
                        unit="%" 
                      />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }} 
                        formatter={(val: any, name: string) => [`${val}%`, name]}
                      />
                      <Legend 
                        wrapperStyle={{ paddingTop: '10px', fontSize: '11px', fontFamily: 'monospace' }} 
                      />
                      <Bar dataKey="Precision" fill="#06b6d4" radius={[3, 3, 0, 0]} />
                      <Bar dataKey="Recall" fill="#10b981" radius={[3, 3, 0, 0]} />
                      <Bar dataKey="F1-Score" fill="#818cf8" radius={[3, 3, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="dark-panel p-6 flex flex-col justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2">Confusion Matrix Heatmap</h3>
                  <p className="text-[11px] text-slate-400 font-light mb-4">Actual Categories (rows) vs Predicted Categories (columns).</p>
                </div>
                {selectedModel.confusion_matrix && selectedModel.confusion_matrix.length > 0 ? (
                  <div className="overflow-x-auto py-2">
                    <div className="min-w-[400px] grid grid-cols-12 gap-1 text-center font-mono text-[10px]">
                      <div className="col-span-3 py-2 text-right pr-2 text-slate-500 font-semibold uppercase">Actual / Pred</div>
                      {selectedModel.classes && selectedModel.classes.map((cls, idx) => (
                        <div key={idx} className="col-span-1 py-2 text-slate-400 font-semibold truncate" title={cls}>{cls.substring(0, 5)}</div>
                      ))}
                      {selectedModel.confusion_matrix.map((row, rIdx) => (
                        <React.Fragment key={rIdx}>
                          <div className="col-span-3 py-2.5 text-right pr-2 font-semibold text-slate-300 truncate" title={selectedModel.classes?.[rIdx]}>{selectedModel.classes?.[rIdx]}</div>
                          {row.map((val, cIdx) => (
                            <div key={cIdx} className={`col-span-1 py-2.5 rounded flex items-center justify-center cursor-default ${getMatrixCellColor(val, rIdx, cIdx, maxMatrixVal)}`} title={`Actual: ${selectedModel.classes?.[rIdx]}, Predicted: ${selectedModel.classes?.[cIdx]} -> Count: ${val}`}>{val}</div>
                          ))}
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="text-center text-xs py-12 text-slate-500">Matrix grid unavailable.</div>
                )}
              </div>

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
                        const classReport = selectedModel.metrics_json?.classification_report || selectedModel.metrics_json;
                        const classMetrics = classReport?.[cls];
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

            <div className="dark-panel p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">Global Feature Importance (XGBoost Gain)</h3>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Global tree split contribution weights across all 39 network features. For local sample-level attribution, see AI SHAP Explainability on the Dashboard.
                  </p>
                </div>
                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/40 text-cyan-400 uppercase">
                  Global Importance
                </span>
              </div>
              {importanceData.length > 0 ? (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={importanceData} layout="vertical" margin={{ top: 5, right: 30, left: 100, bottom: 5 }}>
                      <XAxis type="number" stroke="#64748b" fontSize={10} tickLine={false} />
                      <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }} formatter={(val: any) => [`${(val * 100).toFixed(2)}%`, 'Contribution Score']} />
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
          <p className="text-xs text-slate-400">Select a trained model from the library above to inspect performance evaluation diagnostic metrics.</p>
        </div>
      )}
    </div>
  );
};
