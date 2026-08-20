import React, { useState, useEffect } from 'react';
import {
  Microscope,
  AlertCircle,
  ChevronUp,
  Shield,
  Zap,
  BarChart2,
  Info,
  CheckCircle,
  Search
} from 'lucide-react';
import { apiService } from '../services/api';

interface ExplainabilityProps {
  threatId: number | null;
  onSelectThreat: (id: number) => void;
}

interface FeatureContribution {
  feature: string;
  value: number;
  importance: number;
  contribution: number;
  direction: 'HIGH' | 'LOW';
}

interface ExplainResult {
  threat_id: number;
  record_index: number;
  attack_type: string;
  severity: string;
  risk_score: number;
  anomaly_score: number;
  anomaly_status: string;
  confidence: number;
  feature_contributions: FeatureContribution[];
  explanation: { summary: string; details: string[] };
  detection_reason: string[];
  recommended_actions: string[];
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'text-rose-400 bg-rose-950/30 border-rose-900/40',
  High: 'text-orange-400 bg-orange-950/30 border-orange-900/40',
  Medium: 'text-amber-400 bg-amber-950/30 border-amber-900/40',
  Low: 'text-emerald-400 bg-emerald-950/30 border-emerald-900/40',
};

export const Explainability: React.FC<ExplainabilityProps> = ({ threatId, onSelectThreat }) => {
  const [inputId, setInputId] = useState<string>(threatId ? String(threatId) : '');
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<ExplainResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchExplanation = async (id: number) => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const result = await apiService.explainThreat(id) as ExplainResult;
      setData(result);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load explanation.');
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (threatId) {
      setInputId(String(threatId));
      fetchExplanation(threatId);
    }
  }, [threatId]);

  const handleSearch = () => {
    const id = parseInt(inputId, 10);
    if (!isNaN(id) && id > 0) {
      onSelectThreat(id);
      fetchExplanation(id);
    }
  };

  const top10 = data ? data.feature_contributions.slice(0, 10) : [];
  const maxContrib = top10.length > 0 ? Math.max(...top10.map(f => f.contribution)) : 1;

  return (
    <div className="space-y-6">
      {/* Header search bar */}
      <div className="dark-panel p-5 flex items-center gap-4">
        <Microscope size={20} className="text-violet-400 shrink-0" />
        <div className="flex-1">
          <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">
            Threat Explainability Engine
          </h3>
          <p className="text-[10px] text-slate-500 mt-0.5">
            Enter a Threat ID or click &quot;Explain&quot; on any threat row in the Threat Detection page.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="number"
            min={1}
            value={inputId}
            onChange={(e) => setInputId(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="Threat ID..."
            className="bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-white w-32 focus:outline-none focus:border-violet-500 font-mono"
          />
          <button
            onClick={handleSearch}
            disabled={loading || !inputId}
            className="flex items-center gap-1.5 px-4 py-2 rounded bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold disabled:opacity-50 transition-all"
          >
            {loading ? (
              <div className="w-3.5 h-3.5 rounded-full border-2 border-violet-300 border-t-transparent animate-spin" />
            ) : (
              <Search size={13} />
            )}
            Analyze
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="flex items-center gap-3 p-4 bg-rose-500/10 border border-rose-900/30 rounded-lg text-rose-400 text-xs">
          <AlertCircle size={15} className="shrink-0" />
          <span className="font-mono">{errorMsg}</span>
        </div>
      )}

      {!loading && !data && !errorMsg && (
        <div className="dark-panel p-16 flex flex-col items-center justify-center text-slate-600 space-y-3">
          <Microscope size={40} className="text-slate-700" />
          <p className="text-sm font-medium text-slate-500">No threat selected</p>
          <p className="text-xs text-slate-600 text-center max-w-xs">
            Click Explain on a threat row in the Threat Detection page, or enter a Threat ID above and click Analyze.
          </p>
        </div>
      )}

      {data && (
        <>
          {/* Threat Summary Header */}
          <div className="dark-panel p-5 grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="md:col-span-2">
              <p className="text-[10px] text-slate-500 font-mono uppercase mb-1">Attack Classification</p>
              <p className="text-lg font-bold text-white">{data.attack_type}</p>
              <span className={`inline-flex items-center gap-1 mt-1 px-2 py-0.5 rounded-full text-[10px] font-mono border ${SEVERITY_COLORS[data.severity] || SEVERITY_COLORS.Low}`}>
                {data.severity}
              </span>
            </div>
            <div className="border-l border-slate-800 pl-4">
              <p className="text-[10px] text-slate-500 font-mono uppercase mb-1">Risk Score</p>
              <p className={`text-2xl font-bold font-mono ${data.risk_score >= 75 ? 'text-rose-400' : data.risk_score >= 50 ? 'text-orange-400' : data.risk_score >= 25 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {data.risk_score?.toFixed(1)}
              </p>
            </div>
            <div className="border-l border-slate-800 pl-4">
              <p className="text-[10px] text-slate-500 font-mono uppercase mb-1">Anomaly Score</p>
              <p className={`text-2xl font-bold font-mono ${(data.anomaly_score ?? 0) >= 70 ? 'text-rose-400' : (data.anomaly_score ?? 0) >= 50 ? 'text-amber-400' : 'text-slate-300'}`}>
                {data.anomaly_score?.toFixed(1) ?? '-'}
              </p>
              <p className={`text-[10px] font-mono mt-0.5 ${data.anomaly_status === 'Anomalous' ? 'text-rose-400' : 'text-emerald-400'}`}>
                {data.anomaly_status ?? '-'}
              </p>
            </div>
            <div className="border-l border-slate-800 pl-4">
              <p className="text-[10px] text-slate-500 font-mono uppercase mb-1">Confidence</p>
              <p className="text-2xl font-bold font-mono text-cyan-400">{(data.confidence * 100).toFixed(1)}%</p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">Record #{data.record_index}</p>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {/* Feature Contribution Bar Chart */}
            <div className="dark-panel p-5 space-y-4">
              <div className="flex items-center gap-2">
                <BarChart2 size={15} className="text-violet-400" />
                <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">
                  Top Feature Contributions
                </h3>
              </div>
              <p className="text-[10px] text-slate-500">
                Contribution = global importance weight x normalized feature value. Higher bars indicate features that most influenced this classification.
              </p>
              <div className="space-y-2.5">
                {top10.map((feat, i) => {
                  const barPct = maxContrib > 0 ? (feat.contribution / maxContrib) * 100 : 0;
                  const isHigh = feat.importance > 0.05;
                  return (
                    <div key={feat.feature} className="space-y-0.5">
                      <div className="flex justify-between items-center text-[10px] font-mono">
                        <span className={`truncate max-w-[180px] ${isHigh ? 'text-slate-200' : 'text-slate-400'}`}>
                          {i + 1}. {feat.feature.replace(/_/g, ' ')}
                        </span>
                        <div className="flex items-center gap-3 shrink-0">
                          <span className="text-slate-500">imp: {(feat.importance * 100).toFixed(1)}%</span>
                          <span className={`font-semibold ${feat.contribution > 5 ? 'text-rose-400' : feat.contribution > 2 ? 'text-amber-400' : 'text-slate-300'}`}>
                            {feat.contribution.toFixed(2)}
                          </span>
                        </div>
                      </div>
                      <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            feat.contribution > 5 ? 'bg-rose-500' :
                            feat.contribution > 2 ? 'bg-amber-400' :
                            'bg-violet-500'
                          }`}
                          style={{ width: `${barPct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* AI Reasoning + Recommended Actions */}
            <div className="space-y-4">
              <div className="dark-panel p-5 space-y-3">
                <div className="flex items-center gap-2">
                  <Zap size={14} className="text-amber-400" />
                  <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">
                    Detection Reasoning
                  </h3>
                </div>
                {data.explanation?.summary && (
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded text-xs text-slate-300 leading-relaxed">
                    {data.explanation.summary}
                  </div>
                )}
                {data.detection_reason.length > 0 && (
                  <ul className="space-y-1.5">
                    {data.detection_reason.map((reason, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-slate-400">
                        <ChevronUp size={13} className="text-rose-400 shrink-0 mt-0.5" />
                        {reason}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="dark-panel p-5 space-y-3">
                <div className="flex items-center gap-2">
                  <Shield size={14} className="text-cyan-400" />
                  <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">
                    Recommended Response Actions
                  </h3>
                </div>
                {data.recommended_actions.length > 0 ? (
                  <ul className="space-y-1.5">
                    {data.recommended_actions.map((action, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                        <CheckCircle size={12} className="text-emerald-400 shrink-0 mt-0.5" />
                        {action}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-slate-500 italic">No specific actions recommended.</p>
                )}
              </div>
            </div>
          </div>

          {/* Full Feature Breakdown Table */}
          <div className="dark-panel p-5 space-y-3">
            <div className="flex items-center gap-2">
              <Info size={14} className="text-slate-400" />
              <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">
                Full Feature Breakdown ({data.feature_contributions.length} features)
              </h3>
            </div>
            <div className="overflow-x-auto border border-slate-800/50 rounded max-h-72">
              <table className="w-full text-left text-[11px] font-mono border-collapse">
                <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 sticky top-0">
                  <tr>
                    <th className="py-2 px-3 border-r border-slate-800/40">Feature</th>
                    <th className="py-2 px-3 border-r border-slate-800/40">Actual Value</th>
                    <th className="py-2 px-3 border-r border-slate-800/40">Global Importance</th>
                    <th className="py-2 px-3 border-r border-slate-800/40">Contribution Score</th>
                    <th className="py-2 px-3">Direction</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/40">
                  {data.feature_contributions.map((feat) => (
                    <tr key={feat.feature} className="hover:bg-slate-900/50 text-slate-300">
                      <td className="py-2 px-3 border-r border-slate-800/20 text-slate-200 font-medium">
                        {feat.feature.replace(/_/g, ' ')}
                      </td>
                      <td className="py-2 px-3 border-r border-slate-800/20 text-cyan-300">
                        {typeof feat.value === 'number'
                          ? feat.value.toLocaleString(undefined, { maximumFractionDigits: 4 })
                          : String(feat.value)}
                      </td>
                      <td className="py-2 px-3 border-r border-slate-800/20">
                        <div className="flex items-center gap-2">
                          <div className="h-1 w-16 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-violet-500 rounded-full"
                              style={{ width: `${Math.min((feat.importance * 100), 100).toFixed(0)}%` }}
                            />
                          </div>
                          <span>{(feat.importance * 100).toFixed(2)}%</span>
                        </div>
                      </td>
                      <td className="py-2 px-3 border-r border-slate-800/20">
                        <span className={`font-semibold ${
                          feat.contribution > 5 ? 'text-rose-400' :
                          feat.contribution > 2 ? 'text-amber-400' :
                          'text-slate-300'
                        }`}>
                          {feat.contribution.toFixed(3)}
                        </span>
                      </td>
                      <td className="py-2 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[9px] ${
                          feat.direction === 'HIGH'
                            ? 'bg-rose-950/30 text-rose-400 border border-rose-900/30'
                            : 'bg-emerald-950/30 text-emerald-400 border border-emerald-900/30'
                        }`}>
                          {feat.direction === 'HIGH' ? 'HIGH' : 'LOW'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
