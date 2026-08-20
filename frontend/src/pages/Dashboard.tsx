import React, { useEffect, useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Percent, 
  Cpu, 
  Clock, 
  Activity, 
  AlertOctagon, 
  FileText
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  Legend, 
  LineChart, 
  Line, 
  CartesianGrid 
} from 'recharts';
import { DashboardAnalytics, Threat } from '../types';
import { apiService } from '../services/api';

interface DashboardProps {
  analytics: DashboardAnalytics | null;
  loading: boolean;
  refreshData: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  analytics,
  loading,
  refreshData
}) => {
  const [recentThreats, setRecentThreats] = useState<Threat[]>([]);
  const [threatsLoading, setThreatsLoading] = useState(false);

  useEffect(() => {
    async function loadRecentThreats() {
      setThreatsLoading(true);
      try {
        const threats = await apiService.getThreats();
        // Display latest 10
        setRecentThreats(threats.slice(0, 12));
      } catch (err) {
        console.error("Failed to load recent threats", err);
      } finally {
        setThreatsLoading(false);
      }
    }

    loadRecentThreats();
  }, [analytics]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] gap-4">
        <div className="w-12 h-12 rounded-full border-4 border-slate-800 border-t-cyan-500 animate-spin" />
        <p className="text-slate-400 font-mono text-xs">AQUIRING TELEMETRY SYSTEMS...</p>
      </div>
    );
  }

  // Fallback / Empty state if no data uploaded yet
  if (!analytics || analytics.total_records === 0) {
    return (
      <div className="dark-panel p-12 text-center max-w-2xl mx-auto mt-12">
        <ShieldCheck size={48} className="text-slate-500 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-white mb-2">No Active Telemetry Found</h3>
        <p className="text-sm text-slate-400 mb-6">
          To initialize the dashboard, please upload a dataset CSV and run threat detection.
        </p>
        <button
          onClick={refreshData}
          className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded transition-colors"
        >
          Check Status / Refresh
        </button>
      </div>
    );
  }

  const benignPercent = (analytics.benign_count / analytics.total_records) * 100;
  const maliciousPercent = (analytics.malicious_count / analytics.total_records) * 100;

  // Chart data formatting
  const colorsList = ['#10b981', '#ef4444', '#f59e0b', '#6366f1', '#a855f7', '#06b6d4', '#ec4899'];
  
  const pieData = Object.entries(analytics.threat_distribution).map(([name, value]) => ({
    name,
    value
  }));

  const barData = Object.entries(analytics.severity_distribution)
    .map(([name, value]) => ({
      name,
      value
    }))
    .filter(d => d.value > 0); // Hide 0 count severities

  const trendData = analytics.detection_trend;

  // Check if timestamp exists in recent threats to determine if we can show temporal charts
  const hasTimestamps = recentThreats.some(t => t.record_data && (t.record_data.Timestamp || t.record_data.timestamp));

  return (
    <div className="space-y-8">
      {/* OVERVIEW CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* KPI 1 */}
        <div className="dark-panel p-6 flex items-center justify-between">
          <div>
            <span className="text-[10px] text-slate-500 font-mono tracking-wider block">TOTAL TRAFFIC RECORDS</span>
            <span className="text-2xl font-bold text-white mt-1 block">
              {analytics.total_records.toLocaleString()}
            </span>
            <div className="flex items-center gap-1.5 mt-2 text-[10px] font-mono">
              <span className="text-emerald-500 font-semibold">{benignPercent.toFixed(1)}% Benign</span>
              <span className="text-slate-600">|</span>
              <span className="text-rose-500 font-semibold">{maliciousPercent.toFixed(1)}% Threat</span>
            </div>
          </div>
          <div className="w-10 h-10 rounded bg-slate-800 flex items-center justify-center text-cyan-400">
            <Activity size={20} />
          </div>
        </div>

        {/* KPI 2 */}
        <div className="dark-panel p-6 flex items-center justify-between">
          <div>
            <span className="text-[10px] text-slate-500 font-mono tracking-wider block">THREATS DETECTED</span>
            <span className="text-2xl font-bold text-rose-500 mt-1 block">
              {analytics.threats_detected.toLocaleString()}
            </span>
            <div className="flex items-center gap-1.5 mt-2 text-[10px] text-slate-400 font-mono">
              <span>Avg Conf:</span>
              <span className="text-white font-medium">{(analytics.avg_confidence * 100).toFixed(1)}%</span>
            </div>
          </div>
          <div className="w-10 h-10 rounded bg-rose-950/40 border border-rose-900/50 flex items-center justify-center text-rose-400">
            <ShieldAlert size={20} />
          </div>
        </div>

        {/* KPI 3 */}
        <div className="dark-panel p-6 flex items-center justify-between">
          <div>
            <span className="text-[10px] text-slate-500 font-mono tracking-wider block">CRITICAL EVENTS</span>
            <span className="text-2xl font-bold text-red-600 mt-1 block">
              {analytics.critical_threats.toLocaleString()}
            </span>
            <div className="flex items-center gap-1.5 mt-2 text-[10px] text-slate-400 font-mono">
              <span>Action required:</span>
              <span className="text-red-400 font-semibold">Immediate quarantine</span>
            </div>
          </div>
          <div className="w-10 h-10 rounded bg-red-950/50 border border-red-900 flex items-center justify-center text-red-500">
            <AlertOctagon size={20} />
          </div>
        </div>

        {/* KPI 4 */}
        <div className="dark-panel p-6 flex items-center justify-between">
          <div>
            <span className="text-[10px] text-slate-500 font-mono tracking-wider block">DETECTION MODEL</span>
            <span className="text-sm font-semibold text-white mt-1.5 block truncate max-w-[170px]">
              {analytics.current_model || 'No Model Active'}
            </span>
            <div className="flex items-center gap-1.5 mt-2 text-[10px] text-slate-400 font-mono">
              <span>Last analyzed:</span>
              <span className="text-white text-[9px]">{analytics.last_analysis_time || 'N/A'}</span>
            </div>
          </div>
          <div className="w-10 h-10 rounded bg-slate-800 flex items-center justify-center text-emerald-400">
            <Cpu size={20} />
          </div>
        </div>
      </div>

      {/* CHARTS LAYER */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Distribution (Donut) */}
        <div className="dark-panel p-6 flex flex-col h-80">
          <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-4">Threat Distribution</h3>
          <div className="flex-1 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={colorsList[index % colorsList.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }}
                  labelStyle={{ color: '#fff' }}
                />
                <Legend layout="horizontal" align="center" verticalAlign="bottom" wrapperStyle={{ fontSize: '10px' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Severity (Bar) */}
        <div className="dark-panel p-6 flex flex-col h-80">
          <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-4">Threat Severity Profile</h3>
          <div className="flex-1 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }} />
                <Bar dataKey="value" fill="#38bdf8" radius={[4, 4, 0, 0]}>
                  {barData.map((entry, index) => {
                    let color = '#38bdf8'; // low
                    if (entry.name === 'Medium') color = '#fbbf24';
                    if (entry.name === 'High') color = '#f97316';
                    if (entry.name === 'Critical') color = '#ef4444';
                    return <Cell key={`cell-${index}`} fill={color} />;
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Detection Trend (Line) */}
        <div className="dark-panel p-6 flex flex-col h-80">
          <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2">Detection Trend</h3>
          
          {!hasTimestamps && (
            <p className="text-[10px] text-amber-500 font-mono mb-2">
              ⚠️ Original timestamps not verified in dataset. Mapped sequentially by index.
            </p>
          )}
          
          <div className="flex-1 min-h-0">
            {trendData && trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trendData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                  <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                  <XAxis dataKey="range" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }} />
                  <Line type="monotone" dataKey="threats" name="Malicious Events" stroke="#ef4444" strokeWidth={2} dot={{ r: 2 }} activeDot={{ r: 4 }} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-xs text-slate-500">
                Temporal trends unavailable for current analysis run.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* THREAT INTELLIGENCE SUMMARY & DUAL DETECTION (Section 9, 10, 11) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Dual Detection Chart (Section 10) */}
        <div className="dark-panel p-6 flex flex-col h-80">
          <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2">Supervised vs Anomaly Detection</h3>
          <p className="text-[10px] text-slate-500 font-mono mb-4">Correlation of XGBoost attack classifier and Isolation Forest anomaly detector.</p>
          <div className="flex-1 flex flex-col justify-center space-y-4">
            {/* Classifier Only */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span>CLASSIFIED MALICIOUS ONLY</span>
                <span className="font-semibold text-white">{analytics.dual_detection?.ClassifierOnly?.toLocaleString() || 0}</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div 
                  className="bg-indigo-500 h-full rounded-full" 
                  style={{ width: `${Math.min(100, (analytics.dual_detection?.ClassifierOnly || 0) / (analytics.total_records || 1) * 100)}%` }}
                />
              </div>
            </div>
            {/* Anomalous Only */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span>UNSUPERVISED ANOMALIES ONLY</span>
                <span className="font-semibold text-white">{analytics.dual_detection?.AnomalousOnly?.toLocaleString() || 0}</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div 
                  className="bg-cyan-500 h-full rounded-full" 
                  style={{ width: `${Math.min(100, (analytics.dual_detection?.AnomalousOnly || 0) / (analytics.total_records || 1) * 100)}%` }}
                />
              </div>
            </div>
            {/* Both */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span>FLAGGED BY BOTH LAYERS</span>
                <span className="font-semibold text-white">{analytics.dual_detection?.Both?.toLocaleString() || 0}</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div 
                  className="bg-rose-500 h-full rounded-full" 
                  style={{ width: `${Math.min(100, (analytics.dual_detection?.Both || 0) / (analytics.total_records || 1) * 100)}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Risk Distribution Chart (Section 11) */}
        <div className="dark-panel p-6 flex flex-col h-80">
          <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-2">Combined Risk Distribution</h3>
          <p className="text-[10px] text-slate-500 font-mono mb-4">Volume of traffic records grouped by calculated threat risk percentile.</p>
          <div className="flex-1 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={[
                { name: '0–25 Low', value: analytics.risk_distribution?.['0-25'] || 0, fill: '#10b981' },
                { name: '26–50 Med', value: analytics.risk_distribution?.['26-50'] || 0, fill: '#6366f1' },
                { name: '51–75 High', value: analytics.risk_distribution?.['51-75'] || 0, fill: '#fbbf24' },
                { name: '76–100 Crit', value: analytics.risk_distribution?.['76-100'] || 0, fill: '#ef4444' }
              ]} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={9} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={9} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }} />
                <Bar dataKey="value" fill="#6366f1" radius={[4, 4, 0, 0]}>
                  { [
                      { fill: '#10b981' },
                      { fill: '#6366f1' },
                      { fill: '#fbbf24' },
                      { fill: '#ef4444' }
                    ].map((entry, idx) => <Cell key={`cell-${idx}`} fill={entry.fill} />)
                  }
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* RECENT THREATS TABLE */}
      <div className="dark-panel p-6">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider">Recent Threat Incidents</h3>
          <span className="text-[10px] text-slate-500 font-mono">Showing last 12 detections</span>
        </div>

        {threatsLoading ? (
          <div className="flex justify-center py-12">
            <div className="w-6 h-6 rounded-full border-2 border-slate-800 border-t-cyan-500 animate-spin" />
          </div>
        ) : recentThreats.length === 0 ? (
          <div className="text-center py-8 text-xs text-slate-500">
            No threat records found in log vault.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono text-[10px]">
                  <th className="py-2.5 px-3">RECORD ID</th>
                  <th className="py-2.5 px-3">ATTACK TYPE</th>
                  <th className="py-2.5 px-3">SEVERITY</th>
                  <th className="py-2.5 px-3">CONFIDENCE</th>
                  {recentThreats[0]?.record_data?.Source_IP && <th className="py-2.5 px-3">SOURCE IP</th>}
                  {recentThreats[0]?.record_data?.Destination_IP && <th className="py-2.5 px-3">DESTINATION IP</th>}
                  {recentThreats[0]?.record_data?.Protocol && <th className="py-2.5 px-3">PROTOCOL</th>}
                  <th className="py-2.5 px-3">DETECTION STATUS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {recentThreats.map((threat) => {
                  const isBenign = threat.attack_type.toLowerCase() === 'benign' || threat.attack_type.toLowerCase() === 'normal';
                  
                  let sevColor = 'bg-slate-800 text-slate-300';
                  if (threat.severity === 'Critical') sevColor = 'bg-red-500/10 text-red-400 border border-red-900/30';
                  if (threat.severity === 'High') sevColor = 'bg-orange-500/10 text-orange-400 border border-orange-900/30';
                  if (threat.severity === 'Medium') sevColor = 'bg-amber-500/10 text-amber-400 border border-amber-900/30';
                  if (threat.severity === 'Low') sevColor = 'bg-emerald-500/10 text-emerald-400 border border-emerald-900/30';

                  return (
                    <tr key={threat.id} className="hover:bg-slate-800/20 text-slate-300">
                      <td className="py-3 px-3 font-mono">#{threat.record_index}</td>
                      <td className="py-3 px-3 font-semibold text-white">{threat.attack_type}</td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono leading-none ${sevColor}`}>
                          {threat.severity}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono">{(threat.confidence * 100).toFixed(1)}%</td>
                      {threat.record_data?.Source_IP && <td className="py-3 px-3 font-mono">{threat.record_data.Source_IP}</td>}
                      {threat.record_data?.Destination_IP && <td className="py-3 px-3 font-mono">{threat.record_data.Destination_IP}</td>}
                      {threat.record_data?.Protocol && (
                        <td className="py-3 px-3 font-mono">
                          {threat.record_data.Protocol === 6 ? 'TCP' : threat.record_data.Protocol === 17 ? 'UDP' : threat.record_data.Protocol}
                        </td>
                      )}
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full ${isBenign ? 'bg-emerald-500' : 'bg-red-500 animate-pulse'}`} />
                          <span className="font-mono text-[10px] uppercase">
                            {isBenign ? 'Normal' : 'Threat Block'}
                          </span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
