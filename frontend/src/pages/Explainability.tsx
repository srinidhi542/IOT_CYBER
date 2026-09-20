import React from 'react';
import { PredictionExplanation, ShapContribution } from '../types';
import {
  Sparkles,
  TrendingUp,
  TrendingDown,
  ShieldAlert,
  ArrowRightCircle,
  Play,
  ArrowLeft,
  Shield
} from 'lucide-react';

interface AttackKnowledge {
  whatIsIt: string;
  securityImpact: string;
  analystInterpretation: string;
  recommendedNextStep: string;
}

const ATTACK_KNOWLEDGE_BASE: Record<string, AttackKnowledge> = {
  'Benign': {
    whatIsIt: 'Normal, uncompromised IoT and network communication traffic operating within standard baseline protocol specifications.',
    securityImpact: 'No direct threat. However, baseline drift or stealthy low-and-slow exfiltration can occasionally blend with normal traffic patterns.',
    analystInterpretation: 'The ML model evaluated the packet headers and statistical flow metrics as consistent with authorized benign communications. No active intrusion indicators were triggered.',
    recommendedNextStep: 'Maintain regular baseline logging. No immediate containment required unless unexpected device behavioral anomalies occur elsewhere.'
  },
  'Brute Force': {
    whatIsIt: 'An automated authentication attack where an adversary attempts systematic credential guessing across network login services (SSH, Telnet, HTTP basic auth).',
    securityImpact: 'Potential unauthorized device takeover, credential compromise, and persistent initial access across the IoT network perimeter.',
    analystInterpretation: 'The ML model identified traffic metrics characteristic of rapid, repeated connection attempts and high request variance typical of automated dictionary attacks.',
    recommendedNextStep: 'Inspect targeted authentication endpoints, review failed authentication logs, verify rate-limiting rules, and consider temporary IP blocking on repeated offenders.'
  },
  'DDoS': {
    whatIsIt: 'A Distributed Denial of Service attack where multiple coordinated endpoints overwhelm target bandwidth, buffers, or processing capacity (e.g., HTTP/UDP/SYN floods).',
    securityImpact: 'Severe network degradation, service outage, device memory exhaustion, and disruption of critical IoT control telemetry.',
    analystInterpretation: 'The model flagged high packet rate concentrations and packet length distribution anomalies characteristic of distributed flood attacks.',
    recommendedNextStep: 'Verify current upstream bandwidth utilization, activate anti-DDoS rate limiting or scrubbing filters, and inspect traffic origins to isolate cluster sources.'
  },
  'DoS': {
    whatIsIt: 'A localized Denial of Service attack designed to crash, exhaust, or degrade a single IoT node or server daemon through resource depletion or targeted malformed packets.',
    securityImpact: 'Loss of availability for targeted IoT gateways or backend services, causing downstream sensor data gaps and communication failover triggers.',
    analystInterpretation: 'The model detected elevated flow rates, abnormal inter-arrival times, or protocol flag distributions consistent with targeted exhaustion vectors.',
    recommendedNextStep: 'Inspect CPU/memory utilization on the target device, examine active socket connection tables, and apply ingress rate throttling at the perimeter switch.'
  },
  'Mirai': {
    whatIsIt: 'A specialized IoT botnet malware family that scans the internet for vulnerable embedded devices, infects them via default credentials, and enlists them into a bot army.',
    securityImpact: 'Total device compromise, botnet recruitment, lateral propagation across the LAN segment, and weaponization for external coordinated attacks.',
    analystInterpretation: 'The model identified telemetry patterns matching known Mirai flood vectors (e.g., GRE-IP floods, raw UDP floods) and synchronized high-frequency socket bursts.',
    recommendedNextStep: 'Immediately isolate the suspected IoT device to a quarantine VLAN, check open management ports (Telnet/SSH), and review firmware integrity.'
  },
  'Recon': {
    whatIsIt: 'Reconnaissance and scanning activities such as host discovery, port scanning, OS fingerprinting, vulnerability probing, or DNS spoofing reconnaissance.',
    securityImpact: 'Provides attackers with network layout, live IP addresses, open ports, and vulnerable software versions to plan subsequent exploitation.',
    analystInterpretation: 'The model detected sequential probe patterns, low-payload scan packets, or sweeping destination port distributions typical of pre-attack network mapping.',
    recommendedNextStep: 'Correlate scan origins with threat intelligence feeds, verify firewall ingress rules, and confirm that sensitive management ports are not exposed.'
  },
  'Spoofing': {
    whatIsIt: 'A network attack in which an adversary attempts to impersonate another device, host, or network service by manipulating identifying information (e.g., ARP poisoning or DNS spoofing).',
    securityImpact: 'Allows an attacker to impersonate trusted endpoints, potentially enabling traffic interception, man-in-the-middle (MitM) eavesdropping, or unauthorized data access.',
    analystInterpretation: 'The ML model identified the traffic pattern as consistent with the Spoofing class. This is a classification result, not proof that spoofing has occurred. The contributing features explain the decision and should be correlated with additional network evidence.',
    recommendedNextStep: 'Inspect related network traffic and correlate the event with ARP/DNS activity, MAC-to-IP binding tables, and other telemetry from the same device.'
  },
  'Web Attack': {
    whatIsIt: 'Web-tier application exploits targeting web-enabled IoT configuration consoles (e.g., SQL Injection, Cross-Site Scripting [XSS], or Command Injection).',
    securityImpact: 'Arbitrary remote command execution, backend database tampering, firmware compromise, and administrative session hijacking on IoT management panels.',
    analystInterpretation: 'The model detected payload size fluctuations, HTTP request anomalies, or flag signatures consistent with structured web-application exploit attempts.',
    recommendedNextStep: 'Inspect web server application and access logs for exploit payloads (SQL keywords, script tags, shell metacharacters) and ensure Web Application Firewall (WAF) rules are active.'
  }
};

function generateWhyDetectedText(label: string, topFeatures: ShapContribution[]): string {
  if (!topFeatures || topFeatures.length === 0) {
    return `The model classified this telemetry as ${label} based on its evaluation of the 39 network traffic features.`;
  }

  const positiveFeatures = topFeatures.filter(f => f.direction === 'increases').map(f => f.feature);
  const negativeFeatures = topFeatures.filter(f => f.direction === 'decreases').map(f => f.feature);

  if (positiveFeatures.length > 0 && negativeFeatures.length > 0) {
    const posStr = positiveFeatures.join(', ');
    const negStr = negativeFeatures.join(', ');
    return `The model classified this telemetry as ${label} because features such as ${posStr} contributed strongly toward the prediction. The SHAP values indicate that these observed traffic characteristics pushed the model toward the ${label} class, while ${negStr} contributed in the opposite direction.`;
  } else if (positiveFeatures.length > 0) {
    const posStr = positiveFeatures.join(', ');
    return `The model classified this telemetry as ${label} because features such as ${posStr} contributed strongly toward the prediction. The SHAP attribution indicates that these observed flow metrics elevated the likelihood of this classification.`;
  } else {
    const allStr = topFeatures.map(f => f.feature).join(', ');
    return `The model classified this telemetry as ${label} primarily influenced by the combination of ${allStr} features in the observed network record.`;
  }
}

interface AIExplainabilityProps {
  latestPrediction: PredictionExplanation | null;
  onNavigateToPrediction: () => void;
}

export const AIExplainability: React.FC<AIExplainabilityProps> = ({
  latestPrediction,
  onNavigateToPrediction
}) => {
  if (!latestPrediction) {
    return (
      <div className="space-y-6">
        <div className="dark-panel p-16 flex flex-col items-center justify-center text-center space-y-4 max-w-2xl mx-auto my-12">
          <div className="w-16 h-16 rounded-2xl bg-cyan-950/40 border border-cyan-800/40 flex items-center justify-center text-cyan-400 shadow-xl shadow-cyan-950/20">
            <Sparkles size={32} />
          </div>
          <div>
            <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider mb-1">
              No Prediction Available
            </h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              No active prediction found in the current session. Run a network prediction on the Dashboard to generate a complete SHAP feature attribution and security analysis.
            </p>
          </div>
          <button
            onClick={onNavigateToPrediction}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold uppercase transition-all shadow-lg shadow-cyan-950/40"
          >
            <Play size={14} />
            <span>Go to Prediction</span>
          </button>
        </div>
      </div>
    );
  }

  const currentKnowledge = ATTACK_KNOWLEDGE_BASE[latestPrediction.label] || {
    whatIsIt: `Detected network pattern classified under the ${latestPrediction.label} family.`,
    securityImpact: 'Potential anomaly or malicious behavior across the IoT communications channel.',
    analystInterpretation: `The ML model identified telemetry consistent with the ${latestPrediction.label} classification category based on evaluated network attributes.`,
    recommendedNextStep: 'Inspect related network flows, verify host identities, and correlate with endpoint logs.'
  };

  const maxShap = Math.max(...latestPrediction.top_contributing_features.map(f => Math.abs(f.shap_value)), 0.001);

  return (
    <div className="space-y-6">
      {/* Top Banner with Navigation Back */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold font-mono text-white tracking-wider uppercase flex items-center gap-2">
            <Sparkles size={16} className="text-cyan-400" />
            AI Explainability & Attack Analysis
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            SHAP Tree Attribution and deep contextual breakdown for the latest evaluated telemetry sample.
          </p>
        </div>
        <button
          onClick={onNavigateToPrediction}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-900 border border-slate-800 hover:border-cyan-800 text-slate-300 hover:text-white text-xs font-mono transition-colors"
        >
          <ArrowLeft size={13} />
          <span>New Prediction</span>
        </button>
      </div>

      {/* Prediction Summary Header */}
      <div className="dark-panel p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div>
          <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Detected Attack Family</span>
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-emerald-950/80 border border-emerald-700/50 text-emerald-400 font-bold font-mono text-sm tracking-wide">
            <Shield size={14} />
            {latestPrediction.label}
          </div>
        </div>

        <div>
          <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Classification Confidence</span>
          <p className="text-xl font-bold font-mono text-cyan-400">
            {(latestPrediction.confidence * 100).toFixed(2)}%
          </p>
        </div>

        <div>
          <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Explainer Engine</span>
          <p className="text-sm font-semibold font-mono text-slate-300 mt-1">
            SHAP TreeExplainer
          </p>
        </div>

        <div>
          <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Evaluated Features</span>
          <p className="text-sm font-semibold font-mono text-slate-300 mt-1">
            39 Network Telemetry Features
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* SHAP Attribution Card */}
        <div className="dark-panel p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <Sparkles size={16} className="text-cyan-400" />
              <div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">AI EXPLANATION — SHAP ATTRIBUTION</h4>
                <p className="text-[11px] text-slate-400 font-sans mt-0.5">Why did the model make this prediction?</p>
              </div>
            </div>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/40 uppercase">
              Top 5 Features
            </span>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">
            Top 5 actual network feature contributions driving this telemetry sample toward <b className="text-emerald-400">{latestPrediction.label}</b>:
          </p>

          <div className="space-y-2.5">
            {latestPrediction.top_contributing_features.map((item, idx) => {
              const isPositive = item.direction === 'increases';
              const barWidth = Math.min(100, Math.max(10, (Math.abs(item.shap_value) / maxShap) * 100));

              return (
                <div key={idx} className="p-3 rounded bg-slate-900/90 border border-slate-800/80 space-y-2">
                  <div className="flex justify-between items-center text-xs">
                    <div className="flex items-center gap-2.5">
                      <span className="text-white font-semibold">{item.feature}</span>
                      <span className="text-[10px] text-slate-500 font-mono">val: {item.value}</span>
                    </div>
                    <div className="flex items-center gap-1.5 font-mono">
                      {isPositive ? (
                        <span className="flex items-center gap-1 text-emerald-400 font-semibold text-xs">
                          <TrendingUp size={13} className="text-emerald-400" />
                          +{item.shap_value.toFixed(4)} &nbsp;↑ Increases
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-rose-400 font-semibold text-xs">
                          <TrendingDown size={13} className="text-rose-400" />
                          {item.shap_value.toFixed(4)} &nbsp;↓ Decreases
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Proportional Contribution Bar */}
                  <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden flex">
                    <div
                      className={`h-full rounded-full transition-all duration-300 ${
                        isPositive 
                          ? 'bg-gradient-to-r from-emerald-600 to-emerald-400' 
                          : 'bg-gradient-to-r from-rose-600 to-rose-400'
                      }`}
                      style={{ width: `${barWidth}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Attack Analysis Section */}
        <div className="dark-panel p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <ShieldAlert size={16} className="text-amber-400 shrink-0" />
            <div>
              <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">ATTACK ANALYSIS</h4>
              <p className="text-[11px] text-slate-400 font-sans">Contextual security interpretation for SOC operations</p>
            </div>
          </div>

          <div className="space-y-3.5 text-xs">
            {/* 1. Detected Attack */}
            <div>
              <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1">Detected Attack</span>
              <div className="inline-block px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-emerald-400 font-mono font-bold">
                {latestPrediction.label}
              </div>
            </div>

            {/* 2. What is this attack? */}
            <div>
              <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1">What is this attack?</span>
              <p className="text-slate-300 leading-relaxed text-xs bg-slate-900/50 p-2.5 rounded border border-slate-900">
                {currentKnowledge.whatIsIt}
              </p>
            </div>

            {/* 3. Why was it detected? */}
            <div>
              <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1">Why was it detected?</span>
              <p className="text-slate-300 leading-relaxed text-xs bg-slate-900/50 p-2.5 rounded border border-slate-900">
                {generateWhyDetectedText(latestPrediction.label, latestPrediction.top_contributing_features)}
              </p>
            </div>

            {/* 4. Security Impact */}
            <div>
              <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1">Security Impact</span>
              <p className="text-amber-300/90 leading-relaxed text-xs bg-amber-950/20 p-2.5 rounded border border-amber-900/30">
                {currentKnowledge.securityImpact}
              </p>
            </div>

            {/* 5. Analyst Interpretation */}
            <div>
              <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1">Analyst Interpretation</span>
              <p className="text-slate-300 leading-relaxed text-xs bg-slate-900/50 p-2.5 rounded border border-slate-900">
                {currentKnowledge.analystInterpretation}
              </p>
            </div>

            {/* 6. Recommended Next Step */}
            <div>
              <span className="text-[10px] font-mono uppercase text-cyan-400 block mb-1">Recommended Next Step</span>
              <div className="flex items-start gap-2 bg-cyan-950/30 border border-cyan-800/40 p-2.5 rounded text-xs text-cyan-200/90 leading-relaxed">
                <ArrowRightCircle size={15} className="text-cyan-400 shrink-0 mt-0.5" />
                <span>{currentKnowledge.recommendedNextStep}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};


