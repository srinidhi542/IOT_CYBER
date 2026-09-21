from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime


class NetworkContext(BaseModel):
    timestamp: Optional[str] = None
    source_ip: Optional[str] = "Unknown"
    destination_ip: Optional[str] = "Unknown"
    source_port: Optional[int] = 0
    destination_port: Optional[int] = 0
    protocol: Optional[str] = "TCP"


class ShapEvidence(BaseModel):
    feature: str
    value: float
    shap_value: float
    direction: str  # "increases" or "decreases"


class DetectionOutput(BaseModel):
    attack_type: str
    confidence: float
    probabilities: Dict[str, float] = Field(default_factory=dict)
    network_context: NetworkContext
    top_contributing_features: List[ShapEvidence] = Field(default_factory=list)
    shap_values: Dict[str, float] = Field(default_factory=dict)
    raw_record: Dict[str, Any] = Field(default_factory=dict)


class MitreAttackItem(BaseModel):
    id: str  # e.g. "T1498"
    name: str
    tactic: str
    description: str
    url: str


class CveItem(BaseModel):
    cve_id: str  # e.g. "CVE-2023-1389"
    affected_systems: str
    cvss_score: float
    severity: str
    description: str
    url: str


class CisaAdvisoryItem(BaseModel):
    id: str  # e.g. "AA22-110A"
    title: str
    release_date: str
    summary: str
    url: str


class ThreatIntelOutput(BaseModel):
    mitre_attack: List[MitreAttackItem] = Field(default_factory=list)
    cve_list: List[CveItem] = Field(default_factory=list)
    cisa_advisories: List[CisaAdvisoryItem] = Field(default_factory=list)
    iot_threat_context: str
    retrieval_confidence: float
    sources: List[str] = Field(default_factory=list)


class RiskAssessmentOutput(BaseModel):
    risk_score: float  # 0.0 to 100.0
    severity: str      # "Critical", "High", "Medium", "Low"
    priority: str      # "P1 - Critical Urgent", "P2 - High", "P3 - Medium", "P4 - Low"
    impact: str
    likelihood: str
    reasoning: List[str] = Field(default_factory=list)


class FirewallCommand(BaseModel):
    firewall_type: str  # "iptables", "windows_netsh", "cisco_acl"
    command: str
    description: str


class ResponseOutput(BaseModel):
    containment: List[str] = Field(default_factory=list)
    recovery: List[str] = Field(default_factory=list)
    prevention: List[str] = Field(default_factory=list)
    firewall_commands: List[FirewallCommand] = Field(default_factory=list)
    approval_required: bool = True
    approval_status: str = "PENDING_ANALYST_APPROVAL"  # "PENDING_ANALYST_APPROVAL", "APPROVED", "REJECTED"
    reviewed_by: Optional[str] = None
    review_timestamp: Optional[str] = None
    review_notes: Optional[str] = None


class TimelineEvent(BaseModel):
    timestamp: str
    agent: str
    action: str
    details: str
    status: str = "COMPLETED"


class IncidentReportOutput(BaseModel):
    incident_id: str
    generated_at: str
    title: str
    executive_summary: str
    attack_type: str
    severity: str
    priority: str
    risk_score: float
    timeline: List[TimelineEvent] = Field(default_factory=list)
    markdown_content: str


class IncidentState(BaseModel):
    incident_id: str
    created_at: str
    status: str  # "TRIAGED", "CONTAINED", "PENDING_APPROVAL", "CLOSED"
    detection: DetectionOutput
    threat_intel: Optional[ThreatIntelOutput] = None
    risk_assessment: Optional[RiskAssessmentOutput] = None
    response: Optional[ResponseOutput] = None
    report: Optional[IncidentReportOutput] = None
    timeline: List[TimelineEvent] = Field(default_factory=list)
