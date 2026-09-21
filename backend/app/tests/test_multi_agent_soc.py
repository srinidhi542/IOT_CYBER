import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.capture.tshark_capture import capture_manager, get_network_interfaces
from app.capture.cicflowmeter import CICIOT2023_FEATURES, extract_flows_from_pcap
from app.agents.coordinator_agent import coordinator_agent

client = TestClient(app)

SAMPLE_FLOW_RECORD = {
    'Header_Length': 13.2,
    'Protocol Type': 6,
    'Time_To_Live': 64.0,
    'Rate': 4500.0,
    'fin_flag_number': 0,
    'syn_flag_number': 1,
    'rst_flag_number': 0,
    'psh_flag_number': 0,
    'ack_flag_number': 0,
    'ece_flag_number': 0,
    'cwr_flag_number': 0,
    'ack_count': 0,
    'syn_count': 500,
    'fin_count': 0,
    'rst_count': 0,
    'HTTP': 0,
    'HTTPS': 0,
    'DNS': 0,
    'Telnet': 1,
    'SMTP': 0,
    'SSH': 0,
    'IRC': 0,
    'TCP': 1,
    'UDP': 0,
    'DHCP': 0,
    'ARP': 0,
    'ICMP': 0,
    'IGMP': 0,
    'IPv': 1,
    'LLC': 1,
    'Tot sum': 25000,
    'Min': 40,
    'Max': 1500,
    'AVG': 60,
    'Std': 120,
    'Tot size': 25000,
    'IAT': 0.0002,
    'Number': 500,
    'Variance': 14400.0,
    'Source_IP': '192.168.1.110',
    'Destination_IP': '192.168.1.20',
    'Source_Port': 57332,
    'Destination_Port': 23,
    'Protocol_Name': 'TCP'
}

BENIGN_FLOW_RECORD = {
    "Header_Length": 22.83,
    "Protocol Type": 16.82,
    "Time_To_Live": 75.78,
    "Rate": 332.57,
    "fin_flag_number": 0,
    "syn_flag_number": 0,
    "rst_flag_number": 0,
    "psh_flag_number": 0,
    "ack_flag_number": 1,
    "ece_flag_number": 0,
    "cwr_flag_number": 0,
    "ack_count": 8,
    "syn_count": 10,
    "fin_count": 3,
    "rst_count": 16,
    "HTTP": 0,
    "HTTPS": 1,
    "DNS": 0,
    "Telnet": 0,
    "SMTP": 0,
    "SSH": 0,
    "IRC": 0,
    "TCP": 1,
    "UDP": 0,
    "DHCP": 0,
    "ARP": 0,
    "ICMP": 0,
    "IGMP": 0,
    "IPv": 1,
    "LLC": 1,
    "Tot sum": 7332.61,
    "Min": 232.57,
    "Max": 1583.9,
    "AVG": 767.82,
    "Std": 290.22,
    "Tot size": 508.13,
    "IAT": 0.54,
    "Number": 12,
    "Variance": 850228.74,
    "Source_IP": "192.168.1.15",
    "Destination_IP": "104.24.12.5",
    "Source_Port": 49364,
    "Destination_Port": 443,
    "Protocol_Name": "TCP"
}


def test_network_interfaces_enumeration():
    """Verify system and TShark network interface discovery."""
    ifaces = get_network_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    assert "name" in ifaces[0]
    assert "id" in ifaces[0]


def test_packet_capture_and_cicflowmeter():
    """Verify live capture generation and exact 39-feature extraction."""
    session = capture_manager.start_capture("Default", "uploads", duration_limit=1)
    assert session.is_capturing is True

    import time
    time.sleep(1.2)

    stop_res = capture_manager.stop_capture()
    assert stop_res["is_capturing"] is False
    assert stop_res["packet_count"] > 0
    assert os.path.exists(stop_res["output_pcap"])

    df = extract_flows_from_pcap(stop_res["output_pcap"])
    assert not df.empty

    # Check all 39 model features exist in extracted DataFrame
    for feat in CICIOT2023_FEATURES:
        assert feat in df.columns, f"Missing expected feature: {feat}"


def test_coordinator_agent_pipeline_execution():
    """Verify end-to-end 6-agent sequential pipeline execution."""
    incident = coordinator_agent.run_pipeline(SAMPLE_FLOW_RECORD)

    # 1. Verification of Coordinator & Detection
    assert incident.incident_id.startswith("INC-")
    assert incident.detection.attack_type in ['Benign', 'Brute Force', 'DDoS', 'DoS', 'Mirai', 'Recon', 'Spoofing', 'Web Attack']
    assert 0.0 <= incident.detection.confidence <= 1.0
    assert len(incident.detection.top_contributing_features) > 0

    # 2. Verification of Threat Intelligence (RAG)
    assert incident.threat_intel is not None
    assert incident.threat_intel.retrieval_confidence > 0.0
    assert len(incident.threat_intel.sources) > 0
    for src in incident.threat_intel.sources:
        assert src.startswith("http")

    # 3. Verification of Risk Assessment
    assert incident.risk_assessment is not None
    assert 0.0 <= incident.risk_assessment.risk_score <= 100.0
    assert incident.risk_assessment.severity in ["Critical", "High", "Medium", "Low"]
    assert len(incident.risk_assessment.reasoning) > 0

    # 4. Verification of Response Agent & Approval Safeguard
    assert incident.response is not None
    assert len(incident.response.containment) > 0
    assert len(incident.response.firewall_commands) > 0
    assert incident.response.approval_required is True
    assert incident.response.approval_status == "PENDING_ANALYST_APPROVAL"

    # 5. Verification of Incident Report & Timeline
    assert incident.report is not None
    assert len(incident.report.markdown_content) > 100
    assert len(incident.timeline) >= 6


def test_benign_traffic_safeguard():
    """Verify that benign traffic does NOT have fabricated CVEs or false firewalls."""
    from app.agents.agent_schemas import DetectionOutput, NetworkContext
    from app.agents.threat_intel_agent import threat_intel_agent
    from app.agents.risk_assessment_agent import risk_assessment_agent
    from app.agents.response_agent import response_agent

    benign_detection = DetectionOutput(
        attack_type="Benign",
        confidence=0.99,
        probabilities={"Benign": 0.99},
        network_context=NetworkContext(
            source_ip="192.168.1.15",
            destination_ip="104.24.12.5",
            source_port=49364,
            destination_port=443,
            protocol="TCP"
        )
    )

    intel = threat_intel_agent.retrieve_intelligence(benign_detection)
    assert len(intel.mitre_attack) == 0
    assert len(intel.cve_list) == 0
    assert "baseline" in intel.iot_threat_context.lower()

    risk = risk_assessment_agent.assess_risk(benign_detection, intel)
    assert risk.risk_score == 0.0
    assert risk.severity == "Low"

    resp = response_agent.generate_response_plan(benign_detection, risk)
    assert len(resp.firewall_commands) == 0
    assert resp.approval_required is False


def test_analyst_approval_workflow():
    """Verify analyst sign-off and approval status persistence."""
    incident = coordinator_agent.run_pipeline(SAMPLE_FLOW_RECORD)
    assert incident.response.approval_status == "PENDING_ANALYST_APPROVAL"

    # Approve
    updated = coordinator_agent.record_analyst_approval(
        incident.incident_id,
        approved=True,
        analyst_name="Security Analyst John",
        notes="Validated external attack IP. Approved IPTables rule."
    )
    assert updated.response.approval_status == "APPROVED"
    assert updated.response.reviewed_by == "Security Analyst John"
    assert updated.status == "CONTAINED"


def test_api_capture_endpoints():
    """Verify FastAPI capture endpoints including overall explainability & aggregation."""
    # List interfaces
    r_ifaces = client.get("/api/capture/interfaces")
    assert r_ifaces.status_code == 200
    assert len(r_ifaces.json()) > 0

    # Status
    r_status = client.get("/api/capture/status")
    assert r_status.status_code == 200

    # Start capture
    r_start = client.post("/api/capture/start", json={"interface": "Default", "duration_limit": 1})
    assert r_start.status_code == 200

    import time
    time.sleep(1.2)

    # Stop capture
    r_stop = client.post("/api/capture/stop")
    assert r_stop.status_code == 200
    pcap_path = r_stop.json()["output_pcap"]
    assert os.path.exists(pcap_path)

    # Process PCAP through overall explainability and multi-agent pipeline
    r_proc = client.post("/api/capture/process", json={"pcap_path": pcap_path})
    assert r_proc.status_code == 200
    data = r_proc.json()
    assert data["flows_extracted"] > 0
    assert "overall_prediction" in data
    assert data["overall_prediction"]["label"] in ['Benign', 'Brute Force', 'DDoS', 'DoS', 'Mirai', 'Recon', 'Spoofing', 'Web Attack']
    assert 0.0 <= data["overall_prediction"]["confidence"] <= 1.0
    assert "overall_explainability" in data
    assert len(data["overall_explainability"]["top_contributing_features"]) > 0
    assert "overall_incident" in data
    assert data["overall_incident"]["incident_id"].startswith("INC-")
    assert len(data["incidents"]) > 0


def test_api_agent_endpoints():
    """Verify FastAPI multi-agent endpoints."""
    # Run analysis
    r_analyze = client.post("/api/agents/analyze", json={"record": SAMPLE_FLOW_RECORD})
    assert r_analyze.status_code == 200
    inc_data = r_analyze.json()
    inc_id = inc_data["incident_id"]

    # Retrieve incident
    r_get = client.get(f"/api/agents/incident/{inc_id}")
    assert r_get.status_code == 200
    assert r_get.json()["incident_id"] == inc_id

    # List incidents
    r_list = client.get("/api/agents/incidents")
    assert r_list.status_code == 200
    assert len(r_list.json()) > 0

    # Analyst approval
    r_approve = client.post(
        f"/api/agents/incident/{inc_id}/approval",
        json={"approved": True, "analyst_name": "Lead Analyst", "notes": "Approved in staging"}
    )
    assert r_approve.status_code == 200
    assert r_approve.json()["response"]["approval_status"] == "APPROVED"

    # Markdown report download
    r_report = client.get(f"/api/agents/incident/{inc_id}/report")
    assert r_report.status_code == 200
    assert inc_id in r_report.text
