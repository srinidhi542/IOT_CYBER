import os
import time
import unittest
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


class TestMultiAgentSOC(unittest.TestCase):

    def test_network_interfaces_enumeration(self):
        """Verify system and TShark network interface discovery."""
        ifaces = get_network_interfaces()
        self.assertIsInstance(ifaces, list)
        self.assertGreater(len(ifaces), 0)
        self.assertIn("name", ifaces[0])
        self.assertIn("id", ifaces[0])

    def test_coordinator_agent_pipeline_execution(self):
        """Verify end-to-end 6-agent sequential pipeline execution."""
        incident = coordinator_agent.run_pipeline(SAMPLE_FLOW_RECORD)

        # 1. Verification of Coordinator & Detection
        self.assertTrue(incident.incident_id.startswith("INC-"))
        self.assertIn(incident.detection.attack_type, ['Benign', 'Brute Force', 'DDoS', 'DoS', 'Mirai', 'Recon', 'Spoofing', 'Web Attack'])
        self.assertTrue(0.0 <= incident.detection.confidence <= 1.0)
        self.assertGreater(len(incident.detection.top_contributing_features), 0)

        # 2. Verification of Threat Intelligence (RAG)
        self.assertIsNotNone(incident.threat_intel)
        self.assertGreater(incident.threat_intel.retrieval_confidence, 0.0)
        self.assertGreater(len(incident.threat_intel.sources), 0)
        for src in incident.threat_intel.sources:
            self.assertTrue(src.startswith("http"))

        # 3. Verification of Risk Assessment
        self.assertIsNotNone(incident.risk_assessment)
        self.assertTrue(0.0 <= incident.risk_assessment.risk_score <= 100.0)
        self.assertIn(incident.risk_assessment.severity, ["Critical", "High", "Medium", "Low"])
        self.assertGreater(len(incident.risk_assessment.reasoning), 0)

        # 4. Verification of Response Agent & Approval Safeguard
        self.assertIsNotNone(incident.response)
        self.assertGreater(len(incident.response.containment), 0)
        self.assertGreater(len(incident.response.firewall_commands), 0)
        self.assertTrue(incident.response.approval_required)
        self.assertEqual(incident.response.approval_status, "PENDING_ANALYST_APPROVAL")

        # 5. Verification of Incident Report & Timeline
        self.assertIsNotNone(incident.report)
        self.assertGreater(len(incident.report.markdown_content), 100)
        self.assertGreaterEqual(len(incident.timeline), 6)

    def test_benign_traffic_safeguard(self):
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
        self.assertEqual(len(intel.mitre_attack), 0)
        self.assertEqual(len(intel.cve_list), 0)
        self.assertIn("baseline", intel.iot_threat_context.lower())

        risk = risk_assessment_agent.assess_risk(benign_detection, intel)
        self.assertEqual(risk.risk_score, 0.0)
        self.assertEqual(risk.severity, "Low")

        resp = response_agent.generate_response_plan(benign_detection, risk)
        self.assertEqual(len(resp.firewall_commands), 0)
        self.assertFalse(resp.approval_required)

    def test_analyst_approval_workflow(self):
        """Verify analyst sign-off and approval status persistence."""
        incident = coordinator_agent.run_pipeline(SAMPLE_FLOW_RECORD)
        self.assertEqual(incident.response.approval_status, "PENDING_ANALYST_APPROVAL")

        # Approve
        updated = coordinator_agent.record_analyst_approval(
            incident.incident_id,
            approved=True,
            analyst_name="Security Analyst John",
            notes="Validated external attack IP. Approved IPTables rule."
        )
        self.assertEqual(updated.response.approval_status, "APPROVED")
        self.assertEqual(updated.response.reviewed_by, "Security Analyst John")
        self.assertEqual(updated.status, "CONTAINED")

    def test_api_agent_endpoints(self):
        """Verify FastAPI multi-agent endpoints."""
        # Run analysis
        r_analyze = client.post("/api/agents/analyze", json={"record": SAMPLE_FLOW_RECORD})
        self.assertEqual(r_analyze.status_code, 200)
        inc_data = r_analyze.json()
        inc_id = inc_data["incident_id"]

        # Retrieve incident
        r_get = client.get(f"/api/agents/incident/{inc_id}")
        self.assertEqual(r_get.status_code, 200)
        self.assertEqual(r_get.json()["incident_id"], inc_id)

        # List incidents
        r_list = client.get("/api/agents/incidents")
        self.assertEqual(r_list.status_code, 200)
        self.assertGreater(len(r_list.json()), 0)

        # Analyst approval
        r_approve = client.post(
            f"/api/agents/incident/{inc_id}/approval",
            json={"approved": True, "analyst_name": "Lead Analyst", "notes": "Approved in staging"}
        )
        self.assertEqual(r_approve.status_code, 200)
        self.assertEqual(r_approve.json()["response"]["approval_status"], "APPROVED")

        # Markdown report download
        r_report = client.get(f"/api/agents/incident/{inc_id}/report")
        self.assertEqual(r_report.status_code, 200)
        self.assertIn(inc_id, r_report.text)


if __name__ == "__main__":
    unittest.main()
