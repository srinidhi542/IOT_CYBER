import logging
from typing import List, Dict, Any
from app.agents.agent_schemas import (
    DetectionOutput,
    RiskAssessmentOutput,
    ResponseOutput,
    FirewallCommand
)

logger = logging.getLogger(__name__)


class ResponseAgent:
    """
    Response Agent:
    Formulates structured containment, recovery, and prevention playbooks.
    Generates copyable firewall and ACL commands tailored to incident network context.
    STRICT SECURITY SAFEGUARD:
    - Never executes commands automatically on the host or network.
    - Marks all firewall rules and mitigation playbooks as requiring analyst approval.
    """

    def generate_response_plan(
        self,
        detection: DetectionOutput,
        risk: RiskAssessmentOutput
    ) -> ResponseOutput:
        attack = detection.attack_type.strip().lower()
        is_benign = attack in ["benign", "normal"]

        src_ip = detection.network_context.source_ip or "0.0.0.0"
        dst_ip = detection.network_context.destination_ip or "0.0.0.0"
        dst_port = detection.network_context.destination_port or 0
        proto = (detection.network_context.protocol or "TCP").lower()

        if is_benign:
            return ResponseOutput(
                containment=[
                    "No active containment required for baseline network traffic.",
                    "Keep endpoint under continuous passive anomaly monitoring."
                ],
                recovery=[
                    "Maintain standard device telemetry logging.",
                    "Verify normal heartbeat synchronization."
                ],
                prevention=[
                    "Periodically review IoT device firmware against vendor security bulletins.",
                    "Maintain zero-trust network segregation for sensitive endpoints."
                ],
                firewall_commands=[],
                approval_required=False,
                approval_status="APPROVED",
                review_notes="Automated benign baseline approval."
            )

        # 1. Containment Playbook
        containment = []
        if "ddos" in attack:
            containment = [
                f"Quarantine target endpoint {dst_ip} in an isolated VLAN to protect upstream bandwidth.",
                f"Apply ingress rate limiting on border gateway targeting source subnet for {src_ip}.",
                "Engage upstream ISP / Cloud Scrubbing Center to filter high-volume volumetric flood.",
                "Verify connection state tables on border firewalls to prevent state exhaustion."
            ]
        elif "mirai" in attack or "botnet" in attack:
            containment = [
                f"Immediately sever network connectivity for suspected botnet node {src_ip}.",
                f"Block outbound Command-and-Control (C2) beaconing to destination {dst_ip}.",
                "Terminate all active Telnet (port 23) and SSH (port 22) administrative sessions.",
                "Capture volatile RAM dumps from compromised device for malware forensic analysis."
            ]
        elif "dos" in attack:
            containment = [
                f"Isolate targeted server/gateway {dst_ip} from public WAN access.",
                "Activate TCP SYN cookie verification and drop malformed packet headers.",
                f"Temporarily blackhole incoming traffic from attacking source {src_ip}.",
                "Monitor CPU and memory utilization on affected IoT broker."
            ]
        elif "brute" in attack:
            containment = [
                f"Enforce immediate connection drop on authentication port {dst_port} from {src_ip}.",
                "Lock targeted accounts with excessive consecutive authentication failures.",
                "Implement 15-minute progressive lockout delay for failed login attempts.",
                "Verify administrative sessions originate only from authorized bastion hosts."
            ]
        elif "recon" in attack:
            containment = [
                f"Deploy temporary dynamic block at perimeter firewall for scanner IP {src_ip}.",
                "Silence ICMP unreachable and TCP RST responses to thwart port sweep enumeration.",
                "Review internal network flow logs for signs of lateral scanning.",
                "Confirm honeypot sensors to capture scanner payloads."
            ]
        elif "spoof" in attack:
            containment = [
                f"Drop spoofed frames originating from {src_ip} via switch Dynamic ARP Inspection (DAI).",
                "Flush ARP cache across local default gateway and core switches.",
                "Enforce strict Unicast Reverse Path Forwarding (uRPF) on routing interfaces.",
                "Isolate rogue switch port connected to anomalous MAC address."
            ]
        elif "web" in attack:
            containment = [
                f"Block web application requests containing command injection signatures from {src_ip}.",
                f"Temporarily disable internet WAN access to device management interface on port {dst_port}.",
                "Place vulnerable IoT web server behind a Web Application Firewall (WAF).",
                "Inspect web server access logs for anomalous POST requests to CGI endpoints."
            ]
        else:
            containment = [
                f"Temporarily restrict network traffic from source {src_ip}.",
                "Capture full-packet PCAP for deep packet inspection.",
                "Verify integrity of device configuration."
            ]

        # 2. Recovery Playbook
        recovery = [
            "Power-cycle / reboot the affected IoT node to purge volatile memory-resident malware payloads.",
            "Re-flash firmware using verified cryptographically signed vendor media if filesystem tampering is suspected.",
            "Rotate all administrative passwords, SSH keys, and MQTT broker access tokens immediately.",
            "Conduct post-incident integrity check before restoring node to production VLAN."
        ]

        # 3. Prevention Playbook
        prevention = [
            "Implement microsegmentation (NIST SP 800-213) placing IoT devices into isolated VLANs without direct WAN routing.",
            "Permanently disable legacy, unencrypted management services (Telnet port 23, HTTP port 80, UPnP) on all IoT devices.",
            "Enforce 802.1X Network Access Control (NAC) to prevent rogue physical device attachments.",
            "Establish continuous automated vulnerability scanning against known IoT CVE databases."
        ]

        # 4. Generate copyable syntax-checked Firewall / ACL Commands
        firewall_commands = []

        # Linux iptables rule
        port_clause = f"--dport {dst_port} " if dst_port > 0 else ""
        proto_clause = f"-p {proto} " if proto in ["tcp", "udp", "icmp"] else ""
        iptables_cmd = f"iptables -A INPUT -s {src_ip} {proto_clause}{port_clause}-j DROP"
        firewall_commands.append(FirewallCommand(
            firewall_type="iptables",
            command=iptables_cmd,
            description=f"Linux Netfilter rule to drop inbound packets from attacker {src_ip}."
        ))

        # Windows Advanced Firewall netsh rule
        rule_name = f"IoTShield_Block_{detection.attack_type}_{src_ip}".replace(" ", "_")
        port_param = f" localport={dst_port}" if dst_port > 0 else ""
        proto_param = f" protocol={proto.upper()}" if proto in ["tcp", "udp"] else ""
        windows_cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={src_ip}{proto_param}{port_param}'
        firewall_commands.append(FirewallCommand(
            firewall_type="windows_netsh",
            command=windows_cmd,
            description=f"Windows Advanced Firewall rule to block inbound traffic from {src_ip}."
        ))

        # Cisco IOS ACL rule
        port_acl = f" eq {dst_port}" if dst_port > 0 else ""
        proto_acl = proto if proto in ["tcp", "udp", "icmp"] else "ip"
        cisco_cmd = f"access-list 100 deny {proto_acl} host {src_ip} host {dst_ip}{port_acl}"
        firewall_commands.append(FirewallCommand(
            firewall_type="cisco_acl",
            command=cisco_cmd,
            description=f"Cisco IOS standard extended ACL dropping traffic from {src_ip} to {dst_ip}."
        ))

        return ResponseOutput(
            containment=containment,
            recovery=recovery,
            prevention=prevention,
            firewall_commands=firewall_commands,
            approval_required=True,
            approval_status="PENDING_ANALYST_APPROVAL",
            reviewed_by=None,
            review_timestamp=None,
            review_notes="Automated execution disabled by policy. Requires SOC Analyst sign-off."
        )


response_agent = ResponseAgent()
