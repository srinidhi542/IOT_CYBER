import re
import time
import logging
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field

from app.agents.agent_schemas import (
    DetectionOutput,
    RiskAssessmentOutput,
    ResponseOutput,
    FirewallCommand
)
from app.llm.agent_helpers import call_llm
from app.llm.prompts.response_prompts import (
    RESPONSE_SYSTEM_PROMPT,
    format_response_prompt
)

logger = logging.getLogger(__name__)

# Precedent memory – stores approved analyst actions for few-shot learning
_APPROVED_PRECEDENTS: List[Dict[str, Any]] = []


def record_approved_precedent(incident: Any):
    """Stores approved incident response decisions to inform future playbooks."""
    global _APPROVED_PRECEDENTS
    if not incident or not incident.response:
        return
    item = {
        "incident_id": incident.incident_id,
        "attack_type": incident.detection.attack_type if incident.detection else "Unknown",
        "severity": incident.risk_assessment.severity if incident.risk_assessment else "Medium",
        "containment": incident.response.containment,
        "review_notes": incident.response.review_notes,
        "reviewer": incident.response.reviewed_by,
    }
    _APPROVED_PRECEDENTS.append(item)
    if len(_APPROVED_PRECEDENTS) > 20:
        _APPROVED_PRECEDENTS.pop(0)


class LLMStructuredResponse(BaseModel):
    containment: List[str] = Field(default_factory=list)
    recovery: List[str] = Field(default_factory=list)
    prevention: List[str] = Field(default_factory=list)
    firewall_commands: List[FirewallCommand] = Field(default_factory=list)


def validate_firewall_command(
    cmd: FirewallCommand,
    incident_src_ip: str,
    incident_dst_ip: str,
) -> Tuple[bool, str]:
    """
    Rule-based safety validator:
    - Verifies syntax matches allow-listed firewall types
    - Rejects destructive commands (e.g. iptables -F, netsh reset, no access-list)
    - Rejects wildcard blocks of private/management subnets or localhost
    - Verifies target IPs match the incident context
    """
    raw_cmd = cmd.command.strip()
    cmd_lower = raw_cmd.lower()

    valid_types = {"iptables", "windows_netsh", "cisco_acl"}
    if cmd.firewall_type not in valid_types:
        return False, f"Invalid firewall type '{cmd.firewall_type}' (must be one of {valid_types})"

    destructive_patterns = [
        r"iptables\s+-(?:f|x|z)\b",
        r"iptables\s+-[a-z]*f\b",
        r"netsh\s+advfirewall\s+reset",
        r"no\s+access-list\b",
        r"rm\s+-rf",
        r"reboot\b",
        r"shutdown\b",
        r":\(\)\{ :\|:& \};:",  # fork bomb
    ]
    for pat in destructive_patterns:
        if re.search(pat, cmd_lower):
            return False, f"Prohibited destructive command pattern detected: {pat}"

    wildcard_patterns = [
        r"\b0\.0\.0\.0/0\b",
        r"\b127\.0\.0\.1\b",
        r"\blocalhost\b",
        r"\b255\.255\.255\.255\b",
    ]
    for pat in wildcard_patterns:
        if re.search(pat, cmd_lower):
            return False, f"Prohibited wildcard or loopback blocking rule: {pat}"

    # At least one IP in the command must match the incident endpoints
    found_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_cmd)
    incident_ips = {incident_src_ip, incident_dst_ip} - {"0.0.0.0", "Unknown", ""}
    if incident_ips and found_ips:
        if not any(ip in incident_ips for ip in found_ips):
            return False, (
                f"Command references unverified external IP {found_ips} "
                f"not matching incident endpoints {incident_ips}"
            )

    return True, "Valid"


class ResponseAgent:
    """
    Response Agent:
    Formulates structured containment, recovery, and prevention playbooks.
    Generates copyable firewall and ACL commands tailored to incident network context.

    SAFETY & COMPLIANCE MANDATES:
    - Never auto-executes commands on host or network.
    - All firewall rules and mitigation playbooks strictly require analyst sign-off.
    - Generated commands must pass rule-based safety validation.
    """

    def generate_response_plan(
        self,
        detection: DetectionOutput,
        risk: Optional[RiskAssessmentOutput] = None,
        user_id: str = "system",
    ) -> ResponseOutput:
        from app.core.config import load_platform_settings
        platform_cfg = load_platform_settings()
        llm_cfg = platform_cfg.get("llm", {})

        attack = detection.attack_type.strip().lower()
        is_benign = attack in ["benign", "normal"]

        src_ip = detection.network_context.source_ip or "0.0.0.0"
        dst_ip = detection.network_context.destination_ip or "0.0.0.0"
        dst_port = detection.network_context.destination_port or 0
        proto = (detection.network_context.protocol or "TCP").lower()
        severity = risk.severity if risk else "Medium"

        # ------------------------------------------------------------------
        # 1. Benign Traffic Shortcut
        # ------------------------------------------------------------------
        if is_benign:
            return ResponseOutput(
                containment=[
                    "No active containment required for baseline network traffic.",
                    "Keep endpoint under continuous passive anomaly monitoring.",
                ],
                recovery=[
                    "Maintain standard device telemetry logging.",
                    "Verify normal heartbeat synchronization.",
                ],
                prevention=[
                    "Periodically review IoT device firmware against vendor security bulletins.",
                    "Maintain zero-trust network segregation for sensitive endpoints.",
                ],
                firewall_commands=[],
                approval_required=False,
                approval_status="APPROVED",
                review_notes="Automated benign baseline approval.",
                generated_by="rule_based",
            )

        # ------------------------------------------------------------------
        # 2. LLM-Assisted Playbook Generation via call_llm
        # ------------------------------------------------------------------
        llm_enabled = bool(llm_cfg.get("enabled", True))
        llm_agent_on = llm_cfg.get("agent_toggles", {}).get("response", True)
        used_llm = False
        llm_model = None
        latency_ms = None
        structured_plan: Optional[LLMStructuredResponse] = None

        if llm_enabled and llm_agent_on:
            try:
                t0 = time.time()
                prompt = format_response_prompt(
                    attack_type=detection.attack_type,
                    severity=severity,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    proto=proto,
                    guidelines_context=(
                        "NIST SP 800-213 microsegmentation, disable unencrypted protocols, "
                        "rotate credentials, apply least-privilege ACLs."
                    ),
                    past_approved_responses=_APPROVED_PRECEDENTS,
                )
                success, result = call_llm(
                    system=RESPONSE_SYSTEM_PROMPT,
                    user_prompt=prompt,
                    agent_name="response",
                    user_id=user_id,
                    schema=LLMStructuredResponse,
                )
                if success and isinstance(result, LLMStructuredResponse):
                    structured_plan = result
                    latency_ms = round((time.time() - t0) * 1000, 2)
                    used_llm = True
                    try:
                        from app.llm.client import get_llm_client as _gc
                        llm_model = _gc().model
                    except Exception:
                        llm_model = None
                else:
                    logger.warning(f"[ResponseAgent] call_llm returned failure: {result}")
            except Exception as le:
                logger.warning(
                    f"[ResponseAgent] LLM playbook generation failed "
                    f"(falling back to deterministic playbooks): {le}"
                )

        # ------------------------------------------------------------------
        # 3. Deterministic Playbook Fallback
        # ------------------------------------------------------------------
        if not used_llm or not structured_plan:
            containment, recovery, prevention, fallback_commands = self._generate_rule_based_plan(
                attack=attack,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
            )
            structured_plan = LLMStructuredResponse(
                containment=containment,
                recovery=recovery,
                prevention=prevention,
                firewall_commands=fallback_commands,
            )

        # ------------------------------------------------------------------
        # 4. Mandatory Safety Validation on Firewall Commands
        # ------------------------------------------------------------------
        validated_commands: List[FirewallCommand] = []
        for cmd in structured_plan.firewall_commands:
            is_valid, reason = validate_firewall_command(cmd, src_ip, dst_ip)
            if is_valid:
                validated_commands.append(cmd)
            else:
                logger.warning(
                    f"[Response Safety Alert] Dropped invalid firewall command "
                    f"'{cmd.command}': {reason}"
                )

        # If all LLM commands failed validation, supply safe deterministic rules
        if not validated_commands:
            logger.info("Supplying deterministic fallback firewall commands after validation filtering.")
            _, _, _, fallback_cmds = self._generate_rule_based_plan(
                attack=attack,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
            )
            validated_commands = fallback_cmds

        return ResponseOutput(
            containment=structured_plan.containment,
            recovery=structured_plan.recovery,
            prevention=structured_plan.prevention,
            firewall_commands=validated_commands,
            approval_required=True,
            approval_status="PENDING_ANALYST_APPROVAL",
            reviewed_by=None,
            review_timestamp=None,
            review_notes="Automated execution disabled by policy. Requires SOC Analyst sign-off.",
            generated_by="llm" if used_llm else "rule_based_fallback",
            llm_model=llm_model,
            latency_ms=latency_ms,
        )

    # ------------------------------------------------------------------
    # Rule-Based Deterministic Plan Builder
    # ------------------------------------------------------------------
    def _generate_rule_based_plan(
        self,
        attack: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
    ) -> Tuple[List[str], List[str], List[str], List[FirewallCommand]]:
        """Generate deterministic containment/recovery/prevention steps and safe firewall rules."""

        containment: List[str] = []
        recovery: List[str] = []
        prevention: List[str] = []
        commands: List[FirewallCommand] = []

        if "ddos" in attack or "dos" in attack or "mirai" in attack or "botnet" in attack:
            containment = [
                f"Immediately isolate the affected IoT device at {dst_ip} from the network segment.",
                f"Apply ingress rate-limiting on traffic from {src_ip} at the upstream router.",
                "Alert the ISP or upstream provider to null-route the attack source.",
                "Activate network-layer DDoS mitigation (scrubbing center or RTBH).",
            ]
            recovery = [
                "Restore device connectivity after attack traffic subsides.",
                "Review device firmware and patch to latest vendor release.",
                "Rotate all default device credentials immediately.",
                "Verify device integrity via manufacturer hash / secure boot log.",
            ]
            prevention = [
                "Deploy NIST SP 800-213 compliant network micro-segmentation for IoT devices.",
                "Enable ingress/egress rate-limiting policies on all IoT VLANs.",
                "Implement device allowlisting to prevent unauthorized communication patterns.",
                "Schedule quarterly firmware vulnerability assessments.",
            ]
            commands = [
                FirewallCommand(
                    firewall_type="iptables",
                    command=f"iptables -A INPUT -s {src_ip} -j DROP",
                    description=f"Block all inbound traffic from attacker {src_ip}",
                ),
                FirewallCommand(
                    firewall_type="windows_netsh",
                    command=f'netsh advfirewall firewall add rule name="Block_{src_ip}" dir=in action=block remoteip={src_ip}',
                    description=f"Block inbound traffic from {src_ip} on Windows hosts",
                ),
            ]

        elif "brute force" in attack:
            containment = [
                f"Immediately block source IP {src_ip} at the perimeter firewall.",
                f"Lock the targeted account / service on {dst_ip}:{dst_port}.",
                "Alert on-call SOC analyst for credential compromise assessment.",
            ]
            recovery = [
                "Force password reset on all accounts potentially exposed.",
                "Review authentication logs for successful logins from {src_ip}.",
                "Enable multi-factor authentication on all administrative interfaces.",
            ]
            prevention = [
                "Enforce account lockout after 5 failed attempts (NIST SP 800-63B).",
                "Disable direct root/admin SSH login; use key-based authentication only.",
                "Implement geo-IP blocking for unrecognized source regions.",
            ]
            commands = [
                FirewallCommand(
                    firewall_type="iptables",
                    command=f"iptables -A INPUT -s {src_ip} -p {proto} --dport {dst_port} -j DROP",
                    description=f"Block brute-force attempts from {src_ip} on port {dst_port}",
                ),
            ]

        elif "recon" in attack or "reconnaissance" in attack or "spoofing" in attack:
            containment = [
                f"Rate-limit or block scanning traffic from {src_ip}.",
                "Enable port-scan detection and automatic blocking on the IDS/IPS.",
            ]
            recovery = [
                "Review exposed service inventory – close unnecessary ports.",
                "Verify no unauthorized access occurred during reconnaissance window.",
            ]
            prevention = [
                "Apply host-based firewall rules to restrict non-essential service exposure.",
                "Enable network honeypots to detect and delay reconnaissance activities.",
                "Conduct regular attack-surface reduction audits (OWASP IoT Top 10).",
            ]
            commands = [
                FirewallCommand(
                    firewall_type="iptables",
                    command=f"iptables -A INPUT -s {src_ip} -m limit --limit 5/min -j ACCEPT",
                    description=f"Rate-limit traffic from suspected reconnaissance source {src_ip}",
                ),
            ]

        else:
            # Generic fallback
            containment = [
                f"Quarantine traffic from {src_ip} pending investigation.",
                "Escalate incident to Tier-2 SOC analyst for manual review.",
            ]
            recovery = [
                "Perform forensic memory and log capture on affected IoT device.",
                "Restore device from known-good firmware backup if compromise confirmed.",
            ]
            prevention = [
                "Review and harden IoT device network access policies.",
                "Apply NIST SP 800-213 security controls for IoT deployment.",
            ]
            commands = [
                FirewallCommand(
                    firewall_type="iptables",
                    command=f"iptables -A INPUT -s {src_ip} -j DROP",
                    description=f"Block unclassified threat source {src_ip}",
                ),
            ]

        return containment, recovery, prevention, commands


response_agent = ResponseAgent()
