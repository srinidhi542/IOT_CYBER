import os
import math
import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

# The exact 39 features expected by the tuned 8-class XGBoost model
CICIOT2023_FEATURES = [
    'Header_Length', 'Protocol Type', 'Time_To_Live', 'Rate',
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number',
    'psh_flag_number', 'ack_flag_number', 'ece_flag_number',
    'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'rst_count',
    'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP',
    'DHCP', 'ARP', 'ICMP', 'IGMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max',
    'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Variance'
]


class FlowPacket:
    """Represents a simplified parsed packet for flow feature computation."""
    def __init__(
        self,
        timestamp: float,
        length: int,
        header_length: int,
        protocol: int,
        ttl: int,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        flags: Dict[str, bool],
        is_ipv4: bool = True,
        is_arp: bool = False,
        is_llc: bool = False
    ):
        self.timestamp = timestamp
        self.length = length
        self.header_length = header_length
        self.protocol = protocol
        self.ttl = ttl
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.flags = flags
        self.is_ipv4 = is_ipv4
        self.is_arp = is_arp
        self.is_llc = is_llc


class Flow:
    """Aggregates packets belonging to a bidirectional network flow."""
    def __init__(self, key: Tuple[str, str, int, int, int], first_packet: FlowPacket):
        self.key = key  # (ip1, ip2, port1, port2, proto) normalized
        self.packets: List[FlowPacket] = [first_packet]
        self.start_time = first_packet.timestamp
        self.last_time = first_packet.timestamp
        self.representative_src = first_packet.src_ip
        self.representative_dst = first_packet.dst_ip
        self.representative_sport = first_packet.src_port
        self.representative_dport = first_packet.dst_port
        self.protocol_num = first_packet.protocol

    def add_packet(self, packet: FlowPacket):
        self.packets.append(packet)
        self.last_time = max(self.last_time, packet.timestamp)

    def to_features(self) -> Dict[str, Any]:
        """Calculates the exact 39 CICIoT2023 features for this flow."""
        pkt_count = len(self.packets)
        actual_dur = self.last_time - self.start_time  # real observed duration, may be 0

        lengths = [p.length for p in self.packets]
        tot_sum = sum(lengths)
        tot_size = tot_sum
        min_len = min(lengths)
        max_len = max(lengths)
        avg_len = tot_sum / pkt_count
        variance = float(np.var(lengths)) if pkt_count > 1 else 0.0
        std_len = math.sqrt(variance)

        # Average header length across flow packets (matches CICIoT2023 schema)
        header_len = float(sum(p.header_length for p in self.packets) / pkt_count)

        # Average TTL
        ttls = [p.ttl for p in self.packets if p.ttl > 0]
        avg_ttl = float(np.mean(ttls)) if ttls else 64.0

        # Flow transmission rate (packets / second).
        # For single-packet flows (dur==0) use 0.0 — not 1/0.0001=10000.
        # Inflating Rate causes Recon misclassification because the CICIoT2023 training
        # Recon samples have very high rates.
        #
        # MICRO-BURST SMOOTHING (Fix for live LAN false-positive Recon verdicts):
        # Short benign flows (ARP, DNS, mDNS, multicast) send 2-5 packets within
        # tens of microseconds: Rate = 2 / 0.00004 = 46,000 pkts/sec.
        # The XGBoost model reads this as Recon (99% confidence).
        # Real Recon traffic also has high rates, but over a SUSTAINED window (seconds).
        # Solution: for micro-burst flows (≤5 pkts arriving in <1.0s) compute Rate
        # over a normalised 1.0-second window so that they look like what they are —
        # low-volume bursts — not scanner sweeps.
        if actual_dur > 0:
            if pkt_count <= 5 and actual_dur < 1.0:
                # Normalise to 1-second effective window to suppress burst inflation
                effective_dur = 1.0
                rate = float(pkt_count / effective_dur)
            else:
                rate = float(pkt_count / actual_dur)
        else:
            rate = 0.0

        # Inter-arrival times (IAT)
        if pkt_count > 1:
            timestamps = sorted([p.timestamp for p in self.packets])
            iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_iat = float(np.mean(iats))
        else:
            avg_iat = 0.0

        # Flag counts & numbers
        fin_count = sum(1 for p in self.packets if p.flags.get('F'))
        syn_count = sum(1 for p in self.packets if p.flags.get('S'))
        rst_count = sum(1 for p in self.packets if p.flags.get('R'))
        psh_count = sum(1 for p in self.packets if p.flags.get('P'))
        ack_count = sum(1 for p in self.packets if p.flags.get('A'))
        ece_count = sum(1 for p in self.packets if p.flags.get('E'))
        cwr_count = sum(1 for p in self.packets if p.flags.get('C'))

        fin_flag_number = 1 if fin_count > 0 else 0
        syn_flag_number = 1 if syn_count > 0 else 0
        rst_flag_number = 1 if rst_count > 0 else 0
        psh_flag_number = 1 if psh_count > 0 else 0
        ack_flag_number = 1 if ack_count > 0 else 0
        ece_flag_number = 1 if ece_count > 0 else 0
        cwr_flag_number = 1 if cwr_count > 0 else 0

        # Strict Protocol Identification (Mutually Exclusive)
        is_arp = 1 if any(p.is_arp for p in self.packets) else 0
        is_tcp = 1 if (self.protocol_num == 6 and not is_arp) else 0
        is_udp = 1 if (self.protocol_num == 17 and not is_arp) else 0
        is_icmp = 1 if (self.protocol_num == 1 and not is_arp) else 0
        is_igmp = 1 if (self.protocol_num == 2 and not is_arp) else 0
        is_ipv = 1 if (any(p.is_ipv4 for p in self.packets) and not is_arp) else 0
        is_llc = 1 if any(p.is_llc for p in self.packets) else 0

        # Application Ports only active for matching transport
        sports = {p.src_port for p in self.packets}
        dports = {p.dst_port for p in self.packets}
        all_ports = sports.union(dports)

        is_http = 1 if (is_tcp and any(pt in all_ports for pt in [80, 8080])) else 0
        is_https = 1 if (is_tcp and any(pt in all_ports for pt in [443, 8443])) else 0
        is_dns = 1 if ((is_udp or is_tcp) and 53 in all_ports) else 0
        is_telnet = 1 if (is_tcp and 23 in all_ports) else 0
        is_smtp = 1 if (is_tcp and any(pt in all_ports for pt in [25, 587, 465])) else 0
        is_ssh = 1 if (is_tcp and 22 in all_ports) else 0
        is_irc = 1 if (is_tcp and any(pt in all_ports for pt in [6667, 6697])) else 0
        is_dhcp = 1 if (is_udp and any(pt in all_ports for pt in [67, 68])) else 0

        features = {
            'Header_Length': round(float(header_len), 2),
            'Protocol Type': float(self.protocol_num),
            'Time_To_Live': round(avg_ttl, 2),
            'Rate': round(rate, 4),
            'fin_flag_number': fin_flag_number,
            'syn_flag_number': syn_flag_number,
            'rst_flag_number': rst_flag_number,
            'psh_flag_number': psh_flag_number,
            'ack_flag_number': ack_flag_number,
            'ece_flag_number': ece_flag_number,
            'cwr_flag_number': cwr_flag_number,
            'ack_count': ack_count,
            'syn_count': syn_count,
            'fin_count': fin_count,
            'rst_count': rst_count,
            'HTTP': is_http,
            'HTTPS': is_https,
            'DNS': is_dns,
            'Telnet': is_telnet,
            'SMTP': is_smtp,
            'SSH': is_ssh,
            'IRC': is_irc,
            'TCP': is_tcp,
            'UDP': is_udp,
            'DHCP': is_dhcp,
            'ARP': is_arp,
            'ICMP': is_icmp,
            'IGMP': is_igmp,
            'IPv': is_ipv,
            'LLC': is_llc,
            'Tot sum': round(float(tot_sum), 2),
            'Min': round(float(min_len), 2),
            'Max': round(float(max_len), 2),
            'AVG': round(float(avg_len), 2),
            'Std': round(float(std_len), 4),
            'Tot size': round(float(tot_size), 2),
            'IAT': round(avg_iat, 6),
            'Number': pkt_count,
            'Variance': round(variance, 4),
            # Rich network context for downstream agents & SOC UI
            'Timestamp': datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S'),
            'Source_IP': self.representative_src,
            'Destination_IP': self.representative_dst,
            'Source_Port': self.representative_sport,
            'Destination_Port': self.representative_dport,
            'Protocol_Name': 'TCP' if is_tcp else ('UDP' if is_udp else ('ICMP' if is_icmp else str(self.protocol_num)))
        }
        return features


def extract_flows_from_pcap(pcap_path: str, max_packets: int = 10000) -> pd.DataFrame:
    """
    Parses a PCAP file using Scapy, aggregates packets into bidirectional flows,
    and returns a DataFrame containing all 39 model features plus network context.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    from scapy.utils import PcapReader
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP

    flows: Dict[Tuple[str, str, int, int, int], Flow] = {}
    packet_count = 0

    try:
        reader = PcapReader(pcap_path)
        while True:
            try:
                pkt = reader.read_packet()
                if pkt is None:
                    break
            except (EOFError, StopIteration):
                break
            except Exception as read_err:
                logger.warning(f"Stopped PCAP stream read at packet {packet_count} due to trailing truncation: {read_err}")
                break

            packet_count += 1
            if max_packets and packet_count > max_packets:
                break

            ts = float(getattr(pkt, 'time', datetime.now().timestamp()))
            length = len(pkt)

            # Check layer presence
            is_ipv4 = IP in pkt
            is_arp_pkt = ARP in pkt
            is_llc_pkt = hasattr(pkt, 'haslayer') and pkt.haslayer('LLC')

            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            proto = 0
            ttl = 64
            header_length = 20
            sport = 0
            dport = 0
            flags = {}

            if is_ipv4:
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto = int(ip_layer.proto)
                ttl = int(ip_layer.ttl)
                header_length = int(ip_layer.ihl) * 4

                if TCP in pkt:
                    tcp_layer = pkt[TCP]
                    sport = int(tcp_layer.sport)
                    dport = int(tcp_layer.dport)
                    header_length += int(tcp_layer.dataofs) * 4
                    flag_str = str(tcp_layer.flags)
                    flags = {
                        'F': 'F' in flag_str,
                        'S': 'S' in flag_str,
                        'R': 'R' in flag_str,
                        'P': 'P' in flag_str,
                        'A': 'A' in flag_str,
                        'E': 'E' in flag_str,
                        'C': 'C' in flag_str,
                    }
                elif UDP in pkt:
                    udp_layer = pkt[UDP]
                    sport = int(udp_layer.sport)
                    dport = int(udp_layer.dport)
                    header_length += 8
                elif ICMP in pkt:
                    proto = 1
                    header_length += 8
            elif is_arp_pkt:
                arp_layer = pkt[ARP]
                src_ip = arp_layer.psrc
                dst_ip = arp_layer.pdst
                proto = 2054  # ARP ethertype
                header_length = 28
                header_length = 28

            parsed_pkt = FlowPacket(
                timestamp=ts,
                length=length,
                header_length=header_length,
                protocol=proto,
                ttl=ttl,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                flags=flags,
                is_ipv4=is_ipv4,
                is_arp=is_arp_pkt,
                is_llc=is_llc_pkt
            )

            # Form bidirectional flow key
            # Sort endpoints so (A->B) and (B->A) belong to the same conversation flow
            if (src_ip, sport) <= (dst_ip, dport):
                flow_key = (src_ip, dst_ip, sport, dport, proto)
            else:
                flow_key = (dst_ip, src_ip, dport, sport, proto)

            if flow_key not in flows:
                flows[flow_key] = Flow(flow_key, parsed_pkt)
            else:
                flows[flow_key].add_packet(parsed_pkt)

        try:
            reader.close()
        except Exception:
            pass
    except Exception as e:
        if not flows:
            logger.error(f"Error extracting flows from PCAP {pcap_path}: {e}")
            raise RuntimeError(f"CICFlowMeter failed to parse PCAP: {str(e)}")

    if not flows:
        logger.warning(f"No valid IP/ARP flows found in {pcap_path}")
        return pd.DataFrame()

    records = [flow.to_features() for flow in flows.values()]
    df = pd.DataFrame(records)

    # Drop phantom flows where both endpoints are 0.0.0.0 — these are non-IP
    # frames (raw 802.11 management frames, broken IGMP, etc.) that produced no
    # usable IP header. They can have large packet counts and bias aggregation.
    if 'Source_IP' in df.columns and 'Destination_IP' in df.columns:
        phantom_mask = (df['Source_IP'] == '0.0.0.0') & (df['Destination_IP'] == '0.0.0.0')
        phantom_count = phantom_mask.sum()
        if phantom_count > 0:
            logger.info(f"Dropped {phantom_count} phantom 0.0.0.0 flows (non-IP frames)")
            df = df[~phantom_mask].reset_index(drop=True)

    df.attrs['total_packets'] = packet_count
    logger.info(f"CICFlowMeter parsed {packet_count} packets into {len(df)} flows from {pcap_path}")
    return df


def process_pcap_to_detection(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Complete pipeline bridging raw PCAP into the existing XGBoost & SHAP Detection Agent.
    Returns detected threats with full network details, confidence, and SHAP evidence.
    """
    df = extract_flows_from_pcap(pcap_path)
    if df.empty:
        return []

    from app.ml.predict_pipeline import explain_prediction

    detection_results = []
    for idx, row in df.iterrows():
        record_dict = row.to_dict()
        try:
            # Predict & generate real SHAP explainability through existing pipeline
            shap_res = explain_prediction(record_dict, top_k=5)
            detection_results.append({
                "flow_index": int(idx),
                "timestamp": record_dict.get("Timestamp"),
                "source_ip": record_dict.get("Source_IP"),
                "destination_ip": record_dict.get("Destination_IP"),
                "source_port": record_dict.get("Source_Port"),
                "destination_port": record_dict.get("Destination_Port"),
                "protocol": record_dict.get("Protocol_Name"),
                "attack_type": shap_res["label"],
                "confidence": shap_res["confidence"],
                "probabilities": shap_res["probabilities"],
                "top_contributing_features": shap_res["top_contributing_features"],
                "shap_values": shap_res["shap_values"],
                "raw_features": {f: record_dict.get(f, 0.0) for f in CICIOT2023_FEATURES}
            })
        except Exception as e:
            logger.error(f"Detection failed for flow {idx}: {e}")
            continue

    return detection_results


def aggregate_flow_features(df: pd.DataFrame) -> Tuple[Dict[str, float], Dict[str, Any]]:
    """
    Evaluates each extracted bidirectional flow individually through the detection pipeline
    to avoid multi-protocol averaging distortion. Selects the dominant representative flow
    record and contextual metadata for the overall captured session.
    """
    if df.empty:
        return {}, {}

    from app.ml.predict_pipeline import predict_tuned

    # 1. Evaluate each individual flow
    flow_predictions = []
    for idx, row in df.iterrows():
        record = row.to_dict()
        try:
            pred = predict_tuned(record)
            flow_predictions.append((idx, pred))
            logger.debug(
                f"Flow {idx}: Rate={record.get('Rate', 0):.2f} "
                f"Std={record.get('Std', 0):.2f} "
                f"Variance={record.get('Variance', 0):.2f} "
                f"Number={record.get('Number', 0)} "
                f"-> {pred['label']} ({pred['confidence']*100:.1f}%)"
            )
        except Exception as e:
            logger.error(
                f"Flow {idx} prediction failed: {e} | "
                f"Rate={record.get('Rate', '?')} Std={record.get('Std', '?')} "
                f"Number={record.get('Number', '?')}"
            )
            # Skip failed flows — do NOT fall back to a hardcoded label
            continue

    if not flow_predictions:
        logger.warning("All flow predictions failed — cannot determine representative flow.")
        return {}, {}

    # 2. Separate attack vs benign flows
    attack_flows = [
        (idx, p) for idx, p in flow_predictions
        if p["label"].lower() not in ["benign", "normal"]
    ]
    benign_flows = [
        (idx, p) for idx, p in flow_predictions
        if p["label"].lower() in ["benign", "normal"]
    ]
    total_flows = len(flow_predictions)

    logger.info(
        f"Flow breakdown: {total_flows} total | "
        f"{len(attack_flows)} attack | {len(benign_flows)} benign"
    )

    # 3. Quorum-based representative selection.
    #
    # PROBLEM (before this fix):
    #   Even 1 misclassified 2-packet mDNS broadcast (false-positive Recon due to
    #   micro-burst rate inflation) was enough to make the whole session an attack,
    #   even when 140+ other flows were perfectly Benign.
    #
    # FIX: Require the attack signal to be statistically meaningful:
    #   - attack_ratio  >= 10% of all flows, AND
    #   - attack_pkts   >= 15 total packets across attack flows
    #   OR (special case): very small captures (<=3 flows) where even 1 flow matters.
    attack_ratio = len(attack_flows) / total_flows if total_flows > 0 else 0.0
    attack_pkts = sum(int(df.loc[idx, 'Number']) for idx, _ in attack_flows) if attack_flows else 0

    session_is_attack = bool(attack_flows) and (
        total_flows <= 3
        or (attack_ratio >= 0.10 and attack_pkts >= 15)
    )

    if session_is_attack:
        chosen_idx, chosen_pred = max(attack_flows, key=lambda x: x[1]["confidence"])
        logger.info(
            f"Representative: attack flow {chosen_idx} -> "
            f"{chosen_pred['label']} ({chosen_pred['confidence']*100:.1f}%) "
            f"[quorum: {attack_ratio*100:.1f}% of flows, {attack_pkts} attack pkts]"
        )
    else:
        if attack_flows:
            logger.info(
                f"Attack flows below quorum ({attack_ratio*100:.1f}% of flows, "
                f"{attack_pkts} attack pkts) -> treating session as Benign"
            )
        # Pick representative from flows that were actually classified as benign.
        # Using df['Number'].idxmax() on ALL flows can accidentally select a high-packet
        # attack flow as representative, producing a false attack verdict for the session.
        if benign_flows and 'Number' in df.columns:
            benign_indices = [idx for idx, _ in benign_flows]
            chosen_idx = df.loc[benign_indices, 'Number'].idxmax()
        elif benign_flows:
            chosen_idx = benign_flows[0][0]
        else:
            chosen_idx = df.index[0]
        logger.info(f"Representative: benign flow {chosen_idx} (highest packet count among benign flows)")

    # 4. Use the genuine feature set of the chosen flow as the representative record
    representative_row = df.loc[chosen_idx].to_dict()
    agg_record = {col: float(representative_row.get(col, 0.0)) for col in CICIOT2023_FEATURES}
    agg_record['Source_IP'] = representative_row.get('Source_IP', '')
    agg_record['Destination_IP'] = representative_row.get('Destination_IP', '')
    agg_record['Protocol_Name'] = representative_row.get('Protocol_Name', '')
    agg_record['Source_Port'] = representative_row.get('Source_Port', 0)
    agg_record['Destination_Port'] = representative_row.get('Destination_Port', 0)

    # Extract overall network context
    src_ips = [str(x) for x in df['Source_IP'].dropna().unique().tolist()] if 'Source_IP' in df.columns else []
    dst_ips = [str(x) for x in df['Destination_IP'].dropna().unique().tolist()] if 'Destination_IP' in df.columns else []
    protos = [str(x) for x in df['Protocol_Name'].dropna().unique().tolist()] if 'Protocol_Name' in df.columns else []

    primary_src = str(representative_row.get('Source_IP', src_ips[0] if src_ips else "0.0.0.0"))
    primary_dst = str(representative_row.get('Destination_IP', dst_ips[0] if dst_ips else "0.0.0.0"))

    total_pkts = df.attrs.get('total_packets', int(df['Number'].sum()) if 'Number' in df.columns else len(df))

    net_ctx = {
        "Timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "Source_IP": primary_src,
        "Destination_IP": primary_dst,
        "Source_Port": int(representative_row.get('Source_Port', 0)),
        "Destination_Port": int(representative_row.get('Destination_Port', 0)),
        "Protocol_Name": str(representative_row.get('Protocol_Name', protos[0] if protos else "IP")),
        "total_packets": total_pkts,
        "total_flows": total_flows,
        "attack_flows": len(attack_flows),
        "benign_flows": len(benign_flows),
        "unique_source_ips": src_ips,
        "unique_destination_ips": dst_ips,
        "observed_protocols": protos
    }

    return agg_record, net_ctx

