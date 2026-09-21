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
        dur = max(self.last_time - self.start_time, 0.0001)

        lengths = [p.length for p in self.packets]
        tot_sum = sum(lengths)
        tot_size = tot_sum
        min_len = min(lengths)
        max_len = max(lengths)
        avg_len = tot_sum / pkt_count
        variance = float(np.var(lengths)) if pkt_count > 1 else 0.0
        std_len = math.sqrt(variance)

        # Header length sum
        header_len = sum(p.header_length for p in self.packets)

        # Average TTL
        ttls = [p.ttl for p in self.packets if p.ttl > 0]
        avg_ttl = float(np.mean(ttls)) if ttls else 64.0

        # Rate
        rate = pkt_count / dur

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

        # Protocol one-hot / indicators
        sports = {p.src_port for p in self.packets}
        dports = {p.dst_port for p in self.packets}
        all_ports = sports.union(dports)

        is_http = 1 if any(pt in all_ports for pt in [80, 8080]) else 0
        is_https = 1 if any(pt in all_ports for pt in [443, 8443]) else 0
        is_dns = 1 if 53 in all_ports else 0
        is_telnet = 1 if 23 in all_ports else 0
        is_smtp = 1 if any(pt in all_ports for pt in [25, 587, 465]) else 0
        is_ssh = 1 if 22 in all_ports else 0
        is_irc = 1 if any(pt in all_ports for pt in [6667, 6697]) else 0
        is_dhcp = 1 if any(pt in all_ports for pt in [67, 68]) else 0

        is_tcp = 1 if self.protocol_num == 6 else 0
        is_udp = 1 if self.protocol_num == 17 else 0
        is_icmp = 1 if self.protocol_num == 1 else 0
        is_igmp = 1 if self.protocol_num == 2 else 0
        is_arp = 1 if any(p.is_arp for p in self.packets) else 0
        is_ipv = 1 if any(p.is_ipv4 for p in self.packets) else 0
        is_llc = 1 if any(p.is_llc for p in self.packets) else 0

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
        for pkt in reader:
            packet_count += 1
            if max_packets and packet_count > max_packets:
                break

            ts = float(getattr(pkt, 'time', time_now := datetime.now().timestamp()))
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

        reader.close()
    except Exception as e:
        logger.error(f"Error extracting flows from PCAP {pcap_path}: {e}")
        raise RuntimeError(f"CICFlowMeter failed to parse PCAP: {str(e)}")

    if not flows:
        logger.warning(f"No valid IP/ARP flows found in {pcap_path}")
        return pd.DataFrame()

    records = [flow.to_features() for flow in flows.values()]
    df = pd.DataFrame(records)
    logger.info(f"CICFlowMeter extracted {len(df)} flows from {pcap_path}")
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
    Computes a representative overall network record across all extracted flows in a PCAP,
    along with aggregated network context (unique IPs, dominant protocols, total volume).
    This allows running detection and AI explainability on the entire captured traffic session.
    """
    if df.empty:
        return {}, {}

    agg_record: Dict[str, float] = {}
    flag_cols = {
        'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number',
        'ack_flag_number', 'ece_flag_number', 'cwr_flag_number',
        'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP',
        'DHCP', 'ARP', 'ICMP', 'IGMP', 'IPv', 'LLC'
    }

    for col in CICIOT2023_FEATURES:
        if col in df.columns:
            if col in flag_cols:
                # Active if present in at least 25% of flows or prominent
                agg_record[col] = float(1 if float(df[col].mean()) >= 0.25 else 0)
            else:
                agg_record[col] = round(float(df[col].mean()), 4)
        else:
            agg_record[col] = 0.0

    # Extract network context
    src_ips = [str(x) for x in df['Source_IP'].dropna().unique().tolist()] if 'Source_IP' in df.columns else []
    dst_ips = [str(x) for x in df['Destination_IP'].dropna().unique().tolist()] if 'Destination_IP' in df.columns else []
    protos = [str(x) for x in df['Protocol_Name'].dropna().unique().tolist()] if 'Protocol_Name' in df.columns else []

    primary_src = src_ips[0] if src_ips else "0.0.0.0"
    primary_dst = dst_ips[0] if dst_ips else "0.0.0.0"
    if 'Source_IP' in df.columns and not df['Source_IP'].empty:
        primary_src = str(df['Source_IP'].mode().iloc[0])
    if 'Destination_IP' in df.columns and not df['Destination_IP'].empty:
        primary_dst = str(df['Destination_IP'].mode().iloc[0])

    net_ctx = {
        "Timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "Source_IP": primary_src,
        "Destination_IP": primary_dst,
        "Source_Port": int(df['Source_Port'].iloc[0]) if ('Source_Port' in df.columns and not df.empty) else 0,
        "Destination_Port": int(df['Destination_Port'].iloc[0]) if ('Destination_Port' in df.columns and not df.empty) else 0,
        "Protocol_Name": protos[0] if protos else "IP",
        "total_flows": len(df),
        "unique_source_ips": src_ips,
        "unique_destination_ips": dst_ips,
        "observed_protocols": protos
    }

    return agg_record, net_ctx
