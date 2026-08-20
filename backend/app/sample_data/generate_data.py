import os
import random
import datetime
import pandas as pd
import numpy as np

def generate_synthetic_dataset(output_path: str, num_records: int = 5000):
    np.random.seed(42)
    random.seed(42)
    
    # Pre-generate some IP addresses
    benign_ips = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.22"]
    attacker_ips = ["10.0.0.105", "185.220.101.5", "45.227.254.12", "192.168.1.110"]
    iot_servers = ["192.168.1.1", "104.24.12.5", "34.210.15.22", "192.168.1.50"]
    
    base_time = datetime.datetime.now() - datetime.timedelta(hours=6)
    
    records = []
    
    for idx in range(num_records):
        # Determine attack category
        # 60% Benign, 15% DDoS, 10% Mirai, 8% Reconnaissance, 7% Brute Force
        rand_val = random.random()
        
        # Incremental timestamp to show time trends
        timestamp = (base_time + datetime.timedelta(seconds=idx * random.uniform(2, 8))).strftime("%Y-%m-%d %H:%M:%S")
        
        if rand_val < 0.60:
            # Benign IoT traffic (MQTT, HTTP, DNS)
            label = "Benign"
            src_ip = random.choice(benign_ips)
            dst_ip = random.choice(iot_servers)
            protocol = random.choice([6, 17]) # TCP (6) or UDP (17)
            
            # Normal communication features
            flow_duration = float(np.random.exponential(scale=50000)) # microseconds
            total_fwd_packets = int(np.random.poisson(lam=8)) + 1
            total_bwd_packets = int(np.random.poisson(lam=10)) + 1
            
            tot_len_fwd = total_fwd_packets * random.randint(40, 200)
            tot_len_bwd = total_bwd_packets * random.randint(60, 500)
            
            flow_bytes_sec = (tot_len_fwd + tot_len_bwd) / (flow_duration / 1000000.0) if flow_duration > 0 else 0.0
            flow_pkts_sec = (total_fwd_packets + total_bwd_packets) / (flow_duration / 1000000.0) if flow_duration > 0 else 0.0
            
            src_port = random.randint(49152, 65535)
            dst_port = random.choice([80, 443, 1883, 53]) # HTTP, HTTPS, MQTT, DNS
            
            pkt_len_mean = float(np.random.uniform(50, 150))
            pkt_len_std = float(np.random.uniform(10, 40))
            syn_flags = 0 if random.random() > 0.1 else 1
            ack_flags = total_fwd_packets + total_bwd_packets - 1
            avg_pkt_size = (tot_len_fwd + tot_len_bwd) / (total_fwd_packets + total_bwd_packets)
            
        elif rand_val < 0.75:
            # DDoS (SYN Flood / High volume)
            label = "DDoS"
            src_ip = random.choice(attacker_ips)
            dst_ip = random.choice(benign_ips) # Targeting an IoT device
            protocol = 6 # TCP SYN Flood
            
            # DDoS pattern: Short duration, high packets, small size
            flow_duration = float(np.random.uniform(100, 2000))
            total_fwd_packets = random.randint(150, 600)
            total_bwd_packets = random.randint(0, 5) # Few or no responses
            
            tot_len_fwd = total_fwd_packets * 64 # Small SYN packets
            tot_len_bwd = total_bwd_packets * 64
            
            flow_bytes_sec = (tot_len_fwd + tot_len_bwd) / (flow_duration / 1000000.0)
            flow_pkts_sec = (total_fwd_packets + total_bwd_packets) / (flow_duration / 1000000.0)
            
            src_port = random.randint(1024, 65535)
            dst_port = 80 # Targeting web interface
            
            pkt_len_mean = 64.0
            pkt_len_std = 0.0
            syn_flags = total_fwd_packets # Many SYN flags!
            ack_flags = 0
            avg_pkt_size = 64.0
            
        elif rand_val < 0.85:
            # Mirai Botnet / Command & Control outbound
            label = "Mirai"
            src_ip = random.choice(benign_ips) # Infected IoT device
            dst_ip = "210.10.85.14" # C2 server
            protocol = 6 # TCP
            
            # Mirai pattern: repeated outbound telnet scans/requests
            flow_duration = float(np.random.exponential(scale=10000))
            total_fwd_packets = random.randint(15, 60)
            total_bwd_packets = random.randint(10, 50)
            
            tot_len_fwd = total_fwd_packets * 74
            tot_len_bwd = total_bwd_packets * 90
            
            flow_bytes_sec = (tot_len_fwd + tot_len_bwd) / (flow_duration / 1000000.0) if flow_duration > 0 else 0.0
            flow_pkts_sec = (total_fwd_packets + total_bwd_packets) / (flow_duration / 1000000.0) if flow_duration > 0 else 0.0
            
            src_port = random.randint(1024, 65535)
            dst_port = 23 # Telnet scanning/bruting
            
            pkt_len_mean = 80.0
            pkt_len_std = 12.0
            syn_flags = 1
            ack_flags = total_fwd_packets
            avg_pkt_size = 80.0
            
        elif rand_val < 0.93:
            # Reconnaissance (Port Scanning)
            label = "Reconnaissance"
            src_ip = random.choice(attacker_ips)
            dst_ip = random.choice(benign_ips)
            protocol = 6
            
            # Port scanning: rapid TCP connection attempts, very short
            flow_duration = float(np.random.uniform(10, 500))
            total_fwd_packets = random.randint(2, 4)
            total_bwd_packets = random.randint(0, 2)
            
            tot_len_fwd = total_fwd_packets * 44
            tot_len_bwd = total_bwd_packets * 44
            
            flow_bytes_sec = (tot_len_fwd + tot_len_bwd) / (flow_duration / 1000000.0)
            flow_pkts_sec = (total_fwd_packets + total_bwd_packets) / (flow_duration / 1000000.0)
            
            src_port = random.randint(30000, 60000)
            dst_port = random.randint(1, 1024) # Scanning common low ports
            
            pkt_len_mean = 44.0
            pkt_len_std = 0.0
            syn_flags = total_fwd_packets
            ack_flags = 0
            avg_pkt_size = 44.0
            
        else:
            # Brute Force SSH/Telnet login
            label = "Brute Force"
            src_ip = random.choice(attacker_ips)
            dst_ip = random.choice(benign_ips)
            protocol = 6
            
            # Brute Force: many exchange packets, long duration, specific target port
            flow_duration = float(np.random.uniform(100000, 2000000))
            total_fwd_packets = random.randint(20, 80)
            total_bwd_packets = random.randint(20, 80)
            
            tot_len_fwd = total_fwd_packets * 120
            tot_len_bwd = total_bwd_packets * 140
            
            flow_bytes_sec = (tot_len_fwd + tot_len_bwd) / (flow_duration / 1000000.0)
            flow_pkts_sec = (total_fwd_packets + total_bwd_packets) / (flow_duration / 1000000.0)
            
            src_port = random.randint(1024, 65535)
            dst_port = 22 # SSH brute force
            
            pkt_len_mean = 130.0
            pkt_len_std = 25.0
            syn_flags = 1
            ack_flags = total_fwd_packets + total_bwd_packets - 1
            avg_pkt_size = 130.0
            
        # Compile record
        records.append({
            "Timestamp": timestamp,
            "Source_IP": src_ip,
            "Destination_IP": dst_ip,
            "Protocol": protocol,
            "Source_Port": src_port,
            "Destination_Port": dst_port,
            "Flow_Duration": flow_duration,
            "Total_Fwd_Packets": total_fwd_packets,
            "Total_Backward_Packets": total_bwd_packets,
            "Total_Length_of_Fwd_Packets": tot_len_fwd,
            "Total_Length_of_Bwd_Packets": tot_len_bwd,
            "Flow_Bytes_s": flow_bytes_sec,
            "Flow_Packets_s": flow_pkts_sec,
            "Packet_Length_Mean": pkt_len_mean,
            "Packet_Length_Std": pkt_len_std,
            "SYN_Flag_Count": syn_flags,
            "ACK_Flag_Count": ack_flags,
            "Average_Packet_Size": avg_pkt_size,
            "Label": label
        })
        
    df = pd.DataFrame(records)
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Synthetic cybersecurity dataset generated successfully at: {output_path}")
    print(f"Shape: {df.shape} | Labels: {df['Label'].value_counts().to_dict()}")

if __name__ == "__main__":
    output_dir = os.path.dirname(os.path.abspath(__file__))
    generate_synthetic_dataset(os.path.join(output_dir, "iot_sample_traffic.csv"))
