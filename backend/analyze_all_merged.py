import os
import glob
import json
import time
from collections import Counter
import pandas as pd
import numpy as np

FOLDER = r"C:\Users\Sanjana\Downloads\MERGED_CSV\MERGED_CSV"

RAW_ATTACK_MAPPING = {
    'DDOS-RSTFINFLOOD': 'DDoS', 'DDOS-PSHACK_FLOOD': 'DDoS', 'DDOS-SYN_FLOOD': 'DDoS',
    'DDOS-UDP_FLOOD': 'DDoS', 'DDOS-TCP_FLOOD': 'DDoS', 'DDOS-ICMP_FLOOD': 'DDoS',
    'DDOS-SYNONYMOUSIP_FLOOD': 'DDoS', 'DDOS-ACK_FRAGMENTATION': 'DDoS',
    'DDOS-UDP_FRAGMENTATION': 'DDoS', 'DDOS-ICMP_FRAGMENTATION': 'DDoS',
    'DDOS-SLOWLORIS': 'DoS', 'DDOS-HTTP_FLOOD': 'DoS',
    'DOS-UDP_FLOOD': 'DoS', 'DOS-TCP_FLOOD': 'DoS', 'DOS-SYN_FLOOD': 'DoS',
    'DOS-HTTP_FLOOD': 'DoS',
    'MIRAI-GREETH_FLOOD': 'Mirai', 'MIRAI-GREIP_FLOOD': 'Mirai', 'MIRAI-UDPPLAIN': 'Mirai',
    'RECON-PINGSWEEP': 'Recon', 'RECON-OSSCAN': 'Recon', 'RECON-PORTSCAN': 'Recon',
    'VULNERABILITYSCAN': 'Recon', 'RECON-HOSTDISCOVERY': 'Recon', 'RECONNAISSANCE': 'Recon',
    'DNS_SPOOFING': 'Spoofing', 'MITM-ARPSPOOFING': 'Spoofing', 'SPOOFING': 'Spoofing',
    'BENIGNTRAFFIC': 'Benign', 'BENIGN': 'Benign', 'NORMAL': 'Benign',
    'BROWSERHIJACKING': 'Web Attack', 'BACKDOOR_MALWARE': 'Web Attack',
    'XSS': 'Web Attack', 'UPLOADING_ATTACK': 'Web Attack',
    'SQLINJECTION': 'Web Attack', 'COMMANDINJECTION': 'Web Attack', 'WEB ATTACK': 'Web Attack',
    'DICTIONARYBRUTEFORCE': 'Brute Force', 'BRUTE FORCE': 'Brute Force', 'BOTNET': 'Mirai'
}

def analyze_dataset():
    files = sorted(glob.glob(os.path.join(FOLDER, "*.csv")))
    print(f"[*] Found {len(files)} files. Starting stream analysis...")
    
    total_rows = 0
    raw_label_counts = Counter()
    mapped_8class_counts = Counter()
    missing_counts = Counter()
    inf_counts = Counter()
    
    start_time = time.time()
    
    for i, file_path in enumerate(files, 1):
        file_name = os.path.basename(file_path)
        file_rows = 0
        
        # Read in 100k chunks for memory efficiency and fast processing
        for chunk in pd.read_csv(file_path, chunksize=100000, low_memory=False):
            file_rows += len(chunk)
            
            # Find label column
            label_col = 'Label' if 'Label' in chunk.columns else ('label' if 'label' in chunk.columns else None)
            if label_col:
                raw_counts = chunk[label_col].astype(str).str.strip().value_counts().to_dict()
                for k, v in raw_counts.items():
                    raw_label_counts[k] += v
                    mapped_k = RAW_ATTACK_MAPPING.get(k.upper(), k)
                    mapped_8class_counts[mapped_k] += v
                    
            # Check nulls and infs in numeric columns
            numeric_cols = chunk.select_dtypes(include=[np.number])
            for col in numeric_cols.columns:
                null_c = numeric_cols[col].isna().sum()
                if null_c > 0:
                    missing_counts[col] += int(null_c)
                inf_c = np.isinf(numeric_cols[col]).sum()
                if inf_c > 0:
                    inf_counts[col] += int(inf_c)

        total_rows += file_rows
        elapsed = time.time() - start_time
        print(f"[{i:02d}/{len(files)}] {file_name}: {file_rows:,} rows | Total: {total_rows:,} rows ({elapsed:.1f}s)")

    results = {
        "total_files": len(files),
        "total_rows": total_rows,
        "raw_label_counts": dict(raw_label_counts.most_common()),
        "mapped_8class_counts": dict(mapped_8class_counts.most_common()),
        "missing_counts": dict(missing_counts),
        "inf_counts": dict(inf_counts),
        "analysis_time_seconds": round(time.time() - start_time, 2)
    }

    out_path = r"backend\reports\eda_merged_dataset_summary.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Analysis complete in {results['analysis_time_seconds']}s. Saved summary to {out_path}")

if __name__ == "__main__":
    analyze_dataset()
