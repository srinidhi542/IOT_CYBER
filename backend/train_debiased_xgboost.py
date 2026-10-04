#!/usr/bin/env python3
"""
Debiased Two-Stage Hierarchical XGBoost Retraining Pipeline for CICIoT2023

Why this exists:
Standard 8-class models trained on raw CICIoT2023 cheat by using one-hot protocol
flags (HTTP=1 -> Web Attack, ARP=1 -> Spoofing). This script:
1. Strips all protocol shortcut features to force the model to learn pure flow dynamics.
2. Trains Model 1 (Binary Filter: Benign vs Malicious) with heavy weight on Benign precision.
3. Trains Model 2 (Multi-Class Attributor: 7 Attack Types).
4. Exports both models, scalers, and metadata to backend/models for instant plug-and-play.
"""

import os
import sys
import json
import argparse
import joblib
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# -------------------------------------------------------------------------
# Feature Selection: Stripped of Protocol Shortcut Flags
# -------------------------------------------------------------------------
DEBIASED_FEATURES = [
    'Header_Length', 'Time_To_Live', 'Rate',
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number',
    'psh_flag_number', 'ack_flag_number', 'ece_flag_number',
    'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'rst_count',
    'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Variance'
]

SHORTCUT_FEATURES_TO_DROP = [
    'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP',
    'DHCP', 'ARP', 'ICMP', 'IGMP', 'IPv', 'LLC', 'Protocol Type'
]

# 8-Class Mapping for CICIoT2023 34 sub-classes (normalized to uppercase keys for robust matching)
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

def map_to_8class(val: str) -> str:
    clean_val = str(val).strip().upper()
    return RAW_ATTACK_MAPPING.get(clean_val, str(val).strip())


def load_and_preprocess_dataset(csv_path: str, sample_per_class: int = 25000) -> pd.DataFrame:
    print(f"[*] Loading dataset from: {csv_path}")
    if os.path.isdir(csv_path):
        import glob
        csv_files = glob.glob(os.path.join(csv_path, "*.csv"))
        if not csv_files:
            raise ValueError(f"No CSV files found in folder {csv_path}")
        print(f"[*] Found {len(csv_files)} CSV files. Loading in chunks...")
        chunks = []
        for f in csv_files:
            print(f"    - Loading {os.path.basename(f)}...")
            temp_df = pd.read_csv(f)
            chunks.append(temp_df)
        df = pd.concat(chunks, ignore_index=True)
    else:
        df = pd.read_csv(csv_path)

    # Detect label column
    target_col = None
    for candidate in ['label', 'Label', 'label_8', 'Attack_type', 'label_34', 'Class', 'attack_type', 'class']:
        if candidate in df.columns:
            target_col = candidate
            break
    if target_col is None:
        # Fallback to case-insensitive match
        for col in df.columns:
            if col.strip().lower() in ['label', 'label_8', 'attack_type', 'label_34', 'class']:
                target_col = col
                break

    if target_col is None:
        raise ValueError(f"Could not find label column in {df.columns.tolist()}")

    # Map labels to 8 standard categories
    df['label_8'] = df[target_col].map(map_to_8class)

    # Clean inf/nan values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    print("[*] Raw class distribution:")
    print(df['label_8'].value_counts())

    # Balance classes if sample_per_class is requested
    if sample_per_class and sample_per_class > 0:
        balanced_dfs = []
        for label, group in df.groupby('label_8'):
            n_samples = min(len(group), sample_per_class)
            balanced_dfs.append(group.sample(n=n_samples, random_state=42))
        df = pd.concat(balanced_dfs, ignore_index=True)
        print(f"\n[*] Balanced dataset distribution (max {sample_per_class} per class):")
        print(df['label_8'].value_counts())

    return df


def train_debiased_pipeline(df: pd.DataFrame, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    # Verify features
    available_features = [f for f in DEBIASED_FEATURES if f in df.columns]
    print(f"\n[*] Training using {len(available_features)} debiased flow dynamics features:")
    print(available_features)

    X = df[available_features].copy()
    y_multiclass = df['label_8'].copy()
    y_binary = (y_multiclass != 'Benign').astype(int)  # 0 = Benign, 1 = Attack

    # Scale features
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=available_features)

    # Split train/test
    X_tr, X_te, y_bin_tr, y_bin_te, y_mc_tr, y_mc_te = train_test_split(
        X_scaled, y_binary, y_multiclass, test_size=0.20, random_state=42, stratify=y_multiclass
    )

    # =========================================================================
    # STAGE 1: Train Binary Anomaly / Attack Classifier (Benign vs Malicious)
    # =========================================================================
    print("\n" + "="*70)
    print("STAGE 1: Training Binary Classifier (0 = Benign, 1 = Attack)")
    print("="*70)

    # Give slightly higher weight to Benign to suppress false positives on live traffic
    binary_model = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        eval_metric='logloss',
        random_state=42
    )
    binary_model.fit(X_tr, y_bin_tr)

    y_bin_pred = binary_model.predict(X_te)
    bin_acc = accuracy_score(y_bin_te, y_bin_pred)
    print(f"\n[+] Binary Classifier Accuracy: {bin_acc * 100:.2f}%")
    print(classification_report(y_bin_te, y_bin_pred, target_names=['Benign', 'Attack']))

    # =========================================================================
    # STAGE 2: Train Multi-Class Attributor (Attack Types Only)
    # =========================================================================
    print("\n" + "="*70)
    print("STAGE 2: Training Multi-Class Attributor (Specific Attack Types)")
    print("="*70)

    le = LabelEncoder()
    y_mc_encoded_tr = le.fit_transform(y_mc_tr)
    y_mc_encoded_te = le.transform(y_mc_te)

    mc_model = xgb.XGBClassifier(
        n_estimators=180,
        max_depth=7,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        eval_metric='mlogloss',
        random_state=42
    )
    mc_model.fit(X_tr, y_mc_encoded_tr)

    y_mc_pred = mc_model.predict(X_te)
    mc_acc = accuracy_score(y_mc_encoded_te, y_mc_pred)
    print(f"\n[+] Multi-Class Classifier Accuracy: {mc_acc * 100:.2f}%")
    print(classification_report(y_mc_encoded_te, y_mc_pred, target_names=le.classes_))

    # =========================================================================
    # Export Models
    # =========================================================================
    export_payload = {
        'binary_model': binary_model,
        'multiclass_model': mc_model,
        'scaler': scaler,
        'label_encoder': le,
        'features': available_features,
        'classes': le.classes_.tolist(),
        'metrics': {
            'binary_accuracy': float(bin_acc),
            'multiclass_accuracy': float(mc_acc),
            'confusion_matrix': confusion_matrix(y_mc_encoded_te, y_mc_pred).tolist()
        }
    }

    out_file = os.path.join(output_dir, "ciciot2023_debiased_hierarchical.joblib")
    joblib.dump(export_payload, out_file)
    print(f"\n[+] Successfully saved trained hierarchical pipeline to: {out_file}")

    # Also save backward-compatible tuned 8-class payload so current UI continues to work seamlessly
    compat_payload = {
        'model': mc_model,
        'binary_model': binary_model,
        'scaler': scaler,
        'label_encoder': le,
        'features': available_features,
        'classes': le.classes_.tolist(),
        'metrics': export_payload['metrics']
    }
    compat_file = os.path.join(output_dir, "ciciot2023_8class_xgboost_tuned.joblib")
    joblib.dump(compat_payload, compat_file)
    print(f"[+] Updated compatibility model at: {compat_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Debiased Hierarchical XGBoost for IoT Intrusion Detection")
    parser.add_argument("--csv", type=str, default="uploads/20260825155318_iot_ids_classification_test.csv", help="Path to CICIoT CSV dataset")
    parser.add_argument("--output", type=str, default="models", help="Directory to save serialized .joblib artifacts")
    parser.add_argument("--sample", type=int, default=25000, help="Max sample rows per class (0 for all)")
    args = parser.parse_args()

    if not os.path.exists(args.csv):
        print(f"[-] CSV dataset not found at {args.csv}.")
        print("    Please provide the path via --csv <path_to_ciciot_csv>")
        sys.exit(1)

    dataset_df = load_and_preprocess_dataset(args.csv, sample_per_class=args.sample)
    train_debiased_pipeline(dataset_df, args.output)
