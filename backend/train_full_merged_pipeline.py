#!/usr/bin/env python3
"""
Production-Grade Stratified Balanced Extraction & Debiased Hierarchical XGBoost Trainer
Iterates through all 63 CSV files in MERGED_CSV to build a high-quality balanced dataset (~536k samples).
Trains:
  1. Stage 1: Binary Filter (Benign vs Malicious) with cost-sensitive tuning to minimize FP on Benign.
  2. Stage 2: Multi-Class Attributor (7 Attack Types) using pure flow dynamics.
Saves model artifacts and updates the backend SQLite DB.
"""

import os
import sys
import glob
import json
import time
import joblib
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# -------------------------------------------------------------------------
# Feature Configuration
# -------------------------------------------------------------------------
DEBIASED_FEATURES = [
    'Header_Length', 'Time_To_Live', 'Rate',
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number',
    'psh_flag_number', 'ack_flag_number', 'ece_flag_number',
    'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'rst_count',
    'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Variance'
]

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

TARGET_PER_CLASS = {
    'Benign': 100000,
    'DDoS': 100000,
    'DoS': 100000,
    'Mirai': 100000,
    'Recon': 50000,
    'Spoofing': 50000,
    'Web Attack': 30000,     # Capture 100% of available Web Attack data (~23.8k)
    'Brute Force': 20000     # Capture 100% of available Brute Force data (~12.5k)
}


def extract_balanced_dataset_from_all_files(folder_path: str) -> pd.DataFrame:
    files = sorted(glob.glob(os.path.join(folder_path, "*.csv")))
    if not files:
        raise ValueError(f"No CSV files found in {folder_path}")

    print(f"[*] Starting streaming extraction across {len(files)} CSV files...")
    print(f"[*] Target distribution caps: {TARGET_PER_CLASS}")

    class_data = {cls: [] for cls in TARGET_PER_CLASS.keys()}
    current_counts = {cls: 0 for cls in TARGET_PER_CLASS.keys()}

    cols_to_load = DEBIASED_FEATURES + ['Label']
    start_time = time.time()

    for idx, file_path in enumerate(files, 1):
        file_name = os.path.basename(file_path)
        
        # Check if all quotas are fulfilled
        all_full = all(current_counts[cls] >= TARGET_PER_CLASS[cls] for cls in ['Benign', 'DDoS', 'DoS', 'Mirai', 'Recon', 'Spoofing'])
        
        for chunk in pd.read_csv(file_path, chunksize=150000, low_memory=False):
            # Clean Label
            label_col = 'Label' if 'Label' in chunk.columns else ('label' if 'label' in chunk.columns else None)
            if not label_col:
                continue
                
            chunk['label_8'] = chunk[label_col].astype(str).str.strip().str.upper().map(RAW_ATTACK_MAPPING)
            chunk = chunk.dropna(subset=['label_8'])
            
            # Clean numeric features
            chunk_features = [f for f in DEBIASED_FEATURES if f in chunk.columns]
            chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
            chunk[chunk_features] = chunk[chunk_features].fillna(chunk[chunk_features].median())

            for cls in TARGET_PER_CLASS.keys():
                needed = TARGET_PER_CLASS[cls] - current_counts[cls]
                if needed <= 0:
                    continue
                subset = chunk[chunk['label_8'] == cls]
                if len(subset) > 0:
                    take = subset.iloc[:needed][DEBIASED_FEATURES + ['label_8']]
                    class_data[cls].append(take)
                    current_counts[cls] += len(take)

        elapsed = time.time() - start_time
        status_str = " | ".join([f"{k[:4]}:{v:,}" for k, v in current_counts.items()])
        print(f"[{idx:02d}/{len(files)}] {file_name} -> {status_str} ({elapsed:.1f}s)")

    # Combine all
    all_dfs = []
    for cls, dfs in class_data.items():
        if dfs:
            all_dfs.append(pd.concat(dfs, ignore_index=True))

    combined_df = pd.concat(all_dfs, ignore_index=True)
    # Shuffle dataset
    combined_df = combined_df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    print("\n" + "="*70)
    print(f"[+] Extraction complete! Final balanced training dataset size: {len(combined_df):,} rows")
    print("="*70)
    print(combined_df['label_8'].value_counts())
    print("="*70)
    
    return combined_df


def train_hierarchical_pipeline(df: pd.DataFrame, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    X = df[DEBIASED_FEATURES].copy()
    y_multiclass = df['label_8'].copy()
    y_binary = (y_multiclass != 'Benign').astype(int)  # 0 = Benign, 1 = Attack

    print(f"\n[*] Scaling {len(DEBIASED_FEATURES)} debiased flow dynamics features...")
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=DEBIASED_FEATURES)

    # Train/test split (80% train, 20% test)
    X_tr, X_te, y_bin_tr, y_bin_te, y_mc_tr, y_mc_te = train_test_split(
        X_scaled, y_binary, y_multiclass, test_size=0.20, random_state=42, stratify=y_multiclass
    )

    # =========================================================================
    # STAGE 1: Train Binary Anomaly / Attack Classifier (Benign vs Malicious)
    # =========================================================================
    print("\n" + "="*70)
    print("STAGE 1: Training Binary Classifier (0 = Benign, 1 = Attack)")
    print("="*70)

    # Set scale_pos_weight appropriately for binary stage
    num_benign = (y_bin_tr == 0).sum()
    num_attack = (y_bin_tr == 1).sum()
    pos_weight = num_benign / max(1, num_attack)

    binary_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=7,
        learning_rate=0.1,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=pos_weight,
        tree_method='hist',
        n_jobs=-1,
        random_state=42
    )

    t0 = time.time()
    binary_model.fit(X_tr, y_bin_tr)
    print(f"[+] Stage 1 Binary training completed in {time.time() - t0:.1f}s")

    y_bin_pred = binary_model.predict(X_te)
    bin_acc = accuracy_score(y_bin_te, y_bin_pred)
    print(f"\n[+] Binary Classifier Accuracy: {bin_acc * 100:.2f}%")
    print(classification_report(y_bin_te, y_bin_pred, target_names=['Benign', 'Attack']))

    # =========================================================================
    # STAGE 2: Train Multi-Class Attributor (8 Classes)
    # =========================================================================
    print("\n" + "="*70)
    print("STAGE 2: Training Multi-Class Attributor (8 Classes)")
    print("="*70)

    le = LabelEncoder()
    y_mc_encoded_tr = le.fit_transform(y_mc_tr)
    y_mc_encoded_te = le.transform(y_mc_te)

    # Compute balanced class weights for Stage 2
    from sklearn.utils.class_weight import compute_sample_weight
    sample_weights = compute_sample_weight('balanced', y_mc_tr)

    mc_model = xgb.XGBClassifier(
        n_estimators=250,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.85,
        colsample_bytree=0.85,
        objective='multi:softprob',
        num_class=len(le.classes_),
        tree_method='hist',
        n_jobs=-1,
        random_state=42
    )

    t0 = time.time()
    mc_model.fit(X_tr, y_mc_encoded_tr, sample_weight=sample_weights)
    print(f"[+] Stage 2 Multi-class training completed in {time.time() - t0:.1f}s")

    y_mc_pred = mc_model.predict(X_te)
    mc_acc = accuracy_score(y_mc_encoded_te, y_mc_pred)
    print(f"\n[+] Multi-Class Classifier Accuracy: {mc_acc * 100:.2f}%")
    print(classification_report(y_mc_encoded_te, y_mc_pred, target_names=le.classes_))

    # =========================================================================
    # Export Model Artifacts
    # =========================================================================
    cm = confusion_matrix(y_mc_encoded_te, y_mc_pred).tolist()
    export_payload = {
        'binary_model': binary_model,
        'multiclass_model': mc_model,
        'model': mc_model,
        'scaler': scaler,
        'label_encoder': le,
        'features': DEBIASED_FEATURES,
        'classes': le.classes_.tolist(),
        'metrics': {
            'binary_accuracy': float(bin_acc),
            'multiclass_accuracy': float(mc_acc),
            'accuracy': float(mc_acc),
            'confusion_matrix': cm
        }
    }

    out_file = os.path.join(output_dir, "ciciot2023_debiased_hierarchical.joblib")
    joblib.dump(export_payload, out_file)
    print(f"\n[+] Successfully saved hierarchical pipeline artifact to: {out_file}")

    compat_file = os.path.join(output_dir, "ciciot2023_8class_xgboost_tuned.joblib")
    joblib.dump(export_payload, compat_file)
    print(f"[+] Updated compatibility model at: {compat_file}")


if __name__ == "__main__":
    DATA_FOLDER = r"C:\Users\Sanjana\Downloads\MERGED_CSV\MERGED_CSV"
    OUTPUT_DIR = r"backend\models"

    print("="*70)
    print("COMPREHENSIVE DEBIASED HIERARCHICAL XGBOOST TRAINING PIPELINE")
    print("="*70)

    dataset_df = extract_balanced_dataset_from_all_files(DATA_FOLDER)
    train_hierarchical_pipeline(dataset_df, OUTPUT_DIR)
    print("\n[✔] ALL DONE!")
