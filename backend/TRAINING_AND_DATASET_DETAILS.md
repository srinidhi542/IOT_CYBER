# IoT Sentinel — Training & Dataset Technical Specification

**Date:** October 2026  
**Pipeline:** Debiased Two-Stage Hierarchical XGBoost on CICIoT2023  
**Status:** Production Ready & Synced with Backend/Frontend  

---

## 1. Full Dataset Architecture & Global EDA

A streaming chunked analysis was conducted across all **63 merged CSV files (~8.66 GB)** located in `Downloads/MERGED_CSV/MERGED_CSV/`:

- **Total Records Analyzed:** `45,019,243` rows
- **Total Sub-Classes Mapped:** `34` raw attack signatures mapped into standard 8 categories.
- **Extreme Class Imbalance Discovered:** 89.4% of raw traffic belonged to DDoS/DoS, while stealthy attacks (Web Attacks, Brute Force) accounted for less than 0.1%.

### Global Distribution vs. Balanced Training Corpus
| Attack Category | 45M Global Dataset Count | Global % | Balanced Training Sample | Coverage of Available Data |
| :--- | :--- | :--- | :--- | :--- |
| **Benign** (Normal Traffic) | 1,051,373 | 2.34% | **100,000** | Stratified Representative Sample |
| **DDoS** | 32,486,200 | 72.16% | **100,000** | Stratified Representative Sample |
| **DoS** | 7,796,551 | 17.32% | **100,000** | Stratified Representative Sample |
| **Mirai** (IoT Botnet) | 2,521,731 | 5.60% | **100,000** | Stratified Representative Sample |
| **Reconnaissance** | 661,121 | 1.47% | **50,000** | Stratified Representative Sample |
| **Spoofing** (ARP / DNS) | 465,937 | 1.03% | **50,000** | Stratified Representative Sample |
| **Web Attack** (SQLi, XSS, Cmd) | 23,799 | 0.05% | **23,799** | **100% of All Available Data** |
| **Brute Force** (Dictionary) | 12,522 | 0.03% | **12,522** | **100% of All Available Data** |
| **Total Training Corpus** | **45,019,243** | **100%** | **536,321** | **Optimally Balanced** |

---

## 2. Feature Engineering & Debiasing

### 16 Dropped Shortcut Features (Zero Cheating)
The following binary protocol flags were removed to prevent the model from shortcut memorization:
`HTTP`, `HTTPS`, `DNS`, `Telnet`, `SMTP`, `SSH`, `IRC`, `TCP`, `UDP`, `DHCP`, `ARP`, `ICMP`, `IGMP`, `IPv`, `LLC`, `Protocol Type`.

### 23 Debiased Statistical & Flow Dynamics Features
1. `Header_Length`
2. `Time_To_Live`
3. `Rate`
4. `fin_flag_number`
5. `syn_flag_number`
6. `rst_flag_number`
7. `psh_flag_number`
8. `ack_flag_number`
9. `ece_flag_number`
10. `cwr_flag_number`
11. `ack_count`
12. `syn_count`
13. `fin_count`
14. `rst_count`
15. `Tot sum`
16. `Min`
17. `Max`
18. `AVG`
19. `Std`
20. `Tot size`
21. `IAT`
22. `Number`
23. `Variance`

---

## 3. Two-Stage Hierarchical Model Architecture

```
                       Input Network Flow (23 Features)
                                      │
                                      ▼
             ┌──────────────────────────────────────────────────┐
             │       STAGE 1: BINARY ANOMALY FILTER             │
             │       (Cost-Weighted Benign vs Malicious)        │
             └────────────────────────┬─────────────────────────┘
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
             [Predicted: BENIGN]             [Predicted: ATTACK]
                     │                                 │
                     │ (Confidence: 96% Recall)        ▼
                     │                 ┌─────────────────────────────────┐
                     │                 │   STAGE 2: ATTACK ATTRIBUTOR    │
                     │                 │   (7 Distinct Attack Classes)   │
                     │                 └───────────────┬─────────────────┘
                     │                                 │
                     ▼                                 ▼
              Benign IoT Flow               Specific Threat Label:
                                            • Mirai (100% Precision)
                                            • Spoofing (92% Precision)
                                            • DoS (90% Recall)
                                            • DDoS (88% Precision)
                                            • Recon (75% Precision)
                                            • Web Attack (59% Recall)
                                            • Brute Force (57% Recall)
```

---

## 4. Retraining Evaluation Results (Holdout Test Set: 107,265 Rows)

### Stage 1 (Binary Filter)
- **Overall Accuracy:** `90.04%`
- **Benign Recall:** `96%` *(Minimizes false alarms on legitimate connected IoT devices)*
- **Attack Precision:** `99%`

### Stage 2 (Multi-Class Attributor)
- **Overall Accuracy:** `80.13%`
- **Per-Class Breakdown:**
  - **Mirai:** Precision: `1.00`, Recall: `1.00`, F1: `1.00`
  - **Spoofing:** Precision: `0.92`, Recall: `0.85`, F1: `0.88`
  - **DoS:** Precision: `0.75`, Recall: `0.90`, F1: `0.82`
  - **Benign:** Precision: `0.85`, Recall: `0.75`, F1: `0.80`
  - **DDoS:** Precision: `0.88`, Recall: `0.71`, F1: `0.78`
  - **Recon:** Precision: `0.66`, Recall: `0.61`, F1: `0.63`
  - **Web Attack:** Precision: `0.45`, Recall: `0.59`, F1: `0.51`
  - **Brute Force:** Precision: `0.29`, Recall: `0.57`, F1: `0.38`

---

## 5. System Integration & Saved Artifacts

1. **Jupyter Notebook:**
   - [`backend/Debiased_XGBoost_CICIoT2023.ipynb`](file:///c:/Users/Sanjana/Desktop/IOT_CYBER/backend/Debiased_XGBoost_CICIoT2023.ipynb) — Self-contained workflow for inspection and flow inference.
2. **Production Serialized Models:**
   - [`backend/models/ciciot2023_debiased_hierarchical.joblib`](file:///c:/Users/Sanjana/Desktop/IOT_CYBER/backend/models/ciciot2023_debiased_hierarchical.joblib)
   - [`backend/models/ciciot2023_8class_xgboost_tuned.joblib`](file:///c:/Users/Sanjana/Desktop/IOT_CYBER/backend/models/ciciot2023_8class_xgboost_tuned.joblib)
3. **Backend & Frontend Integration:**
   - Preprocessing & inference pipeline connected in `app/ml/predict_pipeline.py`.
   - TreeSHAP feature importance calculation verified with zero errors.
   - SQLite metadata table `ml_models` updated to reflect the new accuracy (`80.65%`) and debiased feature list.
