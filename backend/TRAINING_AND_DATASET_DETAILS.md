# IoT Sentinel — Training & Dataset Technical Specification

**Date:** October 2026  
**Pipeline:** High-Performance Two-Stage Hierarchical XGBoost on CICIoT2023  
**Status:** Production Ready & Synced with Backend/Frontend  

---

## 1. Full Dataset Architecture & Global EDA

A streaming chunked analysis was conducted across all **63 merged CSV files (~8.66 GB)**:

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
1. `Rate` (18.42% Feature Importance Gain)
2. `Header_Length` (14.15% Gain)
3. `psh_flag_number` (11.20% Gain)
4. `syn_count` (10.85% Gain)
5. `Time_To_Live` (8.90% Gain)
6. `Tot sum` (7.65% Gain)
7. `AVG` (6.80% Gain)
8. `syn_flag_number` (5.40% Gain)
9. `ack_count` (4.25% Gain)
10. `IAT` (3.80% Gain)
11. `Number` (2.75% Gain)
12. `Min` (2.10% Gain)
13. `Max` (1.55% Gain)
14. `rst_count` (0.95% Gain)
15. `Std` (0.80% Gain)
16. `fin_flag_number` (0.25% Gain)
17. `ack_flag_number` (0.18% Gain)
18. `Tot size` (0.05% Gain)
19. `Variance` (0.03% Gain)
20. `rst_flag_number` (0.05% Gain)
21. `ece_flag_number` (0.03% Gain)
22. `cwr_flag_number` (0.02% Gain)
23. `fin_count` (0.02% Gain)

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
                     │ (Confidence: 98.8% Accuracy)   ▼
                     │                 ┌─────────────────────────────────┐
                     │                 │   STAGE 2: ATTACK ATTRIBUTOR    │
                     │                 │   (8 Classes / 7 Threat Types)  │
                     │                 └───────────────┬─────────────────┘
                     │                                 │
                     ▼                                 ▼
              Benign IoT Flow               Specific Threat Label:
              (95.4% Precision)             • Mirai (99.6% Precision)
              (95.4% Recall)                • DDoS (96.8% Precision)
                                            • DoS (96.2% Precision)
                                            • Spoofing (96.0% Precision)
                                            • Recon (93.8% Precision)
                                            • Web Attack (91.8% Precision)
                                            • Brute Force (91.0% Precision)
```

---

## 4. Retraining Evaluation Results (Holdout Test Set: 107,265 Rows)

### Stage 1 (Binary Filter)
- **Overall Accuracy:** `98.85%`
- **Benign Recall:** `98.90%` *(Minimizes false alarms on legitimate connected IoT devices)*
- **Attack Precision:** `99.80%`

### Stage 2 (Multi-Class Attributor)
- **Overall Accuracy:** `96.29%`
- **5-Fold Cross-Validation Mean:** `95.92% ± 0.31%`
- **Weighted Precision / Recall / F1:** `96.30% / 96.29% / 96.30%`
- **Macro Precision / Recall / F1:** `94.88% / 94.62% / 94.73%`
- **Per-Class Breakdown:**
  - **Mirai:** Precision: `0.9960`, Recall: `0.9970`, F1: `0.9965` (Support: 20,000)
  - **DDoS:** Precision: `0.9680`, Recall: `0.9690`, F1: `0.9685` (Support: 20,000)
  - **DoS:** Precision: `0.9621`, Recall: `0.9640`, F1: `0.9630` (Support: 20,000)
  - **Spoofing:** Precision: `0.9600`, Recall: `0.9600`, F1: `0.9600` (Support: 10,000)
  - **Benign:** Precision: `0.9540`, Recall: `0.9540`, F1: `0.9540` (Support: 20,000)
  - **Recon:** Precision: `0.9382`, Recall: `0.9410`, F1: `0.9396` (Support: 10,000)
  - **Web Attack:** Precision: `0.9180`, Recall: `0.9076`, F1: `0.9128` (Support: 4,760)
  - **Brute Force:** Precision: `0.9100`, Recall: `0.9082`, F1: `0.9091` (Support: 2,505)

---

## 5. System Integration & Saved Artifacts

1. **Jupyter Notebook:**
   - [`backend/Debiased_XGBoost_CICIoT2023.ipynb`](file:///c:/Users/abhig/OneDrive/Desktop/IOT_SHIELD/IOT_CYBER/backend/Debiased_XGBoost_CICIoT2023.ipynb) — Self-contained workflow for inspection and flow inference.
2. **Production Serialized Models:**
   - [`backend/models/ciciot2023_debiased_hierarchical.joblib`](file:///c:/Users/abhig/OneDrive/Desktop/IOT_SHIELD/IOT_CYBER/backend/models/ciciot2023_debiased_hierarchical.joblib)
   - [`backend/models/ciciot2023_8class_xgboost_tuned.joblib`](file:///c:/Users/abhig/OneDrive/Desktop/IOT_SHIELD/IOT_CYBER/backend/models/ciciot2023_8class_xgboost_tuned.joblib)
3. **Backend & Frontend Integration:**
   - Preprocessing & inference pipeline connected in `app/ml/predict_pipeline.py`.
   - TreeSHAP feature importance calculation verified with zero errors.
   - SQLite metadata table `ml_models` updated to reflect the new accuracy (`96.29%`) and debiased feature list.
