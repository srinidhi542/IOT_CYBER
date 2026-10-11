# IoT Sentinel — Training & Dataset Technical Specification

**Date:** October 2026  
**Pipeline:** High-Performance Hierarchical Two-Stage XGBoost on CICIoT2023  
**Status:** Production Ready & Connected to API  

---

## 1. Dataset Overview & Global Exploration (EDA)

The entire dataset comprising **63 merged CSV files (~8.66 GB)** was comprehensively analyzed using streaming chunked processors.

- **Total Network Records Analyzed:** `45,019,243` rows
- **Total Raw Sub-Classes:** `34` attack types + `BenignTraffic`
- **Mapped 8 Standard Classes:** `DDoS`, `DoS`, `Mirai`, `Benign`, `Recon`, `Spoofing`, `Web Attack`, `Brute Force`

### Global Class Imbalance Analysis
| Class | 45M Dataset Count | Percentage | Training Stratified Sample | Coverage Rate |
| :--- | :--- | :--- | :--- | :--- |
| **DDoS** | 32,486,200 | 72.16% | 100,000 | Representative Subsample |
| **DoS** | 7,796,551 | 17.32% | 100,000 | Representative Subsample |
| **Mirai** | 2,521,731 | 5.60% | 100,000 | Representative Subsample |
| **Benign** | 1,051,373 | 2.34% | 100,000 | Representative Subsample |
| **Recon** | 661,121 | 1.47% | 50,000 | Representative Subsample |
| **Spoofing** | 465,937 | 1.03% | 50,000 | Representative Subsample |
| **Web Attack** | 23,799 | 0.05% | **23,799** | **100% of All Available Data** |
| **Brute Force** | 12,522 | 0.03% | **12,522** | **100% of All Available Data** |
| **Total Corpus** | **45,019,243** | **100%** | **536,321** | **Optimally Balanced Corpus** |

---

## 2. Feature Engineering & Debiasing Strategy

### Protocol Shortcut Removal
To prevent models from memorizing static protocol flags (e.g. associating HTTP with Web Attack, ARP with Spoofing, or DNS with Spoofing), the following 16 shortcut features were explicitly **dropped**:
`HTTP`, `HTTPS`, `DNS`, `Telnet`, `SMTP`, `SSH`, `IRC`, `TCP`, `UDP`, `DHCP`, `ARP`, `ICMP`, `IGMP`, `IPv`, `LLC`, `Protocol Type`.

### 23 Debiased Flow Dynamics Features
The model trains exclusively on statistical and temporal dynamics of network flows:
1. `Rate` (18.42% Gain)
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

## 3. Two-Stage Hierarchical Architecture

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

## 4. Evaluation Performance Metrics (Unseen Test Set: 107,265 Rows)

### Stage 1 (Binary Filter)
- **Accuracy:** `98.85%`
- **Benign Recall:** `98.90%` (Minimizes false alarms on legitimate IoT operations)
- **Attack Precision:** `99.80%`

### Stage 2 (Multi-Class Attributor)
- **Overall Accuracy:** `96.29%`
- **5-Fold Cross-Validation Mean:** `95.92% ± 0.31%`
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

## 5. Artifacts and Production Endpoints

1. **Serialized Pipeline Artifacts:**
   - [`backend/models/ciciot2023_debiased_hierarchical.joblib`](file:///c:/Users/abhig/OneDrive/Desktop/IOT_SHIELD/IOT_CYBER/backend/models/ciciot2023_debiased_hierarchical.joblib)
   - [`backend/models/ciciot2023_8class_xgboost_tuned.joblib`](file:///c:/Users/abhig/OneDrive/Desktop/IOT_SHIELD/IOT_CYBER/backend/models/ciciot2023_8class_xgboost_tuned.joblib)
2. **Jupyter Notebook:**
   - [`backend/Debiased_XGBoost_CICIoT2023.ipynb`](file:///c:/Users/abhig/OneDrive/Desktop/IOT_SHIELD/IOT_CYBER/backend/Debiased_XGBoost_CICIoT2023.ipynb)
3. **Inference & Explainability:**
   - Backend `predict_tuned()` and `explain_prediction()` with TreeSHAP feature explanations.
   - Connected directly with FastAPI `/api/detection/run`, `/api/capture/stop`, and `/api/ml/model`.
