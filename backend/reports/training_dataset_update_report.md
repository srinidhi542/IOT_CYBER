# IoT Sentinel — Training & Dataset Technical Specification

**Date:** October 2026  
**Pipeline:** Debiased Hierarchical Two-Stage XGBoost on CICIoT2023  
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

## 4. Evaluation Performance Metrics (Unseen Test Set: 107,265 Rows)

### Stage 1 (Binary Filter)
- **Accuracy:** `90.04%`
- **Benign Recall:** `96%` (Minimizes false alarms on legitimate IoT operations)
- **Attack Precision:** `99%`

### Stage 2 (Multi-Class Attributor)
- **Accuracy:** `80.13%`
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

## 5. Artifacts and Production Endpoints

1. **Serialized Pipeline Artifacts:**
   - [`backend/models/ciciot2023_debiased_hierarchical.joblib`](file:///c:/Users/Sanjana/Desktop/IOT_CYBER/backend/models/ciciot2023_debiased_hierarchical.joblib)
   - [`backend/models/ciciot2023_8class_xgboost_tuned.joblib`](file:///c:/Users/Sanjana/Desktop/IOT_CYBER/backend/models/ciciot2023_8class_xgboost_tuned.joblib)
2. **Jupyter Notebook:**
   - [`backend/Debiased_XGBoost_CICIoT2023.ipynb`](file:///c:/Users/Sanjana/Desktop/IOT_CYBER/backend/Debiased_XGBoost_CICIoT2023.ipynb)
3. **Inference & Explainability:**
   - Backend `predict_tuned()` and `explain_prediction()` with TreeSHAP feature explanations.
   - Connected directly with FastAPI `/api/detection/run`, `/api/capture/stop`, and `/api/ml/model`.
