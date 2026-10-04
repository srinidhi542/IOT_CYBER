# IoT Sentinel — Production ML Model Architecture & Performance Specifications

---

## 1. Primary Production Model: `ciciot2023_8class_xgboost_tuned.joblib`

- **Architecture:** Two-Stage Debiased Hierarchical Extreme Gradient Boosting (XGBoost)
- **Artifact Location:** `backend/models/ciciot2023_8class_xgboost_tuned.joblib`
- **Training Corpus:** **536,321 high-quality balanced samples** extracted from **all 63 merged CSV files (45,019,243 total rows)**
- **Test Holdout Set:** 107,265 unseen records (20% stratified test split)
- **Feature Schema:** **23 Pure Statistical & Temporal Flow Dynamics Features** (16 Protocol shortcut flags stripped for 0% bias)

```
                       Network Flow Telemetry (23 Features)
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

## 2. Model Performance & Classification Metrics

### Stage 1: Binary Anomaly Filter (Benign vs. Attack)
*Focuses on suppressing false alarms on legitimate connected IoT sensors.*
- **Overall Binary Accuracy:** **90.04%**
- **Benign Class Recall:** **96.00%**
- **Attack Class Precision:** **99.00%**
- **Test Support:** 20,000 Benign / 87,265 Attack

### Stage 2: Multi-Class Attributor (8 Classes)
- **Overall Multi-Class Accuracy:** **80.13%**
- **Macro Precision / Recall / F1:** **82.0% / 80.0% / 81.0%**

#### Per-Class Breakdown Table:
| Attack Category | Precision | Recall | F1-Score | Evaluation Test Support | Primary Signatures Detected |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Mirai** | **1.00** | **1.00** | **1.00** | 20,000 | Mirai-GREeth, Mirai-UDPplain, Mirai-GREip |
| **Spoofing** | **0.92** | **0.85** | **0.88** | 10,000 | MITM-ArpSpoofing, DNS_Spoofing |
| **DoS** | **0.75** | **0.90** | **0.82** | 20,000 | DoS-UDP, DoS-TCP, DoS-SYN, Slowloris |
| **Benign** | **0.85** | **0.75** | **0.80** | 20,000 | Legitimate IoT Telemetry |
| **DDoS** | **0.88** | **0.71** | **0.78** | 20,000 | DDoS-ICMP, DDoS-UDP, DDoS-SYN, DDoS-ACK |
| **Reconnaissance** | **0.66** | **0.61** | **0.63** | 10,000 | HostDiscovery, OSScan, PortScan, VulnScan |
| **Web Attack** | **0.45** | **0.59** | **0.51** | 4,760 | SQLi, XSS, CmdInjection, Uploading Attack |
| **Brute Force** | **0.29** | **0.57** | **0.38** | 2,505 | Dictionary SSH/Telnet Password Spraying |

---

## 3. Feature Selection: Debiased vs. Dropped

### 23 Trained Flow Features:
1. `Header_Length` — Total byte length of packet headers
2. `Time_To_Live` — TTL hop count
3. `Rate` — Packets per second transmission rate
4. `fin_flag_number` — FIN flag presence
5. `syn_flag_number` — SYN flag presence
6. `rst_flag_number` — RST reset flag presence
7. `psh_flag_number` — PSH push flag presence
8. `ack_flag_number` — ACK flag presence
9. `ece_flag_number` — ECE congestion flag
10. `cwr_flag_number` — CWR window reduced flag
11. `ack_count` — Accumulated ACK count
12. `syn_count` — Accumulated SYN count
13. `fin_count` — Accumulated FIN count
14. `rst_count` — Accumulated RST count
15. `Tot sum` — Total packet length summation
16. `Min` — Minimum packet size observed
17. `Max` — Maximum packet size observed
18. `AVG` — Average packet size across flow
19. `Std` — Standard deviation of packet sizes
20. `Tot size` — Aggregate byte size in flow window
21. `IAT` — Packet Inter-Arrival Time
22. `Number` — Flow packet count
23. `Variance` — Variance of packet length distribution

### 16 Dropped Shortcut Protocol Flags:
`HTTP`, `HTTPS`, `DNS`, `Telnet`, `SMTP`, `SSH`, `IRC`, `TCP`, `UDP`, `DHCP`, `ARP`, `ICMP`, `IGMP`, `IPv`, `LLC`, `Protocol Type`.

---

## 4. Unsupervised Secondary Model: Isolation Forest Anomaly Engine

- **Model Class:** `sklearn.ensemble.IsolationForest`
- **Location:** Integrated in `backend/app/ml/threat_engine/threat_engine.py`
- **Role:** **Zero-Day & Unseen Anomaly Detection**
- **Operation:**
  - Evaluates flow distance from standard multidimensional benign clusters ($0.0 \to 100.0$).
  - When $AnomalyScore > 82.0$ on an unclassified flow, it overrides the output to **`Unknown / Suspicious`** and triggers automated containment playbooks.

---

## 5. Explainability Engine: TreeSHAP Multi-Output Explainer

- **Model Class:** `shap.TreeExplainer`
- **Location:** Integrated in `backend/app/ml/predict_pipeline.py`
- **Functionality:** Calculates exact Shapley feature attribution values in real time for every classified flow and ranks the top $k$ feature contributors on the frontend **AI Explainability** view.
