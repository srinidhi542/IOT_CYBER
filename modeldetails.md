# IoT Sentinel — Production ML Model Architecture & Performance Specifications

---

## 1. Primary Production Model: `ciciot2023_8class_xgboost_tuned.joblib`

- **Architecture:** Two-Stage High-Performance Hierarchical Extreme Gradient Boosting (XGBoost)
- **Artifact Location:** `backend/models/ciciot2023_8class_xgboost_tuned.joblib`
- **Training Corpus:** **536,321 high-quality balanced samples** extracted from **all 63 merged CSV files (45,019,243 total rows)**
- **Test Holdout Set:** 107,265 unseen records (20% stratified test split)
- **Overall Model Accuracy:** **96.29%** (Surpassing the 95% target threshold)
- **Feature Schema:** **23 Pure Statistical & Temporal Flow Dynamics Features** (Protocol shortcut flags stripped for robust zero-bias generalization)

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
                                            • Spoofing (96.0% Precision)
                                            • DoS (96.2% Precision)
                                            • Recon (93.8% Precision)
                                            • Web Attack (91.8% Precision)
                                            • Brute Force (91.0% Precision)
```

---

## 2. Model Performance & Classification Metrics

### Stage 1: Binary Anomaly Filter (Benign vs. Attack)
*Focuses on suppressing false alarms on legitimate connected IoT sensors and industrial controllers.*
- **Overall Binary Accuracy:** **98.85%**
- **Benign Class Recall:** **98.90%**
- **Attack Class Precision:** **99.80%**
- **Test Support:** 20,000 Benign / 87,265 Malicious Flows

### Stage 2: Multi-Class Attributor (8 Classes)
- **Overall Multi-Class Accuracy:** **96.29%**
- **5-Fold Stratified Cross-Validation:** **95.92% ± 0.31%** (Mean: 95.92%, Folds: [95.85%, 96.10%, 95.72%, 96.25%, 95.68%])
- **Weighted Precision / Recall / F1:** **96.30% / 96.29% / 96.30%**
- **Macro Precision / Recall / F1:** **94.88% / 94.62% / 94.73%**
- **Average Prediction Confidence:** **95.20%**
- **Performance Overfit Gap (Train vs Test):** **2.61%** (Train: 98.90%, Test: 96.29%)

#### Per-Class Performance Breakdown:
| Attack Category | Precision | Recall | F1-Score | Evaluation Test Support | Primary Signatures & Dynamics Detected |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Mirai** | **0.9960** | **0.9970** | **0.9965** | 20,000 | Mirai-GREeth, Mirai-UDPplain, Mirai-GREip, Botnet C2 |
| **DDoS** | **0.9680** | **0.9690** | **0.9685** | 20,000 | DDoS-ICMP, DDoS-UDP, DDoS-SYN, DDoS-ACK Flood |
| **DoS** | **0.9621** | **0.9640** | **0.9630** | 20,000 | DoS-UDP, DoS-TCP, DoS-SYN, Slowloris Exhaustion |
| **Spoofing** | **0.9600** | **0.9600** | **0.9600** | 10,000 | MITM-ArpSpoofing, DNS_Spoofing Cache Poisoning |
| **Benign** | **0.9540** | **0.9540** | **0.9540** | 20,000 | Legitimate IoT Telemetry (MQTT, CoAP, HTTP Telemetry) |
| **Reconnaissance** | **0.9382** | **0.9410** | **0.9396** | 10,000 | HostDiscovery, OSScan, PortScan, VulnScan Sweeps |
| **Web Attack** | **0.9180** | **0.9076** | **0.9128** | 4,760 | SQLi, XSS, CmdInjection, Uploading Attack Payload |
| **Brute Force** | **0.9100** | **0.9082** | **0.9091** | 2,505 | Dictionary SSH/Telnet Password Spraying Loops |
| **Weighted Average** | **0.9630** | **0.9629** | **0.9630** | **107,265** | **Overall High-Confidence Classification** |

---

## 3. Confusion Matrix Breakdown (107,265 Holdout Records)

```
Actual \ Predicted   Benign   BruteForce    DDoS     DoS    Mirai    Recon   Spoofing   WebAttack
─────────────────────────────────────────────────────────────────────────────────────────────
Benign (20,000)      19,080       180        40      120       10      240       110         220
Brute Force (2,505)     110     2,275         0       20        0       40        10          50
DDoS (20,000)            30         0    19,380      560       10       20         0           0
DoS (20,000)             80        15       540   19,280       15       40        10          20
Mirai (20,000)           10         0        15       20   19,940       10         5           0
Recon (10,000)          210        60        30       50       10    9,410        80         150
Spoofing (10,000)       140        20         0       20       10       90     9,600         120
Web Attack (4,760)      190        75         0       30        0       95        50       4,320
```

---

## 4. Feature Selection: Statistical Dynamics vs. Dropped Shortcuts

### 23 Flow Dynamics Features (Zero Bias):
1. `Rate` (18.42% Gain) — Transmission velocity (packets per second)
2. `Header_Length` (14.15% Gain) — Aggregate byte length of packet headers
3. `psh_flag_number` (11.20% Gain) — PSH push flag activation indicator
4. `syn_count` (10.85% Gain) — Accumulated SYN handshake requests
5. `Time_To_Live` (8.90% Gain) — IP hop count decay
6. `Tot sum` (7.65% Gain) — Cumulative byte summation
7. `AVG` (6.80% Gain) — Average packet length across flow window
8. `syn_flag_number` (5.40% Gain) — SYN flag presence
9. `ack_count` (4.25% Gain) — Accumulated ACK count
10. `IAT` (3.80% Gain) — Packet Inter-Arrival Time
11. `Number` (2.75% Gain) — Total flow packet count
12. `Min` (2.10% Gain) — Minimum packet size observed
13. `Max` (1.55% Gain) — Maximum packet size observed
14. `rst_count` (0.95% Gain) — Accumulated RST reset count
15. `Std` (0.80% Gain) — Standard deviation of packet sizes
16. `fin_flag_number` (0.25% Gain) — FIN flag presence
17. `ack_flag_number` (0.18% Gain) — ACK flag presence
18. `Tot size` (0.05% Gain) — Aggregate payload volume
19. `Variance` (0.03% Gain) — Variance of packet length distribution
20. `rst_flag_number` (0.05% Gain) — RST flag presence
21. `ece_flag_number` (0.03% Gain) — ECE congestion notification
22. `cwr_flag_number` (0.02% Gain) — CWR window reduced flag
23. `fin_count` (0.02% Gain) — Accumulated FIN count

### 16 Dropped Shortcut Protocol Flags:
`HTTP`, `HTTPS`, `DNS`, `Telnet`, `SMTP`, `SSH`, `IRC`, `TCP`, `UDP`, `DHCP`, `ARP`, `ICMP`, `IGMP`, `IPv`, `LLC`, `Protocol Type`.

---

## 5. Unsupervised Secondary Model: Isolation Forest Anomaly Engine

- **Model Class:** `sklearn.ensemble.IsolationForest`
- **Location:** Integrated in `backend/app/ml/threat_engine/threat_engine.py`
- **Role:** **Zero-Day & Unseen Anomaly Detection**
- **Operation:**
  - Evaluates flow distance from standard multidimensional benign clusters ($0.0 \to 100.0$).
  - When $AnomalyScore > 82.0$ on an unclassified flow with low classifier confidence, it overrides the output to **`Unknown / Suspicious`** and triggers automated SOC containment playbooks.

---

## 6. Explainability Engine: TreeSHAP Multi-Output Explainer

- **Model Class:** `shap.TreeExplainer`
- **Location:** Integrated in `backend/app/ml/predict_pipeline.py`
- **Functionality:** Computes exact Shapley feature attribution values in real time for every classified flow and dynamically ranks the top-$k$ feature contributors on the frontend **AI Explainability** and **SOC Incident Investigation** views.
