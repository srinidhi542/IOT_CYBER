# IoT Sentinel — Intelligent IoT Intrusion Detection & Threat Analysis Platform

IoT Sentinel is a professional, enterprise-style web application for detecting and classifying malicious network traffic targeting Internet of Things (IoT) devices using machine learning. Designed for network security engineers and SOC analysts, it ingests arbitrary CSV logs, preprocesses them, executes XGBoost / Random Forest classification, identifies threat severities, explains predictive factors, proposes mitigation plans, and generates PDF assessment reports.

---

## 1. Project Features
* **CSV Telemetry Upload & Inspection**: Auto-scan uploaded CSVs for columns, missing data, duplications, and class counts.
* **Automated Data Preprocessing**: Dynamically handle null, infinite, and non-numeric values, isolate identifiers, map categorical fields, and perform stratified train-test splitting.
* **Dual-Model ML Pipeline**: Train an **XGBoost Classifier** with automatic fallback to **Random Forest** if XGBoost dependencies are missing.
* **Evaluation Diagnostics**: Inspect confusion matrices (via a custom heatmap), per-class classification reports (Precision, Recall, F1, Support), and global feature importance.
* **Rule-Based Threat Severity Engine**: Classify anomalies into Low, Medium, High, and Critical severities based on predicted category and confidence thresholds.
* **Record-Level Explainability**: Inspect exactly *why* a record was flagged by comparing its features to a computed benign baseline.
* **Response Recommendations**: Map incidents to mitigation strategies (e.g., telnet block, network isolation).
* **PDF Security Reports**: Export executive assessments summarizing audit runs, key findings, and recommendations.
* **Enterprise SOC UI**: Sleek, responsive, developer-style dark interface using Tailwind CSS and Recharts.

---

## 2. Tech Stack & Architecture

### Backend Core
* **Python 3.10+ / FastAPI**: Clean, high-performance web API with type hints.
* **SQLAlchemy & SQLite**: Structured schema persistence, allowing easy migration to PostgreSQL.
* **pandas & NumPy**: Advanced data engineering, cleanup, and statistics.
* **scikit-learn & joblib**: Data scaling, encoding, metric evaluations, and model serialization.
* **XGBoost**: Gradient boosted decision trees for tabular classification.
* **ReportLab**: Programmatic PDF report rendering.

### Frontend Client
* **React 18 & TypeScript**: Strong-typed component design.
* **Vite**: Rapid, optimized build toolchain.
* **Tailwind CSS**: Strict custom design tokens for a premium dark SOC look.
* **Recharts**: Responsive charting for telemetry metrics.
* **Lucide React**: Vector cybersecurity and developer iconography.

---

## 3. Pipeline Ingestion Architecture

```
Data Source
   │
   ├── CSV Dataset (Currently Implemented)
   │
   ├── Future: ESP32 WiFi Ingestion
   │
   ├── Future: Bluetooth BLE GATT Scanning
   │
   └── Future: MQTT IoT Gateway Broker
          ↓
     Data Ingestion Layer (Validation & Cleansing)
          ↓
     Preprocessing (Standard Scaler / Label Encoder)
          ↓
     ML Detection (XGBoost / Random Forest Inference)
          ↓
     Threat Analysis (Severity & Explainability)
          ↓
     Response Recommendation (Mitigation Script Mapping)
          ↓
     Security Assessment Report (Structured PDF / JSON Export)
```

---

## 4. Dataset Format & Sample Data
The platform is designed to work with arbitrary tabular cybersecurity files (e.g. CIC IoT datasets). It automatically detects numerical, categorical, and target label columns.

A script generating a 5,000-row synthetic network file is included at `backend/app/sample_data/generate_data.py` containing typical network features:
* `Flow_Duration` (Microseconds)
* `Total_Fwd_Packets`, `Total_Backward_Packets`
* `Total_Length_of_Fwd_Packets`, `Total_Length_of_Bwd_Packets`
* `Flow_Bytes_s`, `Flow_Packets_s`
* `Protocol`, `Source_Port`, `Destination_Port`
* `Packet_Length_Mean`, `Packet_Length_Std`
* `SYN_Flag_Count`, `ACK_Flag_Count`, `Average_Packet_Size`
* `Label` (Class: `Benign`, `DDoS`, `Mirai`, `Reconnaissance`, `Brute Force`)
* `Source_IP`, `Destination_IP`, `Timestamp` (Metadata fields)

---

## 5. Installation & Setup

### Prerequisites
* Python 3.10+
* Node.js v18+ & npm

### Backend Setup
1. Open a terminal and navigate to the backend folder:
   ```bash
   cd backend
   ```
2. Initialize virtual environment and install python dependencies:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Generate the sample dataset:
   ```bash
   python app/sample_data/generate_data.py
   ```
4. Boot the FastAPI API server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   * *Swagger API documentation will be available at: http://localhost:8000/docs*

### Frontend Setup
1. Open another terminal and navigate to the frontend folder:
   ```bash
   cd frontend
   ```
2. Install client dependencies:
   ```bash
   npm install
   ```
3. Boot the local development server:
   ```bash
   npm run dev
   ```
   * *The web interface will open at: http://localhost:5173*

---

## 6. Primary API Endpoints

### System Status
* `GET  /api/system/status`: Check health of DB, ML models, and uploads folder.

### Datasets
* `POST /api/dataset/upload`: Upload raw network traffic CSV.
* `GET  /api/dataset/{id}/preview`: Fetch first 10-15 rows of a CSV.
* `POST /api/preprocess/{id}`: Clean, validate, and preview splits.

### Machine Learning
* `POST /api/model/train`: Trigger model training (XGBoost / Random Forest).
* `GET  /api/model/{id}`: Fetch accuracy, precision, recall, and feature importances.

### Threat Detection
* `POST /api/detect`: Run batch threat detection using a selected model on a dataset.
* `GET  /api/threats`: List detected incidents with filters.

### Reports
* `POST /api/reports/generate`: Compile security audit results.
* `GET  /api/report/{id}/download`: Download generated Report PDF.
