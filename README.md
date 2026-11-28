# IoTShield — Multi-Agent Explainable Incident Response for IoT Networks

> *Explain · Assist · Respond · Secure*

**IoTShield** (codebase name: *IoT Sentinel*) turns raw IoT network traffic into an **explained, context-rich, risk-scored and analyst-approved incident report**.

It classifies network flows with a two-stage XGBoost model trained on **CICIoT2023**, flags unseen behaviour with an **Isolation Forest**, and explains every decision with **SHAP**. A **coordinator agent** then runs five specialist agents that pull threat intelligence (hybrid RAG over MITRE ATT&CK, NVD CVE and CISA), compute a deterministic risk score, draft a response plan, and write the incident report. **No containment action runs until an analyst approves it.**

---

## Table of contents

1. [Key features](#key-features)
2. [Architecture](#architecture)
3. [How an incident flows through the system](#how-an-incident-flows-through-the-system)
4. [Detection models & results](#detection-models--results)
5. [Multi-agent pipeline](#multi-agent-pipeline)
6. [Threat intelligence (RAG) & LLM layer](#threat-intelligence-rag--llm-layer)
7. [Tech stack](#tech-stack)
8. [Project structure](#project-structure)
9. [Getting started](#getting-started)
10. [Configuration](#configuration)
11. [Using the app](#using-the-app)
12. [API overview](#api-overview)
13. [Testing](#testing)
14. [Deployment](#deployment)
15. [Limitations & roadmap](#limitations--roadmap)
16. [Documentation & references](#documentation--references)

---

## Key features

| Area | What it does |
|---|---|
| **Traffic input** | Live capture (tshark / Scapy), `.pcap` / `.pcapng` upload, or CSV flow datasets |
| **Flow features** | CICFlowMeter-style flow extraction, 23 scaled features per flow |
| **Detection** | Two-stage XGBoost (benign vs attack, then 8 attack classes) |
| **Unknown threats** | Isolation Forest anomaly score (0–100). A "benign" flow that looks highly anomalous is rerouted as *suspicious* |
| **Explainability** | TreeSHAP top-5 features per flow, with value and direction, shown in the UI and passed to the agents |
| **Threat intelligence** | Hybrid RAG over 914 documents (MITRE ATT&CK, NVD CVE, CISA KEV, guidelines) with ID guardrails |
| **Risk scoring** | Deterministic score from 0 to 100 (severity, priority, reasons). The LLM never sets it |
| **Response** | Containment and recovery steps plus validated firewall rules, behind an **analyst approval gate** |
| **Reports** | Seven-section incident report (Markdown / JSON / PDF) with a full timeline |
| **LLM layer** | Pluggable: Ollama, Gemini, OpenAI, Anthropic or Groq. A rule-based fallback runs if the provider is unavailable |
| **Authentication** | JWT login with Argon2id password hashing, rotating refresh tokens, and admin / analyst / viewer roles |
| **SOC dashboard** | React UI with 10 pages: Dashboard, Incidents, Explainability, Model Performance, Datasets, Reports, Settings, Users, Register, Login |

---

## Architecture

```mermaid
flowchart TB
    subgraph IN[Input]
        A1[Live capture<br/>tshark / Scapy]
        A2[pcap / CSV upload]
    end
    subgraph FE[Features]
        B[Flow extraction<br/>23 features · StandardScaler]
    end
    subgraph ML[ML engine]
        C1[XGBoost binary] --> C2[XGBoost 8-class]
        C3[Isolation Forest<br/>anomaly 0–100]
        C4[TreeSHAP top-5]
    end
    subgraph AG[Agents]
        D0[Coordinator]
        D1[Detection] --> D2[Threat Intel] --> D3[Risk] --> D4[Response] --> D5[Report]
        D0 -.orchestrates.-> D1
    end
    subgraph ST[Storage & UI]
        E1[(PostgreSQL / SQLite)]
        E2[(MongoDB)]
        E3[(ChromaDB)]
        E4[FastAPI · 56 routes<br/>JWT auth]
        E5[React dashboard]
    end
    A1 --> B
    A2 --> B
    B --> C1
    B --> C3
    C2 --> C4
    C4 --> D1
    C3 --> D1
    D2 <--> E3
    D5 --> E2
    E4 --> E5
```

Detection is the only hard dependency. If any other agent or the LLM fails, the pipeline keeps going in **degraded mode** using deterministic fallbacks.

---

## How an incident flows through the system

1. **Capture / upload.** Packets come from tshark, Scapy, a pcap or a CSV.
2. **Flow features.** 23 features are computed per flow and scaled.
3. **Detection agent.** It runs the XGBoost label and confidence, the SHAP top-5 and the anomaly score.
4. **Threat intel agent.** Hybrid RAG retrieves up to 3 ATT&CK techniques plus related CVEs and CISA entries.
5. **Risk agent.** It computes a deterministic score from 0 to 100, plus severity and priority.
6. **Response agent.** It produces a containment and recovery plan and firewall rules, which are checked by a validator.
7. **Analyst approval.** Approve or reject. This step is required for any containment.
8. **Incident report.** Markdown, JSON and PDF, with a timeline, saved to MongoDB / disk.

**Risk score (deterministic):** base severity by class (DDoS / Mirai 95 … Recon 45) × confidence factor + evidence bonuses (SHAP, CVSS, CISA, anomaly, IoT port), clipped to 0–100.
**Bands:** Low < 25 · Medium < 50 · High < 75 · Critical ≥ 75.

---

## Detection models & results

**Dataset:** [CICIoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html) has 45,019,243 flows from 105 IoT devices. Its 34 raw labels are grouped into 8 classes: Benign, DDoS, DoS, Mirai, Recon, Spoofing, Web Attack, Brute Force.

- 16 protocol-indicator flags are dropped, so the model can't take a shortcut on protocol names.
- Training data is class-capped: up to 100k flows per class, with all Web and Brute-Force rows kept.
- Stage 1 is a class-weighted binary XGBoost. Stage 2 is a balanced 8-class XGBoost. They run alongside an Isolation Forest (100 trees, contamination 0.05).

**Offline evaluation** (class-capped test split, 107,265 flows):

| Metric | Value |
|---|---|
| Binary accuracy | 98.85 % |
| 8-class accuracy | 96.29 % |
| 5-fold CV accuracy | 95.92 % ± 0.31 |
| Macro F1 | 94.73 % |

> **Stricter re-run.** A later, stricter evaluation gave **80.1 % accuracy and 0.727 macro-F1**. Mirai, Spoofing and DoS stayed strong. The rare Web (F1 0.51) and Brute-Force (0.39) classes dropped, and 25 % of benign flows were flagged as attacks. That run also found a possible leakage risk: the scaler was fitted before the split. Fixing the evaluation protocol is listed under the roadmap. Full details are in `modeldetails.md` and `backend/TRAINING_AND_DATASET_DETAILS.md`.

Trained artifacts are in `backend/models/`, and the training scripts and notebook are in `backend/`.

---

## Multi-agent pipeline

| Agent | Output | LLM role | Fallback |
|---|---|---|---|
| **Coordinator** | Shared `IncidentState`, timeline, persistence | — | Per-agent timeout → *degraded* status |
| **Detection** | Class, confidence, SHAP top-5, anomaly score | Optional narrative | None (hard dependency) |
| **Threat Intel** | ≤ 3 ATT&CK techniques, CVEs, CISA entries | Query variants, synthesis | Retrieval results only |
| **Risk Assessment** | Score 0–100, severity, priority, reasons | Narrative only | Score is always rule-based |
| **Response** | Containment, recovery, firewall rules | Plan drafting | Attack-specific playbook |
| **Incident Report** | Seven-section report + PDF | Executive summary | Template text |

Every agent returns a validated Pydantic object. Benign flows skip the intel lookup and containment, and are auto-closed.

---

## Threat intelligence (RAG) & LLM layer

**RAG**
- **Knowledge base:** 914 documents: MITRE ATT&CK 818, NVD CVE 43, CISA 50, guidelines 3.
- **Store:** sentence-transformers embeddings in ChromaDB (cosine similarity).
- **Retrieval:** exact-ID match + dense vectors + BM25, fused with Reciprocal Rank Fusion (k = 60).
- **Guardrails:** every cited MITRE / CVE / CISA ID is checked against the retrieved set, and invented IDs are dropped. 158 of 158 structured IDs verified.

**LLM layer** (`backend/app/llm/client.py`)
- One client for **Ollama, Gemini, OpenAI, Anthropic and Groq**. Switch providers with `LLM_PROVIDER` in `.env`.
- Redis daily token budget, a 16k-character prompt cap, a 500-entry response cache, and JSON output validated against Pydantic schemas with one retry.
- **The LLM writes language, not verdicts.** Classification, the anomaly score and the risk score always come from XGBoost, the Isolation Forest and deterministic rules.

---

## Tech stack

| Layer | Technologies |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn, SQLAlchemy, Pydantic |
| ML / XAI | XGBoost, scikit-learn, SHAP, pandas, NumPy, joblib |
| RAG | ChromaDB, sentence-transformers (`BAAI/bge-small-en-v1.5`), rank-bm25 |
| LLM | Ollama · Gemini · OpenAI · Anthropic · Groq (via `httpx`) |
| Storage | PostgreSQL (Neon) or SQLite via SQLAlchemy, MongoDB (optional), ChromaDB, file store |
| Auth | PyJWT, Argon2id (argon2-cffi), HttpOnly refresh cookies |
| Capture | tshark, Scapy |
| Reports | ReportLab (PDF), Markdown, JSON |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS, Recharts, React Three Fiber, Lucide |

---

## Project structure

```
IOT_CYBER/
├── backend/
│   ├── app/
│   │   ├── agents/          # coordinator + threat intel, risk, response, report agents
│   │   ├── api/             # FastAPI routers: auth, core, capture, agents, RAG, reports
│   │   ├── auth/            # JWT + Argon2 security, role checks, create_admin script
│   │   ├── capture/         # tshark capture + CICFlowMeter-style flow extraction
│   │   ├── core/            # config, database, MongoDB, user utils
│   │   ├── db/              # SQLAlchemy models
│   │   ├── detection/       # detection engine
│   │   ├── llm/             # provider-agnostic LLM client, token budget, prompts
│   │   ├── ml/              # classifiers, Isolation Forest, threat engine, pipelines
│   │   ├── preprocessing/   # cleaning, encoding, scaling
│   │   ├── rag/             # ingest, embeddings, vector store, retriever, guardrails
│   │   ├── reports/         # report generator + storage service
│   │   ├── sample_data/     # synthetic sample traffic generator
│   │   ├── tests/           # unit tests (anomaly, multi-agent)
│   │   └── main.py          # FastAPI app
│   ├── tests/               # auth tests (pytest)
│   ├── data/                # RAG cache + ChromaDB index (model cache is downloaded here)
│   ├── models/              # trained XGBoost / Isolation Forest artifacts
│   ├── train_*.py           # training pipelines (+ Debiased_XGBoost_CICIoT2023.ipynb)
│   ├── platform_settings.json
│   └── requirements.txt
├── frontend/                # React + Vite SOC dashboard
├── sample_pcaps/            # sample attack captures (SYN / ACK / UDP / ICMP floods)
├── run_backend.bat          # start backend (activates venv)
├── run_frontend.bat         # start frontend
├── AUTH_SETUP.md            # authentication setup & behaviour
├── CHANGES.md               # pre-deployment fixes log
└── DEPLOYMENT.md            # how to deploy (Vercel + Cloudflare tunnel)
```

---

## Getting started

### Prerequisites
- **Python 3.10+**
- **Node.js 20.19+** (or 22.12+) and npm
- A **PostgreSQL** database (e.g. a free [Neon](https://neon.tech) project), or use SQLite locally (see [Configuration](#configuration))
- *Optional:* **Wireshark / tshark** for live capture, **MongoDB** for persistent incident reports, **Redis** for LLM token budgets, **Ollama** for a local LLM

### 1. Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate            # macOS / Linux: source venv/bin/activate
pip install -r requirements.txt  # large (~1 GB, includes PyTorch); add --timeout 120 on slow networks
copy .env.example .env           # macOS / Linux: cp .env.example .env
```

Edit `backend/.env` and set at least:

```dotenv
DATABASE_URL=postgresql://USER:PASSWORD@HOST/DB?sslmode=require   # or: sqlite:///./iot_sentinel.db
AUTH_SECRET_KEY=<output of: python -c "import secrets; print(secrets.token_urlsafe(48))">
```

**The backend won't start without `AUTH_SECRET_KEY`** (it needs at least 32 bytes). Then create the first admin account:

```bash
python -m app.auth.create_admin   # prompts for email + password (min 12 chars)
```

Start it:

```bash
# Windows, from the repo root
run_backend.bat

# or anywhere, from backend/ with the venv active
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

On first start, the embedding model (~130 MB) downloads into `backend/data/models/`.
Interactive API docs: **http://127.0.0.1:8000/docs**

### 2. Frontend

```bash
cd frontend
npm ci
npm run dev          # or run_frontend.bat from the repo root
```

Dashboard: **http://localhost:5173**. Sign in with the admin account you created. During development, Vite proxies `/api` to the backend on port 8000.

### 3. Quick check

- http://127.0.0.1:8000/api/health should return a status response.
- After you log in, the dashboard should load data. All other `/api/*` routes need a login token, so open them through the app or authorise in `/docs`.

---

## Configuration

Settings are read from `backend/.env` (template: `backend/.env.example`) and `backend/platform_settings.json`. Environment variables take priority.

| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | Main database (PostgreSQL or SQLite). **Set your own.** | a hardcoded Neon URL in `config.py`, which should be removed |
| `AUTH_SECRET_KEY` | JWT signing secret, at least 32 bytes. **Required** | — |
| `AUTH_ACCESS_TOKEN_MINUTES` / `AUTH_REFRESH_TOKEN_HOURS` | Token lifetimes | `15` / `8` |
| `AUTH_COOKIE_SECURE` / `AUTH_COOKIE_SAMESITE` | Refresh-cookie flags. Use `true` / `none` when frontend and backend are on different domains (HTTPS) | `false` / `lax` |
| `LLM_PROVIDER` | `ollama` · `gemini` · `openai` · `anthropic` · `groq` | from `platform_settings.json` (`ollama`) |
| `LLM_MODEL` | Model name. Leave empty to use the provider default | provider default |
| `GEMINI_API_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GROQ_API_KEY` | API key for the chosen provider | — |
| `OLLAMA_BASE_URL` | Local Ollama server | `http://localhost:11434` |
| `EMBEDDING_MODEL` | RAG embedding model | `BAAI/bge-small-en-v1.5` |
| `MONGODB_URI` / `MONGODB_DB_NAME` | Persistent report storage (optional) | `mongodb://localhost:27017` / `iot_sentinel` |
| `NVD_API_KEY` | Higher NVD API rate limits (optional) | — |
| `CORS_ORIGINS` | Comma-separated frontend origins allowed to call the API (falls back to `AUTH_ALLOWED_ORIGINS`) | `http://localhost:5173,http://127.0.0.1:5173` |
| `VITE_API_URL` (frontend) | Backend URL when frontend and backend are on different hosts | `/api` (dev proxy) |

> **Free hosted LLM:** `LLM_PROVIDER=groq` with a free key from [console.groq.com](https://console.groq.com) (default model `openai/gpt-oss-120b`).

---

## Using the app

1. Start the backend and frontend, then log in.
2. **Live capture**, or upload a capture from `sample_pcaps/` (for example `ddos_syn_flood.pcap`). You can also upload a CSV dataset.
3. Run detection. Incidents appear in the **SOC Incident Center**, and the agent pipeline shows each agent's status.
4. Open an incident to see the classification, the **SHAP deep-dive**, threat intel, the risk score and the proposed response.
5. **Approve or reject** the response plan.
6. Download the **incident report** (Markdown / JSON / PDF).

*Example from stored runs:* Recon at 99.99 % confidence, top SHAP feature `Tot sum`, MITRE T0816 / T0849, risk 56 (High, P2).

---

## API overview

All routes are under `/api`, with full interactive docs at `/docs`. **Every route except `/api/auth/*` needs a bearer access token.** Viewer accounts are read-only, and only admins can change platform settings.

| Router | Prefix | Key endpoints |
|---|---|---|
| Auth | `/api/auth` | `POST /login`, `POST /refresh`, `POST /logout`, `POST /logout-all`, `GET /me`, `POST /change-password`, `POST /register` (admin), `POST/GET /users` (admin) |
| Core | `/api` | `GET /health`, `GET /system/status`, `GET /llm/health`, `POST /dataset/upload`, `GET /datasets`, `POST /preprocess/{id}`, `GET /models`, `POST /predict`, `POST /predict/explain`, `POST /detect`, `GET /threats`, `GET /threats/{id}/explain`, `GET /analytics`, `GET/POST /settings` |
| Anomaly | `/api` | `GET /anomaly/status`, `POST /anomaly/train`, `GET /anomaly/model/{id}` |
| Capture | `/api/capture` | `GET /interfaces`, `POST /start`, `POST /stop`, `GET /status`, `POST /upload`, `POST /process` |
| Agents | `/api/agents` | `POST /analyze`, `GET /incidents`, `GET /incident/{id}`, `POST /incident/{id}/approval`, `GET /incident/{id}/report`, `GET /incident/{id}/download` |
| RAG / LLM | `/api` | `GET /rag/status`, `POST /rag/search`, `POST /rag/refresh`, `GET /llm/status` |
| Reports | `/api` · `/api/reports/storage` | `POST /reports/generate`, `GET /report/{id}/download`, `GET /reports/storage`, `GET /reports/storage/{id}`, `GET /reports/storage/{id}/download` |

---

## Testing

```bash
cd backend
venv\Scripts\activate
python -m unittest discover -s app/tests -t .
```

- `test_anomaly.py` (8 tests): anomaly score normalisation and training, risk scoring, unknown-behaviour handling, and edge cases (empty, single-class and invalid data).
- `test_multi_agent_soc.py` (5 tests): interface enumeration, the coordinator pipeline, the benign-traffic safeguard, the analyst approval workflow, and the agent API endpoints.

Auth tests (10: login, protected routes, refresh rotation, replay detection, viewer read-only, logout):

```bash
pip install pytest
set PYTHONPATH=backend           # macOS / Linux: export PYTHONPATH=backend
python -m pytest backend/tests/test_auth.py -q   # run from the repo root
```

The project report also documents 18 system test cases (TC-01–TC-18) and 30 firewall-rule validator cases.

---

## Deployment

For a quick, free deployment (frontend on **Vercel**, backend on your machine behind a **Cloudflare quick tunnel**), see **[DEPLOYMENT.md](DEPLOYMENT.md)**.

For a permanent setup, run the backend on a VM with at least 2 GB of RAM and set `CORS_ORIGINS` and `VITE_API_URL` accordingly. When the frontend and backend are on different domains, also set `AUTH_COOKIE_SECURE=true` and `AUTH_COOKIE_SAMESITE=none`, so the login refresh cookie is sent. Some browsers (Safari, Incognito) still block it. Live capture only works where the backend can see the network.

---

## Limitations & roadmap

**Known limitations**
- The stricter evaluation shows a generalisation gap (80.1 % accuracy, a high benign false-alarm rate) and weak rare classes (Web, Brute-Force).
- Only 27 of 90 cited ATT&CK techniques match the attack's tactic.
- The firewall validator is pattern-based and can miss equivalent destructive forms (for example `--flush`).
- LLM-assisted investigations are slow: 194 s median versus 0.26 s rule-based.
- Auth covers JWT login and admin / analyst / viewer roles, but not MFA, password reset or OAuth.

**Roadmap**
- Leakage-free evaluation on a realistic traffic mix, plus cross-dataset tests (BoT-IoT, N-BaIoT)
- An attention / feature-gating classifier inspired by the base paper
- Attack-aware query expansion for threat intel
- A semantic parser for firewall rules
- An ESP32 live testbed, an analyst feedback loop, and federated deployment

---

## Documentation & references

- [`CHANGES.md`](CHANGES.md): pre-deployment fixes (Linux install, upload sanitisation, CORS, FastAPI compatibility, Groq provider)
- [`DEPLOYMENT.md`](DEPLOYMENT.md): deployment guide
- [`AUTH_SETUP.md`](AUTH_SETUP.md): authentication setup and behaviour
- [`modeldetails.md`](modeldetails.md) and [`backend/TRAINING_AND_DATASET_DETAILS.md`](backend/TRAINING_AND_DATASET_DETAILS.md): model and dataset details

**Base paper:** Sharma K.P. et al., *"Interpretable intrusion detection for IoT environments using a self-attention-based explainable AI framework,"* Scientific Reports 15, 39937 (2025).

**Dataset:** Neto E.C.P. et al., *"CICIoT2023: A real-time dataset and benchmark for large-scale attacks in IoT environment,"* Sensors 23(13), 5941 (2023).

---

*Developed as an SDC-II / Project School project at Keshav Memorial Institute of Technology (KMIT), Hyderabad.*
