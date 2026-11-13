# SpecGuard
AI-powered pre-deployment security auditor &amp; governance gatekeeper that cross-examines backend code, infrastructure configs, and API docs to catch shadow endpoints, exposed ports, and documentation drift.

# 🛡️ SpecGuard AI

> **An automated "Shift-Left" security auditor and compliance gatekeeper for modern web backends.**

SpecGuard AI cross-examines your **backend code**, **infrastructure configs**, and **API documentation** in a single automated scan to catch security flaws, shadow/zombie endpoints, and documentation drift *before* code ever reaches production.

![Streamlit](https://img.shields.io/badge/Built%20with-Streamlit-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Gemini AI](https://img.shields.io/badge/Powered%20by-Google%20Gemini-4285F4?style=flat-square&logo=google&logoColor=white)

---

## 🚀 Key Features

* **🔍 Multi-Artifact Cross-Examination:** Simultaneously analyzes application source code (FastAPI/Express), infrastructure configurations (`docker-compose.yml`), and documentation (`README.md` / OpenAPI).
* **⚡ Security & Open-Ends Audit:** Instantly flags unauthenticated routes, forgotten `/debug` endpoints, and exposed server ports (OWASP-style risks).
* **📉 Documentation Drift Detection:** Automatically identifies parameter mismatches, missing endpoints, and contract discrepancies between your code and your written specs.
* **🛠️ Dual Auto-Remediation:** Generates hardened backend code snippets alongside fully synchronized documentation files.
* **🚦 Deterministic Gatekeeper Verdict:** Issues a strict `PASS` or `BLOCK` deployment decision based on configurable security and compliance rules.

---

## 🏗️ Architecture & Workflow

1. **Ingest (`ingestor.py`):** Normalizes and cleans the 3 core inputs (Code, Docs, Infra) or loads built-in demo samples.
2. **Analyze (`analyzer.py`):** Leverages Google Gemini Flash with strict Pydantic schemas to extract structured security risks and drift metrics.
3. **Validate (`validator.py`):** Runs deterministic safety rules to issue the final `PASS`/`BLOCK` deployment verdict.
4. **Interfaces:** `backend/api.py` exposes the FastAPI service, while `frontend/` contains the React/Vite retro-pixel dashboard.

## 🧭 Local development

Install backend dependencies and start the API:

```powershell
.\venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\venv\Scripts\python.exe -m uvicorn backend.api:app --reload --port 8000
```

In another terminal, install and start the frontend:

```powershell
cd frontend
npm install
npm run dev
```

The legacy Streamlit dashboard is still available with `streamlit run backend/app.py`.

If your terminal is already inside `backend\`, use the repository interpreter explicitly:

```powershell
..\venv\Scripts\python.exe -m uvicorn api:app --reload
```

Using `uvicorn` by itself can select a different Python environment that does not
contain FastAPI.
