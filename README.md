# HackerOps Agent — Autonomous Web Vulnerability Assessment & Auto-Remediation System

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.12+-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Frontend-Next.js%2014%20App%20Router-black.svg?style=flat&logo=next.js)](https://nextjs.org)
[![React Flow](https://img.shields.io/badge/Graph-React%20Flow%20%2F%20xyflow-FF0072.svg?style=flat)](https://reactflow.dev)
[![Docker](https://img.shields.io/badge/Isolation-Docker%20Sandbox-2496ED.svg?style=flat&logo=docker)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)

**HackerOps Agent** is an enterprise-grade, closed-loop cybersecurity web application. Given a target URL or domain, it autonomously conducts strictly read-only, non-destructive reconnaissance and vulnerability audits, streams real-time agent reasoning and live attack-path graph nodes over WebSockets, calculates compromise risk & compliance scores (OWASP Top 10, PCI-DSS), and synthesizes copy-paste-ready defensive patches (`nginx.conf`, middleware, DNS TXT, `.env` hardening).

---

## 🛡️ Key Features

- **Strict Ethical & Safety Guardrails:**
  - Non-destructive and strictly read-only probes.
  - Target Scope Validator blocks private/internal RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), and cloud metadata (`169.254.169.254`) by default unless `ALLOW_LOCAL_TARGETS=true` is enabled.
- **Isolated Execution Sandbox:**
  - Sandboxed execution (`Dockerfile.sandbox`) with memory limits (`mem_limit="512m"`), CPU quota (`cpu_quota=50000`), and dropped kernel capabilities (`cap_drop=["ALL"]`).
  - High-concurrency native async socket fallback when Docker daemon is not active.
- **Modular Non-Destructive Scanners:**
  - **OSINT & DNS Hygiene:** SPF, DMARC, MX, and dangling CNAME subdomain takeover indicators.
  - **Security Headers & TLS Auditor:** HSTS, Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, TLS version, certificate expiry, and cookie flags (HttpOnly, Secure, SameSite).
  - **CORS & API Surface Probe:** Wildcard credentials checks, origin reflection validation.
  - **Sensitive Path Discovery:** Safe, read-only GET checks for `/.env`, `/.git/HEAD`, `/robots.txt`, `/swagger.json`, `/openapi.json`, `/actuator/health`.
  - **Scoped Port & Service Recon:** Non-intrusive banner inspection across common database and application ports.
- **Autonomous Agent Loop & Attack Graph Reasoning:**
  - Live attack-path node graph powered by **React Flow** (`@xyflow/react`) with animated edges and tiered hierarchies.
  - Exploit-chain correlator links vulnerabilities into plausible attack paths (e.g. Missing CSP + Permissive CORS $\rightarrow$ Cross-Origin Data Exfiltration).
  - Real-time terminal log streaming over WebSockets.
- **PatchGen Auto-Remediation:**
  - Synthesizes drop-in defensive configurations for **Nginx**, **FastAPI**, **Express.js**, **DNS TXT records**, and **Docker**.
  - One-click copy, downloadable configuration files, and exportable audit reports (**Markdown**, **HTML**, **JSON**).

---

## 📂 Repository Structure

```text
aegis-agent/
├── docker-compose.yml          # Orchestrates backend, frontend, redis, and sandbox
├── .env.example                # Configuration parameters & safety overrides
├── .gitignore                  # Git ignore rules for Python, Node, Next.js, and DBs
├── .dockerignore               # Docker build context exclusions
├── sandbox/
│   ├── Dockerfile.sandbox      # Alpine-based isolated security scanner image
│   └── scripts/                # Safe wrapper scripts returning normalized JSON
├── backend/
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── app/
│   │   ├── main.py             # FastAPI entry, CORS, WebSocket /ws/scans/{id}
│   │   ├── config.py           # Pydantic v2 settings
│   │   ├── database.py         # Async SQLite (WAL mode) / PostgreSQL
│   │   ├── models/             # Scan, Finding, GraphNode, GraphEdge, Patch
│   │   ├── schemas/            # Pydantic request/response schemas
│   │   ├── core/
│   │   │   ├── validator.py    # Target & SSRF safety validator
│   │   │   ├── sandbox.py      # Docker runner + Native async socket fallback
│   │   │   ├── scanners.py     # 5 modular non-destructive scanners
│   │   │   ├── agent.py        # Autonomous state machine loop
│   │   │   └── patchgen.py     # Defensive patch synthesis engine
│   │   └── api/
│   │       └── routes.py       # REST API endpoints & report generator
│   └── tests/                  # Pytest test suite & end-to-end verification
└── frontend/
    ├── package.json
    ├── next.config.js
    └── src/
        ├── app/                # Next.js 14 App Router dashboard
        └── components/
            ├── AttackGraph.tsx # Interactive React Flow attack-chain node graph
            ├── LiveTerminal.tsx# Real-time streaming agent console
            ├── RiskMetrics.tsx # Risk score gauge & compliance cards
            ├── PatchViewer.tsx # Diff viewer with one-click copy and download
            ├── FindingsTable.tsx# Searchable vulnerability table
            └── ScanForm.tsx    # Target input bar & presets
```

---

## 🚀 Quickstart Guide

### Option 1: Local Development

#### 1. Backend Setup
```bash
cd backend
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

### Option 2: Docker Compose

```bash
docker-compose up --build
```

---

## 🧪 Running Automated Tests

Run backend unit and integration tests:
```bash
# From workspace root
$env:PYTHONPATH="backend"
pytest backend/tests -v -c backend/pytest.ini
```

Run end-to-end autonomous lifecycle verification:
```bash
$env:PYTHONPATH="backend"
python backend/tests/verify_e2e_flow.py
```

---

## 🔒 Safety & Ethical Guardrails

HackerOps Agent is strictly designed for authorized security assessments, defensive hardening, and vulnerability posture evaluation. Probing external systems without authorization is prohibited.
