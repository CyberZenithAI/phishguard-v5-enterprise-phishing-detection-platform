````md
# 🛡️ PhishGuard V0.5

> Enterprise-Grade Phishing Detection & Threat Intelligence Platform  
> Secure • Scalable • Cloud-Ready • Modular • SOC-inspired Architecture

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Production-green)
![Docker](https://img.shields.io/badge/Docker-Containerized-blue)
![Cloudflare](https://img.shields.io/badge/Cloudflare-Tunnel-orange)
![Redis](https://img.shields.io/badge/Redis-Queue-red)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## 🚀 Overview

**PhishGuard V0.5** is a cybersecurity backend platform designed to detect phishing domains, malicious URLs, and suspicious email patterns using a modular and scalable architecture.

It simulates a lightweight Security Operations Center (SOC) pipeline, combining real-time processing, asynchronous workers, and threat scoring logic.

Built for learning, experimentation, and production-grade architectural practice.

---

## 🎯 Objectives

- Detect phishing and suspicious domains in real time  
- Analyze email-based threat indicators  
- Provide structured risk scoring outputs  
- Demonstrate scalable backend architecture  
- Simulate SOC-like processing pipelines  

---

## 🧠 Key Features

- 🔍 Real-time phishing domain analysis  
- 📧 Email threat parsing and inspection engine  
- ⚙️ Asynchronous processing with worker architecture  
- 🧠 Rule-based risk scoring system  
- ⚡ Redis queue for background processing  
- 📊 Metrics-ready design (Prometheus-compatible)  
- 🔐 JWT-secured API endpoints  
- ☁️ Cloudflare Tunnel deployment support (no open ports required)  
- 🐳 Fully containerized with Docker & Docker Compose  

---

## 🏗️ Architecture

```text
Client Request
      ↓
FastAPI Gateway
      ↓
Redis Queue System
      ↓
Worker Processing Engine
      ↓
Threat Intelligence Module
      ↓
Risk Scoring Engine
      ↓
Structured JSON Response
````

---

## ⚙️ Tech Stack

| Layer         | Technology              |
| ------------- | ----------------------- |
| Backend       | FastAPI (Python)        |
| Queue System  | Redis                   |
| Containers    | Docker / Docker Compose |
| Security      | JWT Authentication      |
| Observability | Prometheus (optional)   |
| Deployment    | Cloudflare Tunnel / VPS |

---

## 🚀 Quick Start

### 1. Clone repository

```bash
git clone https://github.com/CyberZenithAI/phishguard_v0.5.git
cd phishguard_v0.5
```

---

### 2. Run with Docker

```bash
docker compose up --build -d
```

---

### 3. Access API

```text
http://localhost:8000
```

---

## 🌐 Deployment Options (Cloudflare FREE)

### 🟡 Option 1 — Temporary Public URL (Development)

Expose your local API instantly:

```bash
cloudflared tunnel --url http://localhost:8000
```

Example output:

```text
https://random-name.trycloudflare.com
```

✔ No setup required
✔ No domain needed
✔ Ideal for testing and demos

---

### 🔵 Option 2 — Cloudflare Tunnel (Production-Ready)

Secure persistent tunnel without exposing ports:

```bash
cloudflared tunnel login
cloudflared tunnel create phishguard
```

### Configuration:

```yaml
tunnel: phishguard
credentials-file: /root/.cloudflared/phishguard.json

ingress:
  - service: http://localhost:8000
  - service: http_status:404
```

### Run tunnel:

```bash
cloudflared tunnel run phishguard
```

---

### 🟢 Option 3 — Custom Domain (Enterprise Setup)

```text
https://phishguard.yourdomain.com
```

Powered by Cloudflare DNS + Tunnel.

---

## 🔐 Security Architecture

* JWT authentication per API request
* Isolated Docker container environment
* Internal-only Redis communication (no public exposure)
* Environment variable-based configuration (.env)
* Cloudflare edge-layer protection
* No direct port exposure in production deployments

---

## 📂 Project Structure

```text
phishguard_v0.5/
│
├── app/              # Core FastAPI application
├── worker/           # Background processing engine
├── security/         # Authentication & security logic
├── monitoring/       # Metrics and observability
├── k8s/              # Kubernetes deployment manifests
│
├── docker-compose.yml
├── Dockerfile
└── README.md
```

---

## 📡 API Example

### Request

```http
POST /analyze
```

```json
{
  "input": "http://suspicious-domain.com"
}
```

---

### Response

```json
{
  "risk_score": 92,
  "threat_level": "HIGH",
  "indicators": [
    "newly_registered_domain",
    "suspicious_redirect",
    "obfuscated_url_pattern"
  ]
}
```

---

## 📊 Roadmap

* [x] Core phishing detection engine
* [x] Dockerized architecture
* [x] Cloudflare Tunnel integration
* [ ] Machine Learning-based detection layer
* [ ] Web dashboard (SOC UI)
* [ ] SIEM integration support
* [ ] Kubernetes production deployment
* [ ] Multi-tenant architecture

---

## ⚠️ Disclaimer

This project is developed strictly for **educational, research, and defensive cybersecurity purposes**.

Any malicious or unauthorized use is strictly prohibited.

---

## 👨‍💻 Author

**ThreatStalker**
Cybersecurity & Backend Engineering

GitHub: [https://github.com/CyberZenithAI](https://github.com/CyberZenithAI)

```
```
