# 🛡️ PhishGuard V5 — Autonomous Phishing Detection Platform

![Docker](https://img.shields.io/badge/Docker-ready-blue)
![Kubernetes](https://img.shields.io/badge/Kubernetes-deployed-green)
![Python](https://img.shields.io/badge/Python-3.11-yellow)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen)

---

## 🚀 Overview

**PhishGuard V5** is an advanced cybersecurity platform designed to detect phishing domains and malicious email indicators using a modular, scalable, and cloud-ready architecture.

This version introduces **enterprise-grade infrastructure**, including containerization, orchestration, observability, and secure API access.

---

## 🧠 Core Capabilities

* 🔍 Domain analysis & phishing detection engine
* 📧 Email parsing & indicator extraction
* ⚙️ Asynchronous worker processing
* 📊 Real-time metrics (Prometheus)
* 🔐 JWT-based API security
* ⚡ Redis caching layer
* ☸️ Kubernetes deployment ready
* 🔄 CI/CD automation (GitHub Actions)

---

## 🏗️ Architecture

```
Client → FastAPI → Pipeline Engine → Redis → Worker
                      ↓
               Detection Modules
                      ↓
          Scoring + Threat Intelligence
```

---

## 📂 Project Structure

```
phishguard_v5/
│
├── app/
│   ├── main.py
│   ├── auth.py
│   ├── metrics.py
│   ├── api/
│   ├── core/
│   ├── email/
│   └── worker/
│
├── k8s/              # Kubernetes manifests
├── monitoring/       # Prometheus & Grafana
├── security/         # Secrets management
├── .github/          # CI/CD pipelines
│
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 🐳 Local Development (Docker)

### 1. Build & Run

```bash
docker-compose up --build
```

### 2. API доступ

```
http://localhost:8000
```

---

## ☸️ Kubernetes Deployment

```bash
kubectl apply -f k8s/
kubectl apply -f monitoring/
kubectl apply -f security/
```

---

## 🔐 Security

* JWT authentication for protected endpoints
* Secrets managed via Kubernetes
* Non-root Docker containers
* Isolated services architecture

---

## 📊 Observability

* **Prometheus** for metrics collection
* **Grafana** for visualization
* Custom request tracking

---

## 🔄 CI/CD Pipeline

Automated with GitHub Actions:

* Build Docker image
* Simulated push to registry
* Kubernetes deployment

---

## ⚙️ Tech Stack

* **Backend:** FastAPI (Python)
* **Queue/Cache:** Redis
* **Containerization:** Docker
* **Orchestration:** Kubernetes
* **Monitoring:** Prometheus + Grafana
* **CI/CD:** GitHub Actions

---

## 📈 Roadmap (V6)

* Multi-cloud deployment
* Zero Trust architecture
* AI-based phishing detection (ML models)
* Global threat intelligence feeds (MISP integration)

---

## 🎯 Use Cases

* Security research & phishing analysis
* Email security systems
* SOC automation pipelines
* Cybersecurity portfolio project

---

## 👨‍💻 Author

Developed as an advanced cybersecurity engineering project focused on real-world architecture and scalability.

---

## ⚠️ Disclaimer

This project is for educational and research purposes only.
Do not use for malicious activities.

---

## ⭐ Final Note

PhishGuard V5 represents a transition from a simple detection tool to a **production-ready cybersecurity platform**, aligning with modern DevSecOps and cloud-native practices.
