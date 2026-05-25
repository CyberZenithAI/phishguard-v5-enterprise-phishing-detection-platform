# 🛡️ PhishGuard V0.5 — Plataforma de Detección de Phishing

<p align="center">
  <img src="https://img.icons8.com/fluency/96/hacker.png" width="80"/>
</p>

<p align="center">
  <b>Developed by ThreatStalker</b>
</p>

![Docker](https://img.shields.io/badge/Docker-ready-blue)
![Kubernetes](https://img.shields.io/badge/Kubernetes-concepts-green)
![Python](https://img.shields.io/badge/Python-3.11-yellow)
![Status](https://img.shields.io/badge/Status-Cloud--Ready-brightgreen)

---

## 🚀 Descripción

**PhishGuard V0.5** es una plataforma de ciberseguridad enfocada en la detección de dominios phishing e indicadores maliciosos en correos electrónicos.

Este proyecto forma parte de mi desarrollo como ingeniero en formación, aplicando conceptos modernos de backend, seguridad y arquitectura cloud.

---

## 📖 Documentación

* [⚡ Quick Start](docs/quickstart.md) — Guía rápida para ejecutar el proyecto

---

## 🧠 Capacidades principales

* 🔍 Análisis de dominios sospechosos
* 📧 Procesamiento de correos electrónicos
* ⚙️ Procesamiento asíncrono con workers
* 📊 Métricas con Prometheus
* 🔐 Protección de endpoints con JWT
* ⚡ Redis como sistema de cache y cola
* ☸️ Preparado para Kubernetes (nivel conceptual)
* 🔄 CI/CD básico con GitHub Actions

---

## 🏗️ Arquitectura

```
Cliente → API (FastAPI) → Pipeline → Redis → Worker
                          ↓
                   Módulos de análisis
                          ↓
                  Scoring + Inteligencia
```

---

## 📂 Estructura del proyecto

```
phishguard_v0.5/
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
├── k8s/
├── monitoring/
├── security/
├── .github/
│
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 🐳 Ejecución local

```bash
docker-compose up --build
```

API disponible en:

```
http://localhost:8000
```

---

## ☸️ Kubernetes (conceptual)

```bash
kubectl apply -f k8s/
kubectl apply -f monitoring/
kubectl apply -f security/
```

> Implementación basada en aprendizaje y buenas prácticas.

---

## 🔐 Seguridad

* Autenticación JWT
* Uso de secrets (variables de entorno)
* Contenedores sin privilegios root
* Separación de servicios

---

## 📊 Observabilidad

* Prometheus (métricas)
* Grafana (visualización)
* Tracking básico de requests

---

## 🔄 CI/CD

* Build Docker
* Automatización básica
* Simulación de despliegue

---

## ⚙️ Tecnologías

* FastAPI (Python)
* Redis
* Docker
* Kubernetes (conceptual)
* Prometheus + Grafana
* GitHub Actions

---

## 🧠 Contexto de aprendizaje

Este proyecto fue desarrollado como parte de mi crecimiento técnico.

* Uso de IA como asistente de desarrollo
* Validación manual de arquitectura
* Enfoque en entender cada componente

---

## 🎯 Objetivo

Construir una base sólida en:

* Backend engineering
* Seguridad aplicada
* Arquitecturas modernas

---

## 👨‍💻 Autor

**ThreatStalker**
Cybersecurity & Backend Engineering (Junior–Intermedio)

GitHub: https://github.com/CyberZenithAI

---

## 🧩 Branding

PhishGuard V0.5 forma parte de los proyectos desarrollados bajo el alias **ThreatStalker**, enfocados en ciberseguridad y sistemas escalables.

---

## ⚠️ Aviso

Proyecto educativo.
No usar con fines maliciosos.

---

## ⭐ Nota final

PhishGuard V0.5 representa un paso importante en mi evolución como desarrollador, integrando backend, seguridad y conceptos cloud en un solo sistema.
