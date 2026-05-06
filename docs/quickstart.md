# ⚡ Quick Start — PhishGuard V5

## 📦 Requisitos

Antes de comenzar, asegúrate de tener instalado:

* Docker
* Docker Compose
* (Opcional) Kubernetes + kubectl

---

## 🐳 1. Ejecutar en local (recomendado)

Clona el repositorio:

```bash
git clone https://github.com/TU-USUARIO/phishguard-v5.git
cd phishguard-v5
```

Ejecuta el sistema:

```bash
docker-compose up --build
```

---

## 🌐 2. Acceder a la API

Una vez levantado:

```
http://localhost:8000
```

---

## 🧪 3. Probar endpoint (ejemplo)

```bash
curl -X POST http://localhost:8000/domain \
-H "Authorization: Bearer TOKEN" \
-H "Content-Type: application/json" \
-d '{"domain":"example.com"}'
```

---

## ⚙️ 4. Servicios incluidos

* API (FastAPI)
* Worker (procesamiento asíncrono)
* Redis (cache y cola)

---

## 📊 5. Observabilidad

Si habilitas monitoring:

* Prometheus → métricas
* Grafana → dashboards

---

## ☸️ 6. Despliegue en Kubernetes (avanzado)

```bash
kubectl apply -f k8s/
kubectl apply -f monitoring/
kubectl apply -f security/
```

---

## 🔐 7. Variables importantes

Configura en entorno:

* `JWT_SECRET`
* `REDIS_HOST`

---

## 🧠 Notas

* Este proyecto es educativo
* Basado en arquitectura real simplificada
* Diseñado para aprendizaje y portafolio

---

## 🛠️ Troubleshooting

### Error: puerto ocupado

```bash
lsof -i :8000
```

### Error Docker

```bash
docker-compose down -v
docker-compose up --build
```

---

## 🎯 Resultado esperado

✔ API corriendo
✔ Worker procesando
✔ Redis activo

---

## 👨‍💻 Autor

ThreatStalker
