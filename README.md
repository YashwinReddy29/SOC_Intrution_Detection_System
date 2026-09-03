# 🛡 AI-Powered SOC Intrusion Detection Platform

An event-driven Security Operations Center (SOC) platform that combines behavioral anomaly detection, real-time Socket.IO alerts, risk scoring, threat-intelligence scoring, Docker deployment, and automated CI validation.

## Highlights

- **Isolation Forest anomaly detection** trained on normal traffic only
- **7 behavioral features:** source entropy, port diversity, failed-login rate, bytes-in/out ratio, time-of-day z-score, protocol count, and geographic distance
- **Chronological 70/15/15 evaluation** to reduce temporal leakage
- **10,000 reproducible synthetic SOC events** across brute-force, credential-stuffing, port-scan, data-exfiltration, and DDoS traffic
- **Event-driven Flask + Flask-SocketIO ingestion** with no 3-second polling loop
- **Rolling 5-minute behavioral state** for online feature extraction
- **Risk scoring and threat-intelligence enrichment** before alert emission
- **Real-time `detection_event` and `new_alert` Socket.IO events**
- **Health/readiness endpoints, request IDs, structured request logs, security headers, payload limits, API-key protection, and rate limiting**
- **Docker image builds its own ML artifact** for reproducible deployment
- **Pytest + GitHub Actions + Docker build validation**

## Architecture

```text
                    ┌─────────────────────┐
                    │  Event Producer /   │
                    │  SOC Dashboard      │
                    └──────────┬──────────┘
                               │ POST /api/ml/events
                               ▼
                    ┌─────────────────────┐
                    │ Flask Application    │
                    │ request ID / limits  │
                    │ API key / rate limit │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Rolling Feature     │
                    │ Extractor           │
                    │ 7 behavioral feats  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Isolation Forest    │
                    │ model v2.1.0        │
                    │ calibrated threshold│
                    └──────────┬──────────┘
                               │
                     ┌─────────┴─────────┐
                     ▼                   ▼
              ┌──────────────┐    ┌──────────────┐
              │ Risk Scoring │    │ Threat Intel │
              └──────┬───────┘    └──────┬───────┘
                     └─────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ SQLite persistence  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Socket.IO           │
                    │ detection_event     │
                    │ new_alert            │
                    └─────────────────────┘
```

## ML Evaluation

The current reproducible experiment uses 10,000 generated events with 8,000 normal and 2,000 attack events. Data is split chronologically into 70% training, 15% validation, and 15% untouched test periods. The model is trained on normal training traffic only; the validation set is used to select the operating threshold.

### Held-out test results

| Metric | Result |
|---|---:|
| Precision | **90.52%** |
| Recall | **96.10%** |
| F1 | **93.23%** |
| Accuracy | **93.80%** |
| Mean ML latency | **15.30 ms** |
| p95 ML latency | **17.07 ms** |
| p99 ML latency | **19.70 ms** |

The attack-family test evaluation currently reports F1 scores of 98.87% for brute force, 95.69% for credential stuffing, 100.00% for data exfiltration, 96.90% for DDoS, and 98.47% for port scans.

## Real-Time Benchmark

A 200-event live benchmark measured the actual Flask ingestion and Socket.IO path.

| Metric | Result |
|---|---:|
| Events measured | **200** |
| Socket.IO delivery | **200 / 200** |
| HTTP ingest mean | **67.01 ms** |
| HTTP p95 | **71.69 ms** |
| Socket.IO mean | **25.43 ms** |
| Socket.IO p95 | **30.56 ms** |
| Socket.IO p99 | **34.08 ms** |
| Server ML mean | **17.28 ms** |
| Server ML p95 | **19.44 ms** |

The benchmark measures request-to-client delivery, while the ML benchmark measures model scoring separately. These metrics should not be treated as classification metrics.

## Project Structure

```text
.
├── app/
│   ├── controllers/
│   │   ├── ml_controller.py
│   │   └── realtime_controller.py
│   ├── models/
│   └── services/
├── ml/
│   ├── detection_service.py
│   ├── eval_metrics.py
│   ├── feature_extractor.py
│   ├── ml_service.py
│   ├── risk_scorer.py
│   └── synthetic_data_generator.py
├── scripts/
│   ├── benchmark_event_latency.py
│   └── run_ml_experiment.py
├── tests/
│   └── test_ml_pipeline.py
├── .env.example
├── .github/workflows/ci.yml
├── .dockerignore
├── Dockerfile
├── requirements.txt
└── run.py
```

## Local Setup

### 1. Clone and enter the repository

```bash
git clone https://github.com/YashwinReddy29/SOC_Intrution_Detection_System.git
cd SOC_Intrution_Detection_System
git checkout production-ml-upgrade
```

### 2. Create the virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Generate the model artifact

```bash
PYTHONPATH=. python scripts/run_ml_experiment.py
```

This creates the ignored local artifacts:

```text
ml/models/isolation_forest.joblib
ml/data/soc_events_v2.csv
ml/reports/ml_metrics_v2.json
```

### 5. Run tests

```bash
PYTHONPATH=. pytest -q
```

### 6. Run the application

```bash
PYTHONPATH=. python run.py
```

The default service listens on `http://127.0.0.1:5000`.

## API

### Liveness

```bash
curl http://127.0.0.1:5000/health
```

### Readiness

```bash
curl http://127.0.0.1:5000/ready
```

### ML health

```bash
curl http://127.0.0.1:5000/api/ml/health
```

### Event ingestion

`POST /api/ml/events` requires these fields:

```text
timestamp
source_ip
destination_ip
source_port
destination_port
protocol
bytes_in
bytes_out
failed_logins
country
latitude
longitude
```

Example:

```bash
curl -X POST http://127.0.0.1:5000/api/ml/events \
  -H 'Content-Type: application/json' \
  -d '{
    "timestamp":"2026-01-15T12:00:00+00:00",
    "source_ip":"10.10.10.10",
    "destination_ip":"192.0.2.10",
    "source_port":49152,
    "destination_port":443,
    "protocol":"HTTPS",
    "bytes_in":1000,
    "bytes_out":500,
    "failed_logins":0,
    "country":"US",
    "latitude":40.7128,
    "longitude":-74.0060
  }'
```

## Production API Security

API-key authentication is optional for local development and enabled by setting `ML_API_KEY`.

```bash
export ML_API_KEY='replace-with-a-random-secret'
```

Clients then send:

```text
X-API-Key: <value>
```

The endpoint also applies an in-memory request rate limit. Configure it with:

```text
ML_RATE_LIMIT=300
ML_RATE_WINDOW_SECONDS=60
```

For multi-process or horizontally scaled deployments, move rate-limit state to a shared store such as Redis.

## Environment Configuration

Copy the example configuration:

```bash
cp .env.example .env
```

Supported variables:

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask application secret |
| `LOG_LEVEL` | Logging level, e.g. `INFO` |
| `SOCKETIO_CORS_ORIGINS` | Comma-separated allowed Socket.IO origins |
| `ML_API_KEY` | Optional event-ingestion API key |
| `ML_RATE_LIMIT` | Requests allowed per rate window |
| `ML_RATE_WINDOW_SECONDS` | Rate-limit window size |

Do not commit `.env` or production secrets.

## Docker

The Docker image is self-contained. It generates the ML model artifact during image build, so a fresh clone does not depend on an untracked local model file.

Build:

```bash
docker build -t soc-system .
```

Run:

```bash
docker run --rm -p 5000:5000 \
  -e SECRET_KEY='replace-with-a-random-secret' \
  soc-system
```

Check container readiness:

```bash
curl http://127.0.0.1:5000/ready
```

The image also contains a Docker `HEALTHCHECK` based on `/ready`.

## End-to-End Latency Benchmark

With the application running:

```bash
PYTHONPATH=. python scripts/benchmark_event_latency.py
```

When API-key protection is enabled, export the same key in the benchmark shell:

```bash
export ML_API_KEY='same-value-used-by-the-server'
PYTHONPATH=. python scripts/benchmark_event_latency.py
```

The report is written to:

```text
ml/reports/event_latency_report.json
```

## CI/CD

GitHub Actions validates the project by:

1. Installing pinned dependencies
2. Compiling `app`, `ml`, `scripts`, and `tests`
3. Regenerating the ML artifact
4. Running the pytest suite
5. Importing the Flask application
6. Building the Docker image

## Engineering Notes

- The online detector keeps rolling state between events, matching the event-driven serving model.
- Model artifacts and generated CSV/JSON files are intentionally ignored by Git; CI and Docker recreate them deterministically.
- The current synthetic dataset is for engineering validation and demonstration. Production security analytics should be evaluated against representative, permissioned real telemetry.
- The legacy dashboard/controller code remains in the repository for backward compatibility, but the application factory registers the event-driven realtime and ML controllers.

## Resume-ready project line

**AI-Powered SOC Intrusion Detection Platform** — Built an event-driven anomaly detection service with Isolation Forest, rolling behavioral features, Flask-SocketIO, risk scoring, Docker, and CI/CD; achieved **90.5% precision, 96.1% recall, 93.2% F1** on a chronological 10K-event holdout and **30.6 ms p95 Socket.IO delivery latency** in a 200-event live benchmark.
