# KubeGuard AI — Windows-native starter

A portfolio-friendly observability project that will later become a Kubernetes AIOps experiment. **Milestone 1 is not an ML model or an auto-remediation system.** It is a small fault-injection demo API with Prometheus metrics.

## Requirements (no WSL, no Docker)

- Windows 11 and PowerShell
- Python 3.13
- VS Code with Python extension
- Git
- Prometheus Windows binary, downloaded separately from https://prometheus.io/download/

## 1. Create a virtual environment (PowerShell in VS Code)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r app/requirements.txt -r app/requirements-dev.txt
```

No activation is required; using `.\.venv\Scripts\python.exe` directly avoids PowerShell execution-policy problems.

## 2. Start the API (Terminal 1)

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open http://127.0.0.1:8000/docs , http://127.0.0.1:8000/health , http://127.0.0.1:8000/metrics .

## 3. Install and start Prometheus (Terminal 2)

Download a `prometheus-...windows-amd64.zip` from https://prometheus.io/download/ . Extract its folder **inside `tools/`**. No binary is committed to Git. Then, from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-prometheus.ps1
```

Open http://127.0.0.1:9090/targets . The `kubeguard-api` target must be **UP**. It scrapes the API at `127.0.0.1:8000` every 5 seconds.

## 4. Simulate traffic (Terminal 3)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\generate-traffic.ps1
```

Expected: 12 healthy requests, 8 slow requests, and 4 intentional HTTP 503 responses.

## 5. Useful PromQL queries

Availability:

```promql
up{job="kubeguard-api"}
```

Outcome counts:

```promql
kubeguard_requests_total
```

Approximate p95 latency over five minutes:

```promql
histogram_quantile(0.95, sum by (le) (rate(kubeguard_request_duration_seconds_bucket[5m])))
```

## 6. Run tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Project layout

```text
app/                 FastAPI application and requirements
prometheus/          Prometheus YAML scrape config
services/            (added later as project grows)
scripts/             PowerShell helper scripts
tests/               API unit tests
docs/                Experiment log and project roadmap
.github/workflows/    CI unit tests, on GitHub Windows runners
```

## Safety

The incident simulation does not damage any real workload. It uses controllable time delays and intentionally returned 503 responses. Any future Kubernetes remediation will default to dry-run and be tested only in a disposable cluster.
