# Experiment log

## Experiment 01 — Observable API on Windows

- Date: TODO
- Environment: Windows 11 / Python 3.13 / native Prometheus
- Hypothesis: deliberately slow requests increase the histogram latency metrics.
- Workload: 12 normal, 8 slow, 4 failures (`scripts/generate-traffic.ps1`).
- Prometheus UP: TODO
- Observed metrics: TODO
- Screenshot paths or links: TODO
- Lesson learned: TODO

**Important:** Simulated latency and HTTP 503s are controlled examples, not evidence of actual Kubernetes node resource pressure.
