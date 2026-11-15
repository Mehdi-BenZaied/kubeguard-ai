# KubeGuard AI — Milestone 6 evidence collector

Install these files in the existing `kubeguard-ai` repository:

- `scripts/collect_milestone6_evidence.py`
- `tests/test_collect_milestone6_evidence.py`

The collector **only reads** existing incident SQLite records, historical Prometheus metrics, and current Kubernetes status/events. It writes two local files. It never posts alerts, changes any Kubernetes resource, collects application logs/secrets, or performs AI diagnosis.

Requirements: Ubuntu VM; current MicroK8s access; Prometheus port-forward on `127.0.0.1:9090`; existing receiver `deployment/kubeguard-incident-receiver` in namespace `monitoring`. Run from the repository root with the normal virtualenv active. The script imports `PROMQL` from the existing `scripts/build_milestone4_dataset.py`.

```bash
source .venv/bin/activate
python -m unittest discover -s tests -p 'test_collect_milestone6_evidence.py' -v
microk8s kubectl port-forward -n monitoring svc/kubeguard-monitoring-kube-prometheus 9090:9090
```

In a second terminal:

```bash
cd ~/Projects/kubeguard-ai
source .venv/bin/activate
python scripts/collect_milestone6_evidence.py \
  --episode-start 2026-11-15T18:46:13Z
```

Omit `--episode-start` to select the latest stored `KubeGuardAIHighLatency` firing episode. The collector finds the corresponding resolved event using the same fingerprint and `starts_at`. No receiver port-forward is needed: the SQLite database is queried read-only through `microk8s kubectl exec`.

Outputs:

- `data/milestone6/incident_evidence_<timestamp>.json` — machine-readable time series, incident metadata, current deployment/pods/events, warnings.
- `data/milestone6/incident_evidence_<timestamp>.md` — concise human-readable evidence summary.

Prometheus retention is currently 24 hours in this lab: collect incident evidence **before** historical samples are removed. The current deployment/pod snapshot is NOT a reconstruction of the incident-time state; Kubernetes events can expire. Missing error-rate or throttle series are reported as unavailable, never silently converted to zero. Prometheus p95 is a histogram-derived estimate, not actual measured HTTP p95.

Inspect the files locally before sharing them or using them as AI prompts: event descriptions and resource names may contain operational information. Do not commit collected evidence without reviewing it.
