# KubeGuard AI — Traffic-aware telemetry collection (Stage 1)

**Purpose:** Accumulate real, active-workload telemetry from the existing KubeGuard FastAPI app (`namespace=kubeguard`) without filling the training dataset with idle periods. **This does not retrain or replace the Isolation Forest.** Nothing is marked as trusted normal without later review and incident exclusion.

## What it uses

- Existing local Prometheus port-forward: `127.0.0.1:9090`. No Kubernetes credentials or elevated RBAC needed for this script.
- Existing PromQL feature definitions in `scripts/build_milestone4_dataset.py`.
- Namespace-scoped KubeGuard API metrics and the application's CPU/memory metrics.
- Local SQLite at `data/learning/observations.sqlite3` (inside `.gitignore`). The SQLite file uses permission `0600` and its directory `0700` on Linux.

It never reads Kubernetes Secrets, pod logs, request URLs/bodies, environment variables, or the incident receiver database. No external AI API, network binding, or Cloud connection. No traffic generator is embedded; it observes only requests already reaching the app.

## How the filter works

- Every poll first queries `increase(kubeguard_request_duration_seconds_count[1m])` and `[5m]`.
- If no recent requests, unknown counters, <5 requests / 1m, or <20 / 5m, **no observation row is saved**.
- If core metrics are missing or the app has no available replica, **no observation row is saved**.
- On active traffic, it saves only aggregate numeric metrics as `candidate_unreviewed` (not a ground-truth label). Elevated latency > 250ms or measured errors are saved as `quarantine_*`.
- Missing optional error-rate metrics are preserved as `NULL`, never interpreted as 0.
- Because five-minute lookback windows overlap, rows are correlated; a future training pipeline must group by session, exclude incident windows, and evaluate on held-out sessions.
- Alert detection and availability monitoring still operate separately; **skipping collector data does not mean a workload is healthy**.

## Add the files and run offline tests

On Windows, extract into repo root, commit and push. On Ubuntu:

```bash
cd ~/Projects/kubeguard-ai
git pull --ff-only origin main
source .venv/bin/activate
python -m unittest discover -s tests -p 'test_collect_live_training_data.py' -v
```

Start Prometheus forwarding only if not already running:

```bash
microk8s kubectl port-forward -n monitoring svc/kubeguard-monitoring-kube-prometheus 9090:9090
```

Validate idle in a second Ubuntu terminal (does not create SQLite):

```bash
python scripts/collect_live_training_data.py --samples 1 --dry-run
```

Observe active traffic. In terminal A:

```bash
python scripts/collect_live_training_data.py --samples 0 --interval-sec 30
```

In terminal B, with the existing FastAPI port-forward on `127.0.0.1:18080`, generate a controlled **normal** test workload:

```bash
python3 scripts/generate_milestone4_traffic.py --scenario normal --duration-sec 120 --rps 1 --max-in-flight 4 --output data/milestone4/collector_test_scenarios.csv
```

Terminal A should initially print `SKIPPED_IDLE`/`SKIPPED_LOW_TRAFFIC`, then `ACTIVE_CANDIDATE_UNREVIEWED` with `saved: true`. Stop the collector with Ctrl+C after the traffic experiment. You need not run a slow-traffic test yet.

Check database *only after a sample was saved*:

```bash
python3 - <<'PY'
import sqlite3
p='data/learning/observations.sqlite3'
with sqlite3.connect(p) as db:
    print(db.execute('SELECT review_state, COUNT(*) FROM telemetry_samples GROUP BY review_state').fetchall())
    print(db.execute('SELECT timestamp_utc, avg_latency_seconds, request_count_1m FROM telemetry_samples ORDER BY epoch_seconds DESC LIMIT 5').fetchall())
PY
```

## Security and scope

- No `kubectl exec`, Kubernetes writes, privileges, RBAC change, Ollama connection, or training in this stage.
- `data/` is `.gitignore`d; do not force-add the database or publicize metrics without review.
- Restrict file and directory access. Local users with sufficient OS privileges can still access the data; the collector does not provide encryption at rest or central access control.
- Only `candidate_unreviewed` records can later be considered for trusted normal data, and only **after** excluding known incidents, deployment transitions, unstable periods, and confirming data quality. `quarantine_*` observations are never used for normal fitting by default.
- The current collector only recognizes one app. Multi-project identifiers, project-specific PromQL and access control come later.
