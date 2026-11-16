# KubeGuard AI — Automatic traffic-aware collection on MicroK8s

This adds a continuously running **read-only telemetry collector**, based on the existing `scripts/collect_live_training_data.py`. The new wrapper is in `scripts/collect_live_training_data_k8s.py`; it uses the existing `build_milestone4_dataset.py` PromQL definitions. It does **not** fit or update the Isolation Forest, publish alerts, access Kubernetes APIs, access Ollama, or generate traffic.

**Previously validated behavior retained:** skip idle / unknown / low traffic; require >=5 requests over the preceding minute **and** >=20 over five minutes; require core metrics; store only active aggregate metrics as `candidate_unreviewed` or `quarantine_*` in SQLite. A candidate is NOT a trusted training label. All values are Prometheus measurements from the existing FastAPI app and Kubernetes workload. No app logs, request bodies/URLs, Secrets or environment variables are collected.

## Files to add to the existing repository

- `scripts/collect_live_training_data_k8s.py` — fixed in-cluster runtime wrapper; imports the original collector and reuses its validated filtering and DB schema.
- `monitoring/traffic-collector/{serviceaccount,pvc,networkpolicy,deployment}.yaml`
- `monitoring/traffic-collector/deploy.sh` — packages the three **existing Python files** into a ConfigMap and applies the Kubernetes resources.
- `tests/test_collect_live_training_data_k8s.py` — offline unit and structural tests.
- `README_AUTO_TRAFFIC_COLLECTOR.md` — this guide.

This package does **not** overwrite any existing files. It reuses the `kubeguard-api:0.2` image already used by the FastAPI app and incident receiver in the *single-node* MicroK8s lab, to avoid introducing a new image-build task. The deployment needs this image to exist in the MicroK8s container runtime (`imagePullPolicy: Never`). This reuse is a lab convenience, not a production-minimal/supply-chain-pinned image design.

## A. Add to GitHub (Windows PowerShell)

Extract the ZIP into the root of the **existing** `kubeguard-ai` repo, preserving directories. Commit only these new source/manifests/docs, not `data/` or `.env`.

```powershell
git add scripts/collect_live_training_data_k8s.py tests/test_collect_live_training_data_k8s.py monitoring/traffic-collector README_AUTO_TRAFFIC_COLLECTOR.md
git commit -m "feat: run traffic-aware collector automatically in microk8s"
git push origin main
```

## B. Pull and run offline tests (Ubuntu VM)

```bash
cd ~/Projects/kubeguard-ai
git pull --ff-only origin main
source .venv/bin/activate
python3 -m unittest discover -s tests -p 'test_collect_live_training_data_k8s.py' -v
```

Expected from this package: 9 passing tests. The previously added collector tests can also be rerun:

```bash
python3 -m unittest discover -s tests -p 'test_collect_live_training_data.py' -v
```

**Preflight:** verify current cluster and monitoring installation before changing Kubernetes:

```bash
microk8s kubectl config current-context
microk8s kubectl get pods -n monitoring
microk8s kubectl get svc -n monitoring kubeguard-monitoring-kube-prometheus
microk8s kubectl get storageclass microk8s-hostpath
```

## C. Install Kubernetes Deployment (Ubuntu VM)

This is an **intentional live cluster change**, not a dry run. It creates a dedicated ServiceAccount, ConfigMap, PVC, NetworkPolicy and Deployment **only in the existing `monitoring` namespace**.

```bash
bash monitoring/traffic-collector/deploy.sh
```

The script validates the current context and expected Service/StorageClass, installs a source ConfigMap, applies YAML, restarts the collector Deployment so code changes are taken into account, and waits for pod readiness. It does **not** touch the existing FastAPI, Prometheus, incident receiver, detector, or SQLite incident database.

View the running application and its logs:

```bash
microk8s kubectl get deploy,pods,pvc,networkpolicy -n monitoring
microk8s kubectl logs -n monitoring deployment/kubeguard-traffic-collector -c collector --tail=20
microk8s kubectl logs -n monitoring deployment/kubeguard-traffic-collector -c collector -f
```

While app traffic is idle, logs should show `SKIPPED_IDLE` (or `SKIPPED_UNKNOWN_TRAFFIC` while counters are unavailable), with `"saved": false`. The process **keeps running** even while idle, polls every 30 seconds, and does not create the database until an active eligible sample appears. `kubectl rollout status` proves the container started, NOT necessarily that Prometheus queries work. Confirm `status` is not `ERROR` in logs.

## D. Verify automatic collection with real application traffic

You **do not** launch the collector script manually now. Leave the Deployment running. To create a controlled lab load, keep the FastAPI port-forward from the Ubuntu VM if needed:

```bash
microk8s kubectl port-forward -n kubeguard svc/kubeguard-api 18080:8000
```

In another Ubuntu terminal:

```bash
cd ~/Projects/kubeguard-ai
source .venv/bin/activate
python3 scripts/generate_milestone4_traffic.py \
  --scenario normal --duration-sec 180 --rps 1 --max-in-flight 4 \
  --output data/milestone4/k8s_auto_collector_test.csv
```

Follow the collector logs in the first terminal or rerun `kubectl logs`. After the counters and core metrics become available, expect `ACTIVE_CANDIDATE_UNREVIEWED` with `"saved": true` without starting the collector yourself. Stop the traffic generator and allow request count windows to drain: later observations should be skipped. The generated traffic is controlled lab traffic; **do not treat these observations as independently verified training data**.

To inspect stored counts, an **administrator** can optionally run a read-only SQLite query using kubectl exec (the **collector ServiceAccount has no permission or token to exec**):

```bash
microk8s kubectl exec -n monitoring deployment/kubeguard-traffic-collector -c collector -- \
  python -c 'import sqlite3; c=sqlite3.connect("file:/data/learning/observations.sqlite3?mode=ro",uri=True); print(c.execute("SELECT review_state, count(*) FROM telemetry_samples GROUP BY review_state").fetchall()); c.close()'
```

Only run this after the logs show `"saved": true`; before that the database intentionally may not exist. The database is stored **inside a PVC**, not in `~/Projects/kubeguard-ai/data/learning` on the Ubuntu host.

Verify the no-RBAC-grants design:

```bash
microk8s kubectl auth can-i get secrets -n monitoring --as=system:serviceaccount:monitoring:kubeguard-traffic-collector
microk8s kubectl auth can-i create pods/exec -n monitoring --as=system:serviceaccount:monitoring:kubeguard-traffic-collector
microk8s kubectl auth can-i update deployments -n monitoring --as=system:serviceaccount:monitoring:kubeguard-traffic-collector
```

Each should print `no`. These impersonation tests are issued by your operator account; the collector itself cannot use the Kubernetes API because token auto-mounting is disabled.

## E. Restart / stop / troubleshoot

To test that Kubernetes restarts the process, you may deliberately restart the Deployment (SQLite PVC is retained):

```bash
microk8s kubectl rollout restart -n monitoring deployment/kubeguard-traffic-collector
microk8s kubectl rollout status -n monitoring deployment/kubeguard-traffic-collector
microk8s kubectl logs -n monitoring deployment/kubeguard-traffic-collector -c collector --tail=10
```

To **pause collection without deleting any stored data**:

```bash
microk8s kubectl scale -n monitoring deployment/kubeguard-traffic-collector --replicas=0
```

To resume:

```bash
microk8s kubectl scale -n monitoring deployment/kubeguard-traffic-collector --replicas=1
```

To update collector code after a later source edit, run `bash monitoring/traffic-collector/deploy.sh` again. **Note:** it enforces the desired single replica, so do not rerun this installer when you intend to leave collection paused.

Troubleshooting:

- `ImagePullBackOff` / `ErrImageNeverPull`: inspect the existing MicroK8s `kubeguard-api:0.2` image in the same runtime/node. Do not pull a random replacement image.
- `CreateContainerConfigError`: check the generated ConfigMap `kubeguard-traffic-collector-code`.
- `Init:Error`: check `kubectl logs -n monitoring deployment/kubeguard-traffic-collector -c prepare-storage`; the root **init only** adjusts PVC directory ownership, because MicroK8s hostpath volumes may be root-owned. Main process runs as user 10001 with no added capabilities.
- `ERROR` statuses: confirm Prometheus Service endpoints, the pod's DNS access and NetworkPolicy behavior. The script uses the exact internal Service `kubeguard-monitoring-kube-prometheus.monitoring.svc.cluster.local:9090` and does not use a port-forward. NetworkPolicy enforcement depends on cluster CNI. **Do not turn off network restrictions to hide a networking error**; diagnose the selected namespace/DNS endpoint.
- No `saved: true`: the app may be idle, recent request counts may be below the thresholds, or required metrics may be unavailable. That is expected fail-closed behavior.

## Security and limitations

- One replica, `Recreate` strategy, persistent `microk8s-hostpath` PVC, no automatic training or model promotion, no alert publishing, no `pods/exec` or Secret access by the collector.
- Restricted non-root main container, read-only root filesystem, dropped capabilities, runtime default seccomp, no automounted Kubernetes credential, private database directory 0700/file 0600. An init container runs as root **only to prepare hostpath PVC ownership** and has limited `CHOWN`/`FOWNER` capabilities; production storage should use a provisioner that supports unprivileged ownership preparation.
- NetworkPolicy denies inbound connections and permits outbound traffic only to kube-system namespace on DNS ports and monitoring namespace on TCP 9090. Depending on the CNI, enforcement may differ; this is not a guarantee against a compromised node or cluster administrator.
- Prometheus HTTP within the cluster is not TLS-encrypted here; it is scoped to the cluster network, but for a real multi-node or untrusted network deployment use authenticated TLS/mTLS, pinned images and stronger storage protection.
- PVC is tied to MicroK8s hostpath storage on the VM and is **not a backup**. Plan exports/backups and retention before using real production telemetry.
- The Deployment starts automatically as long as MicroK8s and the Ubuntu VM are running; it does not start a powered-off VM.
- For multi-application support, build application-scoped service identities, RBAC, retention controls and separate/trustworthy training datasets later.

No manual ML retraining, Ollama integration, or incident lifecycle automation is changed by this package.
