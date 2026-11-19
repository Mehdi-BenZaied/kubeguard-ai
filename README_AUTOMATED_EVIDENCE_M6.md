# KubeGuard AI — Milestone 6: automated, sanitized incident evidence

**Status: lab package, deploy only after the tests and a VM snapshot. No LLM integration or remediation.**

This change upgrades the existing secured receiver with a separate, authenticated **read-only incident feed** and adds an isolated automatic evidence collector. It **does not** replay the existing 50 test incident events. It begins collecting on subsequent newly recorded firing/resolved events.

The collector has **no Kubernetes API credentials**, `kubectl`, `pods/exec`, arbitrary Kubernetes events, application logs, Secret API access, shell commands, configurable PromQL, external HTTP destinations, or LLM access. It uses hardcoded internal service addresses and only numeric, aggregated Prometheus metrics. The read-only evidence key cannot sign the separate POST `/alerts` protocol. The receiver keeps its existing `kubeguard-incident-hmac` key and SQLite PVC.

## What the collector saves

A separate 1Gi PVC `kubeguard-evidence` stores `/data/evidence/cursor.json` and `incident_<event-id>.json` files with permissions 0600 under a 0700 directory. The payload includes an opaque incident ID, lifecycle status, timestamps, numeric event values, fixed-field numeric Prometheus samples and explicit evidence gaps. No raw labels, request bodies/paths, headers, alert annotations, pod names, Kubernetes events, or secrets are returned by the feed or included in the report. An event causes one evidence bundle; a resolution creates a second bundle with its own time window.

The collector polls every 30 seconds. On the **very first** poll it saves the newest existing event ID as the starting cursor and writes **no** evidence. On subsequent polls, it reads events in batches of 20, saves each report durably, then updates its cursor. If a report cannot be written, the cursor does not advance. Missing data is represented as missing, never 0; if all Prometheus requests fail, the collector retries later without advancing its cursor. If the cursor is invalid or disappears, collection halts rather than silently skipping records.

The collector uses the existing fixed aggregation queries for available replicas, request rate, mean/p95 latency, error percentage, CPU millicores, memory MiB and CPU throttle percentage, plus app-specific running-pod and restart totals. Restart totals are cumulative counters, not an active-crash diagnosis. The current metrics do not prove an incident's root cause.

## Security boundaries and limitations

- The receiver retains the **existing separate POST HMAC credential**. The new read-only GET `/evidence/feed` uses its own random 32-byte HMAC Secret `kubeguard-evidence-read-hmac`; it cannot authenticate POST `/alerts`.
- The receiver GET endpoint returns **only** fixed, minimized event metadata and numeric values; it never returns `alert_json` or raw annotations. An unsigned GET is rejected with HTTP 401. The endpoint is only accessible to the evidence-collector Pod according to the receiver NetworkPolicy. The existing incident-agent Pod retains its POST access.
- These are **internal HTTP**, not mTLS or TLS. HMAC authenticates requests but does **not** provide transport confidentiality or authenticate the response to an on-path attacker. Kubernetes NetworkPolicy depends on Calico enforcement, can be bypassed by privileged host-level access, and label-based authorization needs admission control to prevent spoofed pod labels. Further hardening is needed before production.
- A separate Secret mounted in the collector is accessible to that Pod by design, even if its ServiceAccount has `get secrets: no`. Neither collector nor receiver mounts a Kubernetes API token.
- MicroK8s `microk8s-hostpath` PVCs are node-local and do not provide automatic backup/encryption. Evidence retention and disk usage are not bounded by time; a future retention/backup policy is necessary. Do not paste the evidence JSON or credential files into public GitHub.
- The old manual `scripts/collect_milestone6_evidence.py` remains as historical lab code: it uses administrator-side `kubectl exec` and can expose arbitrary Kubernetes event messages. **Do not reuse that script in the automated AI pipeline.**

## Included files

```text
monitoring/incident-receiver/receiver.py                 (updated)
monitoring/incident-receiver/deployment.yaml              (updated)
monitoring/incident-receiver/networkpolicy.yaml           (updated)
monitoring/incident-receiver/deploy-evidence-feed.sh      (new)
monitoring/evidence-collector/deploy.sh                    (new)
monitoring/evidence-collector/deployment.yaml              (new)
monitoring/evidence-collector/networkpolicy.yaml           (new)
monitoring/evidence-collector/pvc.yaml                     (new)
monitoring/evidence-collector/serviceaccount.yaml          (new)
scripts/collect_incident_evidence_k8s.py                  (new)
tests/test_evidence_collector_k8s.py                      (new)
README_AUTOMATED_EVIDENCE_M6.md                           (new)
```

No credentials, existing SQLite data, or model files are included. Preserve all the repository's other files, including the existing `monitoring/incident-receiver/kustomization.yaml`, `service.yaml` and `pvc.yaml`.

## Step 1 — Windows: review and push code (NO cluster actions)

Extract ZIP into the root of your existing Windows `kubeguard-ai` repository, preserving subfolders. Review the diff before committing. From VS Code PowerShell:

```powershell
git status --short
git diff -- monitoring/incident-receiver

git add monitoring/incident-receiver/receiver.py monitoring/incident-receiver/deployment.yaml monitoring/incident-receiver/networkpolicy.yaml monitoring/incident-receiver/deploy-evidence-feed.sh monitoring/evidence-collector scripts/collect_incident_evidence_k8s.py tests/test_evidence_collector_k8s.py README_AUTOMATED_EVIDENCE_M6.md

git commit -m "feat: collect authenticated incident evidence without Kubernetes API access"
git push origin main
```

## Step 2 — Ubuntu: offline tests and preflight

```bash
cd ~/Projects/kubeguard-ai
git pull --ff-only origin main
source .venv/bin/activate
python3 -m unittest discover -s tests -p 'test_secure_incident_receiver.py' -v
python3 -m unittest discover -s tests -p 'test_evidence_collector_k8s.py' -v
bash -n monitoring/incident-receiver/deploy-evidence-feed.sh monitoring/evidence-collector/deploy.sh
microk8s kubectl kustomize monitoring/incident-receiver >/dev/null && echo 'Kustomize OK'
```

The original 16 secure-receiver tests should still pass; 15 new offline tests passed in the isolated package test. Test the actual repository before touching the cluster.

### Preflight — no active incident, no pending outbox

```bash
microk8s kubectl exec -n monitoring deployment/kubeguard-incident-agent -c agent -- python -c '
import json
s=json.load(open("/data/agent/send_state.json"))
print("Active:",bool(s["active_start_at"]),"Pending:",bool(s["pending_payload"]))
'
```

If either value is True, **do not pause** the agent. Let the incident finish, or preserve its state and plan a separate maintenance window. Take a **VM snapshot** before the receiver upgrade; the original `kubeguard-incidents` PVC must remain intact.

## Step 3 — Controlled receiver upgrade (brief interruption of detection)

The receiver's current Deployment uses the live HMAC key. Upgrading it restarts the receiver and changes ingress policy. To avoid changing it under an active incident, **pause the agent** temporarily; do not delete the Deployment or its PVC:

```bash
microk8s kubectl scale deployment/kubeguard-incident-agent -n monitoring --replicas=0
bash monitoring/incident-receiver/deploy-evidence-feed.sh
microk8s kubectl get pod -n monitoring -l app=kubeguard-incident-receiver
microk8s kubectl logs -n monitoring deployment/kubeguard-incident-receiver -c receiver --tail=10
```

The script explicitly refuses the upgrade if agent replicas != 0. It generates a **new separate** read-only HMAC Secret (or reuses it if already present), then runs `kubectl apply -k`, and waits for the receiver rollout. It preserves the original SQLite PVC and original HMAC Secret. It never prints secret bytes.

Test that the **read endpoint** cannot be called unsigned. Using administrator `kubectl exec` only for validation:

```bash
microk8s kubectl exec -n monitoring deployment/kubeguard-incident-receiver -c receiver -- python -c '
from urllib.request import Request,urlopen
from urllib.error import HTTPError
try:
    urlopen(Request("http://127.0.0.1:8081/evidence/feed",method="GET"),timeout=4)
except HTTPError as e:
    print("Unsigned evidence response:",e.code)
'
```

Expected: `Unsigned evidence response: 401`.

After the upgraded receiver is ready, **restore your existing send-mode agent** by scaling it up (do not run its `deploy.sh`, which reverts the base manifest to preview):

```bash
microk8s kubectl scale deployment/kubeguard-incident-agent -n monitoring --replicas=1
microk8s kubectl rollout status deployment/kubeguard-incident-agent -n monitoring
microk8s kubectl get deployment kubeguard-incident-agent -n monitoring -o jsonpath='{.spec.template.spec.containers[0].args}'; echo
```

Expected args: `["--send","--samples","0","--interval-sec","30"]`. If the receiver rollout fails, leave the agent paused while examining the pod errors, or explicitly roll back the receiver; do not proceed blindly. No normal incident monitoring occurs while the agent is paused.

## Step 4 — Deploy evidence-only collector

```bash
bash monitoring/evidence-collector/deploy.sh
microk8s kubectl get pod -n monitoring -l app=kubeguard-evidence-collector
microk8s kubectl logs -n monitoring deployment/kubeguard-evidence-collector -c collector --tail=10
```

Expected initial status: `BOOTSTRAPPED` once, followed by `NO_NEW_INCIDENTS`. This intentionally does **not** backfill your existing incident history; it starts from the latest event currently in SQLite.

Verify its token-free Kubernetes identity:

```bash
microk8s kubectl auth can-i get secrets -n monitoring --as=system:serviceaccount:monitoring:kubeguard-evidence-collector --as-group=system:serviceaccounts --as-group=system:serviceaccounts:monitoring --as-group=system:authenticated
```

Expected `no` (this is independent of the mounted read-only HMAC key).

Only after reviewing these logs, generate one controlled latency incident and recovery as in Milestone 5, then check the collector logs for `EVIDENCE_SAVED`. To count files *without outputting their contents*:

```bash
microk8s kubectl exec -n monitoring deployment/kubeguard-evidence-collector -c collector -- python -c '
from pathlib import Path
p=Path("/data/evidence")
print("Evidence files:",len(list(p.glob("incident_*.json"))))
print("Cursor exists:",(p/"cursor.json").is_file())
'
```

There is **no Ollama connection** or automatic remediation in this stage. Review evidence locally before connecting your Windows RTX GPU inference machine. Later stages will add audited access and retention plus a strict AI-facing sanitized schema.

## Restore / rollback reminders

- Do not delete PVCs (`kubeguard-incidents`, `kubeguard-incident-agent-state`, `kubeguard-evidence`).
- Do not disable RBAC, reset MicroK8s, print keys, or commit credentials to Git.
- To stop collecting new evidence without deleting saved data: `microk8s kubectl scale deploy/kubeguard-evidence-collector -n monitoring --replicas=0`.
- Receiver rollback must deliberately restore the earlier receiver code, Deployment and ingress rules as one set. The HMAC key/SQLite PVC need not be deleted. An older receiver may not understand the new GET endpoint; the collector should be paused if the endpoint is removed.
