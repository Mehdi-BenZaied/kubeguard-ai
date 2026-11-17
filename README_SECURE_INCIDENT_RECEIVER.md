# KubeGuard AI — Secure incident receiver (preparation for send mode)

## Why this change

The MicroK8s `kubeguard-incident-receiver` Service is `ClusterIP`, but it had **no ingress NetworkPolicy** and accepted unauthenticated POSTs. A `ClusterIP` does not authenticate callers.

The package secures the **existing** receiver. It does **not** enable incident publishing; `kubeguard-incident-agent` remains in PREVIEW mode and your existing training/incident SQLite PVCs stay intact.

## Security behavior

- New receiver-specific NetworkPolicy: ingress only from pods labeled `app=kubeguard-incident-agent` in namespace `monitoring` on TCP 8081; receiver egress denied. Actual enforcement depends on the cluster CNI.
- Receiver authenticates POST `/alerts` using `HMAC-SHA256` over a timestamp and the **exact request bytes**, with a 60-second clock window. Rejects missing/invalid signatures with HTTP 401 and stores nothing.
- Each retry gets a fresh signed timestamp; existing episode fingerprint + lifecycle status + episode timestamps still deduplicate events in SQLite.
- A Kubernetes Secret named `kubeguard-incident-hmac` carries a 32-byte random key, created on the Ubuntu VM by the deployment script. It is not committed to Git. Only the two selected containers mount it as read-only files; no key is put in environment variables.
- Receiver accepts only KubeGuard's known `KubeGuardAIHighLatency` / `namespace=kubeguard` / `v4` lifecycle event shape. Non-numeric metrics, extra labels or fields are rejected. It stores only fixed metadata and bounded numeric measurements; raw annotations are discarded.
- The service still responds to GET `/health` for Kubernetes readiness checks. Its existing SQLite database and schema are preserved.
- ServiceAccounts have no Roles/RoleBindings and do not mount Kubernetes API tokens. Agent remains preview-only; no ML, Ollama, pod exec, or remediation.

**Important compatibility change:** generic Grafana webhooks, manually posted events, and other alert types sent to `/alerts` will now be rejected. If Grafana is configured to post directly to this receiver, migrate it to a separately authenticated integration before this rollout. This step intentionally dedicates the receiver to the KubeGuard incident agent.

**Threat boundaries:** HMAC provides message authenticity/integrity, **not traffic encryption**. Cluster HTTP traffic is not TLS-protected. Kubernetes Secrets are not automatically encrypted at rest, and administrators/compromised nodes may still access them. NetworkPolicy may be bypassed by privileged host-level traffic and may not stop DNS tunneling; further hardening (mTLS, receiver authentication for all writers, backups, key rotation, monitoring, host/CNI review) is necessary for production.

## Step 1 — Windows / GitHub

Extract the ZIP into the repository root. Review the changed files (`receiver.py`, its Deployment and Kustomization, incident-agent Deployment and deployment script); do not replace your SQLite database files.

```powershell
git status --short
git add monitoring/incident-receiver monitoring/incident-agent/deployment.yaml monitoring/incident-agent/deploy.sh scripts/secure_incident_agent_k8s.py tests/test_secure_incident_receiver.py README_SECURE_INCIDENT_RECEIVER.md
git commit -m "feat: authenticate incident receiver and isolate notification traffic"
git push origin main
```

## Step 2 — Ubuntu / offline verification

```bash
cd ~/Projects/kubeguard-ai
git pull --ff-only origin main
source .venv/bin/activate
python3 -m unittest discover -s tests -p 'test_secure_incident_receiver.py' -v
python3 -m unittest discover -s tests -p 'test_auto_incident_agent_k8s.py' -v
bash -n monitoring/incident-receiver/deploy-secure.sh monitoring/incident-agent/deploy.sh
sudo grep '^--authorization-mode=' /var/snap/microk8s/current/args/kube-apiserver
```

Expect `RBAC,Node` for the authorization mode. Take an Ubuntu VM snapshot first: the receiver Deployment and the in-cluster incident-ingestion endpoint will change. The persistent `kubeguard-incidents` PVC is **not deleted**.

## Step 3 — Receiver upgrade FIRST

Confirm the incident agent is in preview (no `--send` in Deployment args):

```bash
microk8s kubectl get deployment kubeguard-incident-agent -n monitoring \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="agent")].args}'; echo
```

Then:

```bash
bash monitoring/incident-receiver/deploy-secure.sh
microk8s kubectl get pods -n monitoring -l app=kubeguard-incident-receiver
microk8s kubectl get networkpolicy -n monitoring kubeguard-incident-receiver-isolation
microk8s kubectl logs -n monitoring deployment/kubeguard-incident-receiver -c receiver --tail=10
```

`deploy-secure.sh` fails if the agent currently uses `--send`. It creates the signing key only when the Secret doesn't already exist; it never prints or rotates a live key. `kubectl apply -k` updates the hashed receiver ConfigMap while preserving the original Service and PVC.

Test an **unsigned** request locally in the receiver pod; expected HTTP 401, with no inserted event:

```bash
microk8s kubectl exec -n monitoring deployment/kubeguard-incident-receiver -c receiver -- \
  python -c 'import urllib.request,urllib.error; r=urllib.request.Request("http://127.0.0.1:8081/alerts",data=b"{}",method="POST"); exec("try:\n urllib.request.urlopen(r,timeout=4)\nexcept urllib.error.HTTPError as e:\n print(\"Unsigned response:\",e.code)")'
```

## Step 4 — Upgrade the agent while PREVIEW stays on

```bash
bash monitoring/incident-agent/deploy.sh
microk8s kubectl rollout status -n monitoring deployment/kubeguard-incident-agent
microk8s kubectl logs -n monitoring deployment/kubeguard-incident-agent -c agent --tail=10
```

Check RBAC for each ServiceAccount:

```bash
for sa in kubeguard-incident-receiver kubeguard-incident-agent; do
  echo "Checking $sa"
  microk8s kubectl auth can-i get secrets -n monitoring \
    --as="system:serviceaccount:monitoring:$sa" \
    --as-group=system:serviceaccounts \
    --as-group=system:serviceaccounts:monitoring \
    --as-group=system:authenticated
done
```

Expected both `no`. The key-file mount is a **different access mechanism** from API RBAC; the two pods can read their own mounted notification key even with `can-i get secrets: no`.

**Do not enable `--send` yet.** After reviewing the unauthorized-request result, service health, and RBAC checks, plan a controlled send-mode activation and verify actual `firing` / `resolved` delivery and durable retries.

## Rollback notes

Do not use `microk8s disable rbac`, delete PVCs, or copy the HMAC key into public files. If the receiver rollout fails, leave the agent preview-only, inspect pod events/logs, and restore the prior receiver Deployment and receiver.py from your Git history as an explicit rollback. The new receiver ingress NetworkPolicy and Secret must be deliberately reconciled during rollback, not deleted indiscriminately. Data already collected remains on the PVC.
