# KubeGuard AI — Automatic read-only incident agent (preview-first)

This stage runs continuous *rule-based* application latency monitoring in Kubernetes, without requiring a terminal to launch detection or a local port-forward. It does **not** load, retrain or validate the experimental IsolationForest model. It does **not** run Ollama, touch Kubernetes resources or automatically remediate incidents.

## Safety first

- **Preview mode is the only mode deployed by `monitoring/incident-agent/deploy.sh`.** `--send` is absent from the Deployment manifest. Preview records lifecycle state but sends no alerts.
- Uses the same operational guards as the earlier V4 lab: latency >250ms, 5 requests in 1m, 20 requests in 5m, 2 consecutive high-latency observations to confirm and 2 consecutive sufficiently healthy readings to resolve.
- Idle, missing, insufficient-count, unknown, and unavailable readings never create a high-latency incident or falsely resolve one.
- Uses only three existing aggregate metric families: request counts, average latency, and app available replicas (plus request rate for sanity). The queries are fixed in code, with no arbitrary user-provided PromQL, request data, pod logs, secrets, environment variables, or AI service.
- Confirms an episode once, keeps `pending_payload` in a separate persistent state file, then (if explicitly enabled later) delivers the same payload to the existing incident receiver with retry after restart. Preview and send have separate state files to avoid confusing trial events with real events.
- ServiceAccount has no Role or RoleBinding; its token is not mounted. A NetworkPolicy limits pod traffic to internal DNS, Prometheus and the incident receiver. Network-policy enforcement must still be verified on the cluster.
- **Current incident receiver is an unauthenticated in-cluster HTTP endpoint.** This stage does not solve application-level authentication. Its trust boundary is the internal MicroK8s network. Restricting receiver ingress and adding authentication are future hardening steps. Do not expose this service outside the cluster.
- Single replica, Recreate strategy, 1Gi PVC; state data survives pod replacement while the PVC remains intact. There is no durable off-node backup or storage encryption guarantee.
- The MicroK8s lab image `kubeguard-api:0.2` is reused for convenience, not production supply-chain hardening.

## Add code through Windows/VS Code and test on Ubuntu

Extract the ZIP directly into the existing `kubeguard-ai` repository on Windows, retaining directory paths. The package adds only:

```
scripts/auto_incident_agent_k8s.py
tests/test_auto_incident_agent_k8s.py
monitoring/incident-agent/deployment.yaml
monitoring/incident-agent/deploy.sh
monitoring/incident-agent/networkpolicy.yaml
monitoring/incident-agent/pvc.yaml
monitoring/incident-agent/serviceaccount.yaml
README_AUTO_INCIDENT_AGENT.md
```

On Windows PowerShell:

```powershell
git add scripts/auto_incident_agent_k8s.py tests/test_auto_incident_agent_k8s.py monitoring/incident-agent README_AUTO_INCIDENT_AGENT.md
git commit -m "feat: add automatic preview-only incident agent in microk8s"
git push origin main
```

On Ubuntu (where MicroK8s is installed):

```bash
cd ~/Projects/kubeguard-ai
git pull --ff-only origin main
source .venv/bin/activate
python3 -m unittest discover -s tests -p 'test_auto_incident_agent_k8s.py' -v
```

## Deploy in preview mode

```bash
microk8s kubectl config current-context
microk8s kubectl get pods -n monitoring
bash monitoring/incident-agent/deploy.sh
microk8s kubectl get pods -n monitoring -l app=kubeguard-incident-agent
microk8s kubectl logs -n monitoring deployment/kubeguard-incident-agent -c agent --tail=15
```

At idle, expect a status such as `SKIPPED_IDLE` or `REQUEST_COUNT_UNKNOWN`, with `mode: preview` and no emitted events. A preview `firing` / `resolved` event appears only as `published: false`. **This stage does not change your existing incident database.**

Kubernetes API authorization checks:

```bash
microk8s kubectl auth can-i get secrets -n monitoring --as=system:serviceaccount:monitoring:kubeguard-incident-agent --as-group=system:serviceaccounts --as-group=system:serviceaccounts:monitoring --as-group=system:authenticated
microk8s kubectl auth can-i patch deployments -n monitoring --as=system:serviceaccount:monitoring:kubeguard-incident-agent --as-group=system:serviceaccounts --as-group=system:serviceaccounts:monitoring --as-group=system:authenticated
```

Both should return `no` with RBAC enabled. These tests do not replace a full security review.

## Optional controlled preview of a high-latency episode

Only after observing stable idle logs, keep the existing FastAPI port-forward available on Ubuntu (`18080`) and run a deliberate latency lab scenario, which **must not** enter a trusted-normal ML dataset:

```bash
python3 scripts/generate_milestone4_traffic.py --scenario latency --duration-sec 180 --rps 1 --max-in-flight 4 --output data/milestone4/auto_incident_preview_latency.csv
```

Expected: `ANOMALY_PENDING` followed by `ANOMALY`, with a `firing` preview log and `published: false` after sufficient traffic accumulates. Because the latency query uses a five-minute rolling PromQL window, resolution can take more than five minutes of sustained normal traffic after the slow scenario; low or absent traffic must **not** auto-resolve it.

### Persistent-state check

The preview file is in `/data/agent/preview_state.json` in the dedicated agent PVC. No state file exists until the first successfully processed snapshot. Check that file using your administrator's `kubectl exec` only during lab validation:

```bash
microk8s kubectl exec -n monitoring deployment/kubeguard-incident-agent -c agent -- python -c 'import json; p="/data/agent/preview_state.json"; s=json.load(open(p)); print("mode",s["mode"],"active",bool(s["active_start_at"]),"pending",bool(s["pending_payload"]))'
```

The agent itself has no `pods/exec` permission. Deleting the pod leaves the PVC intact. Do not delete the PVC to restart the agent.

## Mode activation later

No auto-publishing command is provided here. First inspect preview behavior and the receiver's authentication/network access controls. After reviewing this, explicitly decide when to switch on `--send`. Its state is separate from preview, so a prior preview incident will not suddenly be sent. An episode already active at the time of switching is **not reconstructed retroactively**; send mode starts with fresh detection state.

## Cleanup

To stop the agent without removing the persistent data:

```bash
microk8s kubectl scale -n monitoring deployment/kubeguard-incident-agent --replicas=0
```

This does not stop Prometheus, the traffic collector, FastAPI or the incident receiver.
