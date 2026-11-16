#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

[[ "$(microk8s kubectl config current-context)" == "microk8s" ]] || {
  echo "Refusing to run outside the expected microk8s context" >&2
  exit 1
}
microk8s kubectl get namespace monitoring >/dev/null
microk8s kubectl get storageclass microk8s-hostpath >/dev/null
microk8s kubectl get svc -n monitoring kubeguard-monitoring-kube-prometheus >/dev/null
microk8s kubectl get svc -n monitoring kubeguard-incident-receiver >/dev/null
for path in scripts/auto_incident_agent_k8s.py scripts/auto_publish_milestone5_incidents.py scripts/collect_live_training_data.py scripts/build_milestone4_dataset.py; do
  [[ -f "$path" ]] || { echo "Missing $path" >&2; exit 1; }
done

echo "Deploying read-only automatic rule-based incident agent in PREVIEW mode."
microk8s kubectl apply -f monitoring/incident-agent/serviceaccount.yaml
microk8s kubectl create configmap kubeguard-incident-agent-code -n monitoring \
  --from-file=auto_incident_agent_k8s.py=scripts/auto_incident_agent_k8s.py \
  --from-file=auto_publish_milestone5_incidents.py=scripts/auto_publish_milestone5_incidents.py \
  --from-file=collect_live_training_data.py=scripts/collect_live_training_data.py \
  --from-file=build_milestone4_dataset.py=scripts/build_milestone4_dataset.py \
  --dry-run=client -o yaml | microk8s kubectl apply -f -
microk8s kubectl apply -f monitoring/incident-agent/pvc.yaml
microk8s kubectl apply -f monitoring/incident-agent/networkpolicy.yaml
microk8s kubectl apply -f monitoring/incident-agent/deployment.yaml
microk8s kubectl rollout restart -n monitoring deployment/kubeguard-incident-agent
microk8s kubectl rollout status -n monitoring deployment/kubeguard-incident-agent --timeout=180s
printf '\nPreview mode deployed. Check logs:\n'
echo "microk8s kubectl logs -n monitoring deployment/kubeguard-incident-agent -c agent --tail=15"
