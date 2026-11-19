#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
[[ "$(microk8s kubectl config current-context)" == "microk8s" ]] || { echo 'Wrong context' >&2; exit 1; }
microk8s kubectl get secret kubeguard-evidence-read-hmac -n monitoring >/dev/null
microk8s kubectl get deploy kubeguard-incident-receiver -n monitoring >/dev/null
microk8s kubectl apply -f monitoring/evidence-collector/serviceaccount.yaml
microk8s kubectl create configmap kubeguard-evidence-code -n monitoring \
  --from-file=collect_incident_evidence_k8s.py=scripts/collect_incident_evidence_k8s.py \
  --from-file=build_milestone4_dataset.py=scripts/build_milestone4_dataset.py \
  --dry-run=client -o yaml | microk8s kubectl apply -f -
microk8s kubectl apply -f monitoring/evidence-collector/pvc.yaml
microk8s kubectl apply -f monitoring/evidence-collector/networkpolicy.yaml
microk8s kubectl apply -f monitoring/evidence-collector/deployment.yaml
microk8s kubectl rollout status deployment/kubeguard-evidence-collector -n monitoring --timeout=180s
echo 'Evidence-only collector deployed. First run bookmarks history, does not replay old events.'
