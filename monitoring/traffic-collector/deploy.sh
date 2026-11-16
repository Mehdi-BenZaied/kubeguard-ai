#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

for required in scripts/collect_live_training_data.py scripts/build_milestone4_dataset.py scripts/collect_live_training_data_k8s.py; do
  if [[ ! -f "$required" ]]; then
    echo "Missing source file: $required" >&2
    exit 1
  fi
done

# Do not create resources in the wrong cluster or silently choose a namespace.
echo "Current Kubernetes context:"
microk8s kubectl config current-context
microk8s kubectl get namespace monitoring >/dev/null
microk8s kubectl get storageclass microk8s-hostpath >/dev/null
microk8s kubectl get service -n monitoring kubeguard-monitoring-kube-prometheus >/dev/null

echo "Installing dedicated ServiceAccount (no Role or RoleBinding)."
microk8s kubectl apply -f monitoring/traffic-collector/serviceaccount.yaml

# Keep source single-sourced in scripts/. ConfigMap updated only by this script.
# No code files contain secrets. Do NOT put data/, .env, or other files here.
echo "Publishing collector Python code as a ConfigMap."
microk8s kubectl create configmap kubeguard-traffic-collector-code \
  --namespace monitoring \
  --from-file=collect_live_training_data.py=scripts/collect_live_training_data.py \
  --from-file=build_milestone4_dataset.py=scripts/build_milestone4_dataset.py \
  --from-file=collect_live_training_data_k8s.py=scripts/collect_live_training_data_k8s.py \
  --dry-run=client -o yaml | microk8s kubectl apply -f -

echo "Applying PVC, Deployment and restricted network policy."
microk8s kubectl apply -f monitoring/traffic-collector/pvc.yaml
microk8s kubectl apply -f monitoring/traffic-collector/networkpolicy.yaml
microk8s kubectl apply -f monitoring/traffic-collector/deployment.yaml

# ConfigMap content changes require pod restart, even if the Deployment is identical.
microk8s kubectl rollout restart -n monitoring deployment/kubeguard-traffic-collector
microk8s kubectl rollout status -n monitoring deployment/kubeguard-traffic-collector --timeout=180s

echo "Installed. Verify the collector's actual connectivity and decisions:"
echo "  microk8s kubectl logs -n monitoring deployment/kubeguard-traffic-collector -c collector --tail=20"
