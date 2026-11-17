#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
CTX="$(microk8s kubectl config current-context)"
[[ "$CTX" == microk8s ]] || { echo "Unexpected context: $CTX" >&2; exit 1; }
microk8s kubectl get namespace monitoring >/dev/null
microk8s kubectl get deployment -n monitoring kubeguard-incident-receiver >/dev/null
# Never replace the receiver while an automated sender is active.
AGENT_ARGS="$(microk8s kubectl get deployment -n monitoring kubeguard-incident-agent -o jsonpath='{.spec.template.spec.containers[?(@.name=="agent")].args}')"
if [[ " $AGENT_ARGS " == *--send* ]]; then
  echo "Refusing receiver migration while incident agent is in send mode" >&2
  exit 1
fi
SECRET=kubeguard-incident-hmac
if ! microk8s kubectl get secret "$SECRET" -n monitoring >/dev/null 2>&1; then
  echo "Creating a new per-cluster random HMAC key in a Kubernetes Secret (key not printed)."
  TMP="$(mktemp)"
  trap 'rm -f "$TMP"' EXIT
  python3 - "$TMP" <<'PY'
import os, sys
with open(sys.argv[1], "wb") as f:
    f.write(os.urandom(32))
PY
  microk8s kubectl create secret generic "$SECRET" -n monitoring --from-file="key=$TMP"
  rm -f "$TMP"
  trap - EXIT
else
  echo "Reusing existing HMAC Secret (not rotating key)."
fi
echo "Applying receiver with HMAC authentication and restricted ingress."
microk8s kubectl apply -k monitoring/incident-receiver
microk8s kubectl rollout status -n monitoring deployment/kubeguard-incident-receiver --timeout=180s
echo "Receiver upgraded; existing incidents PVC was not deleted."
echo "Leave the agent in preview mode. Next: bash monitoring/incident-agent/deploy.sh"
