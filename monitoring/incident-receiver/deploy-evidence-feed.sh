#!/usr/bin/env bash
# Controlled upgrade: require incident agent intentionally paused to avoid
# changing receiver during live incident ingestion.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
[[ "$(microk8s kubectl config current-context)" == "microk8s" ]] || { echo 'Wrong kubectl context' >&2; exit 1; }
N=monitoring
microk8s kubectl get secret kubeguard-incident-hmac -n "$N" >/dev/null
microk8s kubectl get pvc kubeguard-incidents -n "$N" >/dev/null
microk8s kubectl get deployment kubeguard-incident-receiver -n "$N" >/dev/null
COUNT="$(microk8s kubectl get deploy kubeguard-incident-agent -n "$N" -o jsonpath='{.spec.replicas}')"
if [[ "$COUNT" != 0 ]]; then
  echo 'Refusing receiver upgrade: first scale incident-agent replicas to 0 (current count is not zero).' >&2
  exit 1
fi
if ! microk8s kubectl get secret kubeguard-evidence-read-hmac -n "$N" >/dev/null 2>&1; then
  KEYFILE="$(mktemp)"
  trap 'rm -f "$KEYFILE"' EXIT
  python3 - "$KEYFILE" <<'PY'
import os,sys
with open(sys.argv[1], 'wb') as stream: stream.write(os.urandom(32))
PY
  microk8s kubectl create secret generic kubeguard-evidence-read-hmac -n "$N" --from-file="key=$KEYFILE"
  rm -f "$KEYFILE"
  trap - EXIT
  echo 'Created separate read-only evidence HMAC Secret (key not printed).'
else
  echo 'Reusing evidence-read HMAC Secret; no rotation.'
fi
microk8s kubectl kustomize monitoring/incident-receiver >/dev/null
microk8s kubectl apply -k monitoring/incident-receiver
microk8s kubectl rollout status deployment/kubeguard-incident-receiver -n "$N" --timeout=180s
echo 'Receiver upgraded. Validate before restoring incident-agent replicas to 1.'
