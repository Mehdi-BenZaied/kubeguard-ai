#!/usr/bin/env python3
"""Automatic KubeGuard *rule-based* incident lifecycle in MicroK8s.

Preview-only by default. Explicit --send publishes events to the fixed in-cluster
incident receiver. This is NOT a machine-learning inference agent: it uses the
V4 operational latency threshold (250 ms), sample thresholds (5/1m, 20/5m),
two consecutive anomaly readings, two consecutive healthy recovery readings,
and the previously tested restart-aware outbox/state-machine module.

No Kubernetes client, RBAC credentials, shell, application logs, sensitive
labels, request paths or bodies are involved. Only pre-defined aggregate PromQL
queries are sent to the existing internal Prometheus Service.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, build_opener, ProxyHandler

import auto_publish_milestone5_incidents as lifecycle
import collect_live_training_data as telemetry
from build_milestone4_dataset import PROMQL

PROMETHEUS = "http://kubeguard-monitoring-kube-prometheus.monitoring.svc.cluster.local:9090"
RECEIVER = "http://kubeguard-incident-receiver.monitoring.svc.cluster.local:8081/alerts"
STATE_DIR = Path("/data/agent")
THRESHOLD_SECONDS = 0.25
MIN_REQUESTS_1M = 5.0
MIN_REQUESTS_5M = 20.0
REQUIRED_VIOLATIONS = 2
REQUIRED_RECOVERIES = 2
MAX_SNAPSHOT_GAP_SECONDS = 120
REQUEST_COUNT = (
    'sum(increase(kubeguard_request_duration_seconds_count'
    '{namespace="kubeguard"}[%s]))'
)


def _nonnegative(value: object) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and value >= 0)


def detect_once(epoch: int, consecutive: int, query=telemetry.query_instant) -> tuple[dict, int]:
    """Produce a conservative snapshot for lifecycle.step, using only allowed metrics.

    No events are generated for idle, low-traffic or unknown/missing evidence.
    Unavailability is reported as a status but is NOT a high-latency event.
    """
    c1 = query(PROMETHEUS, REQUEST_COUNT % "1m", epoch)
    c5 = query(PROMETHEUS, REQUEST_COUNT % "5m", epoch)
    replicas = query(PROMETHEUS, PROMQL["available_replicas"], epoch)
    enough = (_nonnegative(c1) and _nonnegative(c5)
              and c1 >= MIN_REQUESTS_1M and c5 >= MIN_REQUESTS_5M)
    snapshot = {
        "timestamp_utc": datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "status": "INSUFFICIENT_DATA",
        "available_replicas": replicas,
        "metrics": {"avg_latency_seconds": None, "request_rate_per_s": None},
        "latency_threshold_seconds": THRESHOLD_SECONDS,
        "baseline_anomaly": None,
        "sample_count_sufficient": bool(enough),
        "request_count_1m": c1,
        "request_count_5m": c5,
        "consecutive_latency_violations": 0,
        "required_latency_violations": REQUIRED_VIOLATIONS,
    }
    if _nonnegative(replicas) and replicas < 1:
        snapshot["status"] = "UNAVAILABLE"
        return snapshot, 0
    if not _nonnegative(replicas):
        return snapshot, 0
    if not (_nonnegative(c1) and _nonnegative(c5)):
        snapshot["status"] = "REQUEST_COUNT_UNKNOWN"
        return snapshot, 0
    if not enough:
        snapshot["status"] = "SKIPPED_IDLE" if c1 == 0 else "LOW_SAMPLE_COUNT"
        return snapshot, 0

    latency = query(PROMETHEUS, PROMQL["avg_latency_seconds"], epoch)
    rate = query(PROMETHEUS, PROMQL["request_rate_per_s"], epoch)
    snapshot["metrics"] = {"avg_latency_seconds": latency, "request_rate_per_s": rate}
    if not _nonnegative(latency) or not _nonnegative(rate) or rate <= 0:
        return snapshot, 0
    exceeds = latency > THRESHOLD_SECONDS
    snapshot["baseline_anomaly"] = exceeds
    count = consecutive + 1 if exceeds else 0
    snapshot["consecutive_latency_violations"] = count
    snapshot["status"] = (
        "ANOMALY" if exceeds and count >= REQUIRED_VIOLATIONS else
        "ANOMALY_PENDING" if exceeds else "NORMAL"
    )
    return snapshot, count


def send_payload(payload: dict) -> None:
    """POST only to a compiled-in internal Service; deny redirects and proxies."""
    body = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode()
    req = Request(RECEIVER, data=body, headers={"Content-Type": "application/json"}, method="POST")
    opener = build_opener(ProxyHandler({}), telemetry.DenyRedirects())
    with opener.open(req, timeout=8) as response:
        if response.status != 200:
            raise RuntimeError("Incident receiver did not acknowledge the event")
        response.read(512)


def deliver_pending(state: dict, state_file: Path, send: bool, publisher=send_payload) -> None:
    """The durable outbox is cleared only after a successful delivery/preview."""
    payload = state.get("pending_payload")
    if payload is None:
        return
    status = payload["status"]
    if send:
        publisher(payload)  # failure leaves on-disk payload intact for retry
        print(json.dumps({"event": status, "published": True}), flush=True)
    else:
        print(json.dumps({"event": status, "published": False, "mode": "preview"}), flush=True)
    state["pending_payload"] = None
    lifecycle.save_state(state_file, state)


def _reset_stale_confirmation(state: dict, epoch: int) -> None:
    """Do not use pre-restart confirmations after long gaps in observation."""
    previous = state.get("last_snapshot_at")
    if not previous:
        return
    dt = datetime.fromisoformat(previous.replace("Z", "+00:00"))
    if epoch - int(dt.timestamp()) > MAX_SNAPSHOT_GAP_SECONDS:
        state["consecutive_latency_violations"] = 0
        state["candidate_start_at"] = None
        state["recovery_count"] = 0
        # Deliberately retain active_start_at: unresolved incidents must not vanish.


def tick(epoch: int, state: dict, state_file: Path, send: bool,
         query=telemetry.query_instant, publisher=send_payload) -> tuple[dict, dict]:
    # Always drain/retry a pending outbox message before observing new state.
    deliver_pending(state, state_file, send, publisher)
    _reset_stale_confirmation(state, epoch)
    snapshot, violations = detect_once(epoch, int(state["consecutive_latency_violations"]), query)
    state["consecutive_latency_violations"] = violations
    state, event = lifecycle.step(state, snapshot, recovery_required=REQUIRED_RECOVERIES)
    lifecycle.save_state(state_file, state)  # Persist outbox BEFORE sending.
    deliver_pending(state, state_file, send, publisher)
    return state, {
        "timestamp_utc": snapshot["timestamp_utc"],
        "status": snapshot["status"],
        "request_count_1m": snapshot["request_count_1m"],
        "request_count_5m": snapshot["request_count_5m"],
        "latency_seconds": snapshot["metrics"]["avg_latency_seconds"],
        "active_incident": state["active_start_at"] is not None,
        "event": event["status"] if event else None,
        "mode": "send" if send else "preview",
    }


def _shutdown(_signum, _frame):
    raise KeyboardInterrupt


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--send", action="store_true", help="Explicit opt-in: publish to existing receiver")
    p.add_argument("--samples", type=int, default=0, help="0: continuous")
    p.add_argument("--interval-sec", type=int, default=30)
    args = p.parse_args()
    if args.samples < 0 or not 10 <= args.interval_sec <= 3600:
        p.error("Invalid sample count or interval")
    os.umask(0o077)
    signal.signal(signal.SIGTERM, _shutdown)
    state_file = STATE_DIR / ("send_state.json" if args.send else "preview_state.json")
    mode = "send" if args.send else "preview"
    # Directory was prepared by the Deployment's storage init container.
    # SQLite storage and incident state use distinct PVCs.
    try:
        state = lifecycle.load_state(state_file, mode)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Cannot load persistent state: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(f"KubeGuard automatic RULE-BASED incident agent ({mode}); no ML/remediation.", file=sys.stderr)
    n = 0
    try:
        while args.samples == 0 or n < args.samples:
            begin = time.monotonic()
            try:
                state, event = tick(int(time.time()), state, state_file, args.send)
                print(json.dumps(event, allow_nan=False), flush=True)
            except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
                # A POST may fail AFTER a new outbox event was saved. Reload
                # durable state rather than reusing stale in-memory state.
                print(json.dumps({"status": "ERROR", "reason": type(exc).__name__}), flush=True)
                try:
                    state = lifecycle.load_state(state_file, mode)
                except (OSError, ValueError, TypeError, KeyError) as reload_exc:
                    print(f"State recovery failed: {type(reload_exc).__name__}", file=sys.stderr)
                    return 1  # fail closed; preserve the PVC for inspection
            n += 1
            if args.samples and n >= args.samples:
                break
            time.sleep(max(0., args.interval_sec - (time.monotonic() - begin)))
    except KeyboardInterrupt:
        print("Stopping; on-disk state and outbox preserved.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
