#!/usr/bin/env python3
"""KubeGuard AI: experimental, restart-aware detection-to-incident lifecycle.

Runs on Ubuntu with Prometheus forwarded to localhost:9090 and, for --send,
the existing incident receiver forwarded to localhost:18081. No Kubernetes
writes or remediation are performed. Default mode is dry-run: no HTTP POST.

Safe laboratory design:
- Reuses existing V4 policy for latency confirmation and request-count gating.
- Sends one `firing` when an eligible anomaly is first confirmed.
- Sends one `resolved` after 2 consecutive sufficient, non-violating readings.
- Does NOT resolve on no traffic, missing metrics, low sample volume, or outage.
- Persists episode/counters and an outbox to an atomic local state file.
- Retries an unsent event after restart. Exact payload is stable so the
  receiver's SQLite event-id deduplication handles retry after a crash.
- Each state file is tied to preview or send mode to avoid silent loss.

This is a laboratory agent, not a production alerting solution. Running --send
explicitly opts in to publishing real events to the configured receiver.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import tempfile
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_URL = "http://127.0.0.1:18081/alerts"
ALERT_LABELS = {
    "alertname": "KubeGuardAIHighLatency",
    "namespace": "kubeguard",
    "source": "kubeguard-ai",
    "detector_version": "v4",
    "rule": "average_latency",
    "severity": "warning",
}
FINGERPRINT = hashlib.sha256(
    json.dumps(ALERT_LABELS, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()


def new_state(mode: str) -> dict:
    return {
        "schema_version": 1,
        "mode": mode,
        "consecutive_latency_violations": 0,
        "candidate_start_at": None,
        "active_start_at": None,
        "recovery_count": 0,
        "last_snapshot_at": None,
        "pending_payload": None,
    }


def load_state(path: Path, mode: str) -> dict:
    if not path.exists():
        return new_state(mode)
    obj = json.loads(path.read_text(encoding="utf-8"))
    expected = set(new_state(mode))
    if not isinstance(obj, dict) or set(obj) != expected or obj.get("schema_version") != 1:
        raise ValueError(f"Unsupported/corrupted state file: {path}")
    if obj["mode"] != mode:
        raise ValueError("State file belongs to a different mode (--send vs preview). Use separate files.")
    return obj


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _valid_timestamp(timestamp: str) -> str:
    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Snapshot timestamp is not timezone-aware")
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def notification(status: str, started_at: str, ended_at: str, snapshot: dict) -> dict:
    if status not in ("firing", "resolved"):
        raise ValueError(f"Unexpected notification status {status}")
    if status == "firing" and ended_at:
        raise ValueError("Firing notifications must not have endsAt")
    if status == "resolved" and not ended_at:
        raise ValueError("Resolved notifications require endsAt")

    m = snapshot.get("metrics", {})
    def finite_float(value):
        return float(value) if isinstance(value, (int, float)) and math.isfinite(value) else None

    alert = {
        "status": status,
        "labels": ALERT_LABELS,
        "annotations": {
            "summary": f"KubeGuard V4 application latency {status}",
            "description": "Experimental automatic incident lifecycle; no remediation is performed.",
        },
        "fingerprint": FINGERPRINT,
        "startsAt": _valid_timestamp(started_at),
        "endsAt": _valid_timestamp(ended_at) if ended_at else "",
        "values": {
            "avg_latency_seconds": finite_float(m.get("avg_latency_seconds")),
            "latency_threshold_seconds": finite_float(snapshot.get("latency_threshold_seconds")),
            "request_count_1m": finite_float(snapshot.get("request_count_1m")),
            "request_count_5m": finite_float(snapshot.get("request_count_5m")),
        },
    }
    return {"status": status, "alerts": [alert]}


def step(state: dict, snapshot: dict, recovery_required: int = 2) -> tuple[dict, dict | None]:
    """Pure episode state machine. Never sends or writes to Kubernetes.

    An outstanding outbox event must be delivered or acknowledged in preview
    before the next step can be processed.
    """
    if recovery_required < 1:
        raise ValueError("recovery_required must be >= 1")
    if state["pending_payload"] is not None:
        raise ValueError("Outstanding event must be handled before processing more snapshots")

    current = deepcopy(state)
    stamp = _valid_timestamp(snapshot["timestamp_utc"])
    previous = current["last_snapshot_at"]
    if previous is not None and stamp <= previous:
        raise ValueError(f"Non-increasing snapshot timestamp: {stamp} <= {previous}")
    current["last_snapshot_at"] = stamp
    status = snapshot.get("status")
    event = None

    if current["active_start_at"] is None:
        current["recovery_count"] = 0
        if status == "ANOMALY_PENDING":
            if current["candidate_start_at"] is None:
                current["candidate_start_at"] = stamp
        elif status == "ANOMALY":
            start = current["candidate_start_at"] or stamp
            current["active_start_at"] = start
            current["candidate_start_at"] = None
            event = notification("firing", start, "", snapshot)
        else:
            current["candidate_start_at"] = None
    else:
        # Count recovery only when the operational latency rule is explicitly
        # clear AND there is adequate recent traffic to support the conclusion.
        replicas = snapshot.get("available_replicas")
        healthy = (
            snapshot.get("baseline_anomaly") is False
            and snapshot.get("sample_count_sufficient") is True
            and isinstance(replicas, (int, float)) and replicas >= 1
            and status in ("NORMAL", "ML_SUSPICIOUS", "ML_NOT_EVALUATED")
        )
        if healthy:
            current["recovery_count"] += 1
            if current["recovery_count"] >= recovery_required:
                event = notification("resolved", current["active_start_at"], stamp, snapshot)
                current["active_start_at"] = None
                current["recovery_count"] = 0
        else:
            current["recovery_count"] = 0

    if event is not None:
        current["pending_payload"] = event
    return current, event


def handle_outbox(state: dict, state_file: Path, send: bool, url: str, publisher) -> dict:
    pending = state["pending_payload"]
    if pending is None:
        return state
    status = pending["status"]
    episode = pending["alerts"][0]["startsAt"]
    if send:
        http_status, body = publisher.send_payload(url, pending)
        print(f"SENT {status} for episode {episode}: HTTP {http_status} {body}", file=sys.stderr)
    else:
        print(f"PREVIEW ONLY {status} for episode {episode}; nothing sent", file=sys.stderr)
        print(json.dumps(pending, indent=2, allow_nan=False), file=sys.stderr)
    state["pending_payload"] = None
    save_state(state_file, state)
    return state


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--send", action="store_true", help="Explicitly send firing/resolved events over local HTTP")
    p.add_argument("--receiver", default=DEFAULT_URL)
    p.add_argument("--prometheus", default="http://127.0.0.1:9090")
    p.add_argument("--model", type=Path, default=Path("data/milestone5/detector.joblib"))
    p.add_argument("--state-file", type=Path, help="Default separate state file for send vs preview")
    p.add_argument("--log-file", type=Path, default=Path("data/milestone5/live_lifecycle.jsonl"))
    p.add_argument("--samples", type=int, default=0, help="0 means continuous until Ctrl+C")
    p.add_argument("--interval-sec", type=int, default=30)
    p.add_argument("--rule-consecutive", type=int, default=2)
    p.add_argument("--recovery-consecutive", type=int, default=2)
    p.add_argument("--ml-min-rps", type=float, default=0.8)
    p.add_argument("--ml-max-rps", type=float, default=2.2)
    p.add_argument("--min-requests-5m", type=float, default=20)
    p.add_argument("--min-requests-1m", type=float, default=5)
    args = p.parse_args()
    if args.samples < 0 or not 1 <= args.interval_sec <= 3600:
        p.error("Invalid sampling options")
    if args.rule_consecutive < 1 or args.recovery_consecutive < 1:
        p.error("Confirmation counters must be >= 1")
    if not 0 <= args.ml_min_rps < args.ml_max_rps <= 10:
        p.error("Invalid model rate envelope")
    if args.min_requests_5m < 1 or args.min_requests_1m < 1:
        p.error("Request-count thresholds must be >= 1")
    # Imports live in main() so the policy tests use only the stdlib.
    import live_detect_milestone5_v2 as v2
    import live_detect_milestone5_v4 as v4
    import publish_milestone5_incident as publisher

    # Use the validated publisher's localhost-only URL checks also for --send.
    # With --send we will validate by attempting to send. For preview never
    # establish an outbound receiver connection.
    mode = "send" if args.send else "preview"
    path = args.state_file or Path(f"data/milestone5/incident_agent_{mode}_state.json")
    state = load_state(path, mode)
    detector = v2.load_detector(args.model)
    args.log_file.parent.mkdir(parents=True, exist_ok=True)
    print(f"KubeGuard V4 incident lifecycle ({mode}). No Kubernetes remediation.", file=sys.stderr)
    print(f"State: {path}; log: {args.log_file}", file=sys.stderr)
    state = handle_outbox(state, path, args.send, args.receiver, publisher)

    observations = 0
    try:
        while args.samples == 0 or observations < args.samples:
            tick = time.monotonic()
            epoch = int(time.time())
            raw = v2.detect_once(args.prometheus, detector, epoch)
            count5 = v2.query_instant(args.prometheus, v4._REQUEST_COUNT % "5m", epoch)
            count1 = v2.query_instant(args.prometheus, v4._REQUEST_COUNT % "1m", epoch)
            processed, new_counter = v4.apply_policy_v4(
                raw,
                int(state["consecutive_latency_violations"]),
                args.rule_consecutive,
                args.ml_min_rps,
                args.ml_max_rps,
                count5,
                count1,
                args.min_requests_5m,
                args.min_requests_1m,
            )
            state["consecutive_latency_violations"] = new_counter
            state, event = step(state, processed, args.recovery_consecutive)
            save_state(path, state)  # Persist the outbox BEFORE network I/O.
            with args.log_file.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(processed, allow_nan=False) + "\n")
            print(json.dumps({
                "timestamp_utc": processed["timestamp_utc"],
                "status": processed["status"],
                "latency_seconds": processed["metrics"].get("avg_latency_seconds"),
                "requests_1m": processed["request_count_1m"],
                "consecutive_latency_violations": processed["consecutive_latency_violations"],
                "active_incident": state["active_start_at"] is not None,
                "recovery_count": state["recovery_count"],
                "event": event["status"] if event else None,
            }, allow_nan=False), flush=True)
            state = handle_outbox(state, path, args.send, args.receiver, publisher)
            observations += 1
            if args.samples and observations >= args.samples:
                break
            time.sleep(max(0.0, args.interval_sec - (time.monotonic() - tick)))
    except KeyboardInterrupt:
        print("Stopped by user. State preserved.", file=sys.stderr)
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
