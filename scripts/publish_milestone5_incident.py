#!/usr/bin/env python3
"""Manually publish a confirmed KubeGuard V4 detection to the existing receiver.

Safe by default: without --send, print a Grafana-compatible JSON payload and
make no HTTP request. Intended for controlled lab validation only, not for
continuous alert delivery or automated Kubernetes remediation.

Start a local receiver port-forward before using --send:
    microk8s kubectl port-forward -n monitoring svc/kubeguard-incident-receiver 18081:8081

Examples:
    python scripts/publish_milestone5_incident.py --input data/milestone5/live_v4_final_test.jsonl
    python scripts/publish_milestone5_incident.py --input data/milestone5/live_v4_final_test.jsonl --send
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


DEFAULT_URL = "http://127.0.0.1:18081/alerts"
ALERT_NAME = "KubeGuardAIHighLatency"
EPISODE_STATUSES = {"ANOMALY_PENDING", "ANOMALY"}


def parse_time(text: str) -> datetime:
    date = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if date.tzinfo is None:
        raise ValueError(f"Missing timezone: {text}")
    return date.astimezone(timezone.utc)


def read_snapshots(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        rows = []
        prev = None
        for lineno, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("Expected JSON object")
                stamp = parse_time(row["timestamp_utc"])
            except (ValueError, TypeError, KeyError) as exc:
                raise ValueError(f"Invalid snapshot at line {lineno}: {exc}") from exc
            if prev is not None and stamp < prev:
                raise ValueError("Snapshots must be in chronological order")
            prev = stamp
            rows.append(row)
    if not rows:
        raise ValueError("Detection log is empty")
    return rows


def latest_confirmed_episode(rows: list[dict]) -> list[dict]:
    """Return only the *latest* contiguous pending/anomaly episode.

    A recovered/idle entry after an anomaly means that older episode is not
    selected for delivery. This tool does not auto-monitor for recovery.
    """
    episode = []
    for row in rows:
        if row.get("status") in EPISODE_STATUSES:
            episode.append(row)
        else:
            episode = []
    if not episode:
        raise ValueError("No active pending/anomaly episode at end of log")
    if episode[-1].get("status") != "ANOMALY":
        raise ValueError("Latest snapshot is not a confirmed ANOMALY")
    latest = episode[-1]
    if latest.get("baseline_anomaly") is not True:
        raise ValueError("Refusing ML-only anomaly: latency rule must be true")
    if latest.get("sample_count_sufficient") is not True:
        raise ValueError("Refusing to publish without sufficient recent requests")
    if float(latest.get("available_replicas") or 0) < 1:
        raise ValueError("Refusing high-latency incident when replicas are unavailable")
    required = int(latest.get("required_latency_violations", 2))
    if int(latest.get("consecutive_latency_violations", 0)) < required or required < 1:
        raise ValueError("Missing consecutive latency confirmation")
    latency = latest.get("metrics", {}).get("avg_latency_seconds")
    if not isinstance(latency, (int, float)) or not math.isfinite(latency):
        raise ValueError("Invalid measured latency")
    if latency <= float(latest["latency_threshold_seconds"]):
        raise ValueError("Latest latency is not above threshold")
    return episode


def build_payload(rows: list[dict]) -> dict:
    episode = latest_confirmed_episode(rows)
    latest = episode[-1]
    labels = {
        "alertname": ALERT_NAME,
        "namespace": "kubeguard",
        "source": "kubeguard-ai",
        "detector_version": "v4",
        "rule": "average_latency",
        "severity": "warning",
    }
    # Stable fingerprint across repeated publishing of the SAME episode.
    fingerprint = hashlib.sha256(
        json.dumps(labels, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    latency = latest["metrics"]["avg_latency_seconds"]
    values = {
        "avg_latency_seconds": float(latency),
        "latency_threshold_seconds": float(latest["latency_threshold_seconds"]),
        "request_count_1m": float(latest["request_count_1m"]),
        "request_count_5m": float(latest["request_count_5m"]),
    }
    return {
        "status": "firing",
        "alerts": [{
            "status": "firing",
            "labels": labels,
            "annotations": {
                "summary": "KubeGuard V4 confirmed elevated application latency",
                "description": (
                    "Manual, read-only lab incident; latency and request-count "
                    "requirements met. No Kubernetes remediation requested."
                ),
            },
            "fingerprint": fingerprint,
            "startsAt": parse_time(episode[0]["timestamp_utc"]).isoformat().replace("+00:00", "Z"),
            "endsAt": "",
            "values": values,
        }],
    }


def send_payload(url: str, payload: dict) -> tuple[int, str]:
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1")
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path != "/alerts"):
        raise ValueError("Receiver URL must be a local HTTP port-forward ending /alerts")
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=10) as response:
        return response.status, response.read(4096).decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/milestone5/live_v4_final_test.jsonl"))
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--send", action="store_true", help="Opt in to HTTP POST to local receiver")
    args = parser.parse_args()
    try:
        rows = read_snapshots(args.input)
        payload = build_payload(rows)
        if not args.send:
            print("DRY RUN: no data sent. Use --send to publish exactly one firing incident.")
            print(json.dumps(payload, indent=2))
            return 0
        status, response = send_payload(args.url, payload)
        print(f"Receiver response: HTTP {status}: {response}")
        print("Note: HTTP 200 means accepted, not necessarily inserted (duplicates are ignored).")
        return 0
    except (OSError, ValueError, KeyError, TypeError, URLError, HTTPError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
