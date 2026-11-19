#!/usr/bin/env python3
"""KubeGuard Milestone 6: automatic, credential-isolated evidence collection.

Read-only incident feed + fixed PromQL aggregates only. No Kubernetes client,
subprocess, kubectl, AI inference, external network, application logs or secrets.
Does not read or write the original incident SQLite database. Bootstrap skips
historical events; new firing/resolved events are durably processed in order.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import signal
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

from build_milestone4_dataset import PROMQL

PROMETHEUS = "http://kubeguard-monitoring-kube-prometheus.monitoring.svc.cluster.local:9090"
RECEIVER = "http://kubeguard-incident-receiver.monitoring.svc.cluster.local:8081"
READ_KEY = Path("/var/run/kubeguard-evidence-key/key")
STORE = Path("/data/evidence")
CURSOR_FILE = STORE / "cursor.json"
SIGNING_PREFIX = b"kubeguard-evidence-v1\n"
ID_RE = re.compile(r"[a-f0-9]{64}\Z")
METRICS = {
    "available_replicas": PROMQL["available_replicas"],
    "container_restarts": 'sum(kube_pod_container_status_restarts_total{namespace="kubeguard",container="kubeguard-api"})',
    "running_pods": 'sum(kube_pod_status_phase{namespace="kubeguard",pod=~"kubeguard-api-.*",phase="Running"})',
    "request_rate_per_s": PROMQL["request_rate_per_s"],
    "avg_latency_seconds": PROMQL["avg_latency_seconds"],
    "p95_latency_seconds": PROMQL["p95_latency_seconds"],
    "error_rate_pct": PROMQL["error_rate_pct"],
    "cpu_millicores": PROMQL["cpu_millicores"],
    "memory_mib": PROMQL["memory_mib"],
    "cpu_throttle_pct": PROMQL["cpu_throttle_pct"],
}
INCIDENT_VALUE_KEYS = frozenset({"avg_latency_seconds", "latency_threshold_seconds", "request_count_1m", "request_count_5m"})


class DenyRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise RuntimeError("Redirect not permitted")


def opener():
    return build_opener(ProxyHandler({}), DenyRedirect())


def utc(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Invalid timestamp")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Missing timezone")
    return dt.astimezone(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_cursor(value):
    return value == "origin" or (isinstance(value, str) and ID_RE.fullmatch(value) is not None)


def feed_headers(path, key, *, epoch=None):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Evidence key must be 32 bytes")
    ts = str(int(time.time() if epoch is None else epoch))
    mac = hmac.new(key, SIGNING_PREFIX + ts.encode() + b"\nGET\n" + path.encode("ascii"), hashlib.sha256).hexdigest()
    return {"X-KubeGuard-Evidence-Timestamp": ts, "X-KubeGuard-Evidence-Signature": "sha256=" + mac}


def validate_event(e):
    if not isinstance(e, dict) or set(e) != {"event_id", "status", "starts_at", "ends_at", "received_at", "values"}:
        raise ValueError("Unexpected event shape")
    if not ID_RE.fullmatch(e["event_id"]) or e["status"] not in ("firing", "resolved"):
        raise ValueError("Invalid event identity")
    started, received = utc(e["starts_at"]), utc(e["received_at"])
    ended = utc(e["ends_at"]) if e["ends_at"] is not None else None
    if (e["status"] == "resolved") != (ended is not None):
        raise ValueError("Invalid lifecycle")
    if ended is not None and ended < started:
        raise ValueError("Resolution before incident")
    if started > datetime.now(timezone.utc) + timedelta(minutes=2):
        raise ValueError("Future event")
    v = e["values"]
    if not isinstance(v, dict) or set(v) != INCIDENT_VALUE_KEYS:
        raise ValueError("Unexpected values")
    for field in INCIDENT_VALUE_KEYS:
        x = v[field]
        if x is not None and (not isinstance(x, (int, float)) or isinstance(x, bool)
                              or not math.isfinite(x) or not 0 <= x <= 1e12):
            raise ValueError("Unsafe metric value")
    return e


def validate_feed(payload, cursor):
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "bootstrap", "cursor", "more", "events"}:
        raise ValueError("Unexpected feed shape")
    if payload["schema_version"] != 1 or type(payload["more"]) is not bool or type(payload["bootstrap"]) is not bool:
        raise ValueError("Invalid feed version")
    if not safe_cursor(payload["cursor"]):
        raise ValueError("Unexpected cursor")
    events = payload["events"]
    if not isinstance(events, list) or len(events) > 20:
        raise ValueError("Unbounded feed")
    for e in events:
        validate_event(e)
    if cursor is None:
        if not payload["bootstrap"] or events or payload["more"]:
            raise ValueError("Invalid bootstrap")
    else:
        if payload["bootstrap"] or (events and payload["cursor"] != events[-1]["event_id"]) or (not events and payload["cursor"] != cursor):
            raise ValueError("Invalid feed cursor sequence")
    return payload


def fetch_feed(cursor, *, key_file=READ_KEY, http=None):
    if cursor is not None and not safe_cursor(cursor):
        raise ValueError("Invalid local cursor")
    path = "/evidence/feed" + ("?after=" + cursor if cursor is not None else "")
    req = Request(RECEIVER + path, headers=feed_headers(path, key_file.read_bytes()), method="GET")
    client = http or opener()
    with client.open(req, timeout=8) as response:
        if response.status != 200:
            raise RuntimeError("Receiver unavailable")
        body = response.read(65537)
    if len(body) > 65536:
        raise ValueError("Oversized evidence feed")
    return validate_feed(json.loads(body), cursor)


def query_series(expression, left, right, *, http=None):
    if right < left or right - left > timedelta(minutes=7):
        raise ValueError("Invalid Prometheus evidence window")
    query = urlencode({"query": expression, "start": int(left.timestamp()),
                       "end": int(right.timestamp()), "step": 30})
    req = Request(PROMETHEUS + "/api/v1/query_range?" + query, method="GET")
    with (http or opener()).open(req, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError("Prometheus unavailable")
        body = response.read(65537)
    if len(body) > 65536:
        raise ValueError("Oversized metrics")
    data = json.loads(body)
    if data.get("status") != "success" or data.get("data", {}).get("resultType") != "matrix":
        raise ValueError("Unexpected Prometheus result")
    series = data["data"].get("result", [])
    if not isinstance(series, list) or len(series) > 1:
        raise ValueError("Ambiguous Prometheus result")
    points = []
    if series:
        for pair in series[0].get("values", []):
            if len(points) >= 20:
                break
            if not isinstance(pair, list) or len(pair) != 2:
                continue
            try:
                stamp = float(pair[0]); value = float(pair[1])
                dt = datetime.fromtimestamp(stamp, timezone.utc)
            except (ValueError, TypeError, OverflowError, OSError):
                continue
            if math.isfinite(value) and left <= dt <= right:
                points.append({"at": iso(dt), "value": round(value, 6)})
    return {"sample_count": len(points), "min": min((p["value"] for p in points), default=None),
            "max": max((p["value"] for p in points), default=None),
            "last": points[-1]["value"] if points else None, "points": points}


def build_evidence(event, *, now=None, query=query_series):
    validate_event(event)
    now = now or datetime.now(timezone.utc)
    anchor = utc(event["ends_at"] if event["status"] == "resolved" else event["starts_at"])
    left, right = anchor - timedelta(minutes=5), min(now, anchor + timedelta(minutes=1))
    if right < left:
        raise ValueError("Incident observation window is in the future")
    measurements, gaps = {}, []
    for name, expression in METRICS.items():
        try:
            measurement = query(expression, left, right)
            if measurement["sample_count"] == 0:
                gaps.append("missing_" + name)
            measurements[name] = measurement
        except (OSError, RuntimeError, ValueError, TypeError, KeyError):
            gaps.append("unavailable_" + name)
            measurements[name] = {"sample_count": 0, "min": None, "max": None, "last": None, "points": []}
    if sum(gap.startswith("unavailable_") for gap in gaps) == len(METRICS):
        raise RuntimeError("All Prometheus queries failed; retry before advancing cursor")
    return {
        "schema_version": 1,
        "purpose": "read_only_incident_evidence_not_root_cause",
        "generated_at": iso(now),
        "incident": event,
        "window": {"from": iso(left), "to": iso(right), "step_seconds": 30,
                   "anchor": "resolution" if event["status"] == "resolved" else "start"},
        "metrics": measurements,
        "evidence_gaps": gaps,
        "cautions": ["Missing values are not zero", "Restarts are cumulative, not necessarily current failures",
                     "Only aggregated Prometheus data; Kubernetes events/logs were not accessed"],
    }


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".kubeguard-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, allow_nan=False, sort_keys=True, separators=(",", ":"))
            f.write("\n")
            f.flush(); os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        # fsync directory to improve crash durability on local filesystems.
        directory = os.open(str(path.parent), os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_cursor(path=CURSOR_FILE):
    if not path.exists():
        return None
    obj = json.loads(path.read_text())
    if not isinstance(obj, dict) or set(obj) != {"schema_version", "cursor"} or obj["schema_version"] != 1 or not safe_cursor(obj["cursor"]):
        raise ValueError("Invalid persistent cursor; refusing silent rewind")
    return obj["cursor"]


def poll_once(store=STORE, *, feed=fetch_feed, collect=build_evidence):
    cursor_file = store / "cursor.json"
    cursor = load_cursor(cursor_file)
    data = feed(cursor)
    if cursor is None:
        atomic_json(cursor_file, {"schema_version": 1, "cursor": data["cursor"]})
        return {"status": "BOOTSTRAPPED", "cursor": data["cursor"], "processed": 0}
    processed = 0
    for event in data["events"]:
        report = collect(event)
        atomic_json(store / ("incident_" + event["event_id"] + ".json"), report)
        cursor = event["event_id"]
        atomic_json(cursor_file, {"schema_version": 1, "cursor": cursor})
        processed += 1
    return {"status": "EVIDENCE_SAVED" if processed else "NO_NEW_INCIDENTS",
            "processed": processed, "more": data["more"]}


def _stop(_signum, _frame):
    raise KeyboardInterrupt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--samples", type=int, default=0)
    p.add_argument("--interval-sec", type=int, default=30)
    args = p.parse_args()
    if args.samples < 0 or not 10 <= args.interval_sec <= 3600:
        p.error("Invalid polling settings")
    os.umask(0o077)
    signal.signal(signal.SIGTERM, _stop)
    print("KubeGuard automated numeric evidence collector; no AI, Kubernetes API or remediation.", flush=True)
    n = 0
    try:
        while args.samples == 0 or n < args.samples:
            tick = time.monotonic()
            try:
                result = poll_once()
            except (OSError, RuntimeError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                result = {"status": "ERROR", "reason": type(exc).__name__}
            # Cursor and incident details stay on PVC; logs disclose only status/count.
            print(json.dumps(result, allow_nan=False), flush=True)
            n += 1
            if args.samples and n >= args.samples:
                break
            time.sleep(max(0., args.interval_sec - (time.monotonic() - tick)))
    except KeyboardInterrupt:
        print("Stopped; evidence and cursor persisted.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
