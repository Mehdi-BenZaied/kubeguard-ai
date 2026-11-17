#!/usr/bin/env python3
"""Authenticated, data-minimizing KubeGuard incident receiver.

Only accepts signed KubeGuard V4 average-latency lifecycle events. No generic
Grafana webhook support is provided by this endpoint. Legacy incidents remain
in the existing SQLite table. Secrets and raw untrusted alert JSON are never
stored or printed. The HTTP health endpoint stays available for kubelet probes.
"""
import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DB = "/data/incidents.sqlite3"
KEY_FILE = "/var/run/kubeguard-hmac/key"
MAX_BODY_BYTES = 8192
MAX_CLOCK_SKEW = 60
SIGNING_PREFIX = b"kubeguard-alert-v1\n"
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
VALUE_KEYS = frozenset({
    "avg_latency_seconds", "latency_threshold_seconds",
    "request_count_1m", "request_count_5m",
})
ALERT_KEYS = frozenset({
    "status", "labels", "annotations", "fingerprint", "startsAt", "endsAt", "values",
})


def load_key(path=KEY_FILE):
    # Fixed-size binary key; generated on the Ubuntu host and mounted from a
    # Kubernetes Secret. Never accept a weak or missing key.
    key = Path(path).read_bytes()
    if len(key) != 32:
        raise ValueError("Invalid notification signing key")
    return key


def valid_signature(body, timestamp, signature, key, *, now=None):
    if not isinstance(timestamp, str) or not re.fullmatch(r"[0-9]{10,11}", timestamp):
        return False
    if not isinstance(signature, str) or not re.fullmatch(r"sha256=[0-9a-f]{64}", signature):
        return False
    instant = int(time.time()) if now is None else int(now)
    if abs(instant - int(timestamp)) > MAX_CLOCK_SKEW:
        return False
    expected = hmac.new(
        key, SIGNING_PREFIX + timestamp.encode("ascii") + b"\n" + body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(signature, "sha256=" + expected)


def valid_timestamp(value, *, allow_blank=False):
    if allow_blank and value == "":
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 40:
        raise ValueError("Invalid event timestamp")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid event timestamp") from exc
    if dt.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    return dt.astimezone(timezone.utc)


def sanitized_event(payload):
    """Validate strict schema and return a minimized alert for storage."""
    if not isinstance(payload, dict) or set(payload) != {"status", "alerts"}:
        raise ValueError("Invalid notification envelope")
    status = payload["status"]
    if status not in ("firing", "resolved"):
        raise ValueError("Unexpected notification status")
    alerts = payload["alerts"]
    if not isinstance(alerts, list) or len(alerts) != 1 or not isinstance(alerts[0], dict):
        raise ValueError("Expected exactly one alert")
    alert = alerts[0]
    if not set(alert).issubset(ALERT_KEYS) or not ALERT_KEYS.difference({"annotations"}).issubset(alert):
        raise ValueError("Unexpected alert fields")
    if alert["status"] != status or alert["labels"] != ALERT_LABELS or alert["fingerprint"] != FINGERPRINT:
        raise ValueError("Unexpected alert identity")
    annotations = alert.get("annotations", {})
    if not isinstance(annotations, dict) or not set(annotations).issubset({"summary", "description"}):
        raise ValueError("Unexpected annotations")
    if not all(isinstance(v, str) and len(v) <= 250 for v in annotations.values()):
        raise ValueError("Invalid annotations")
    starts = valid_timestamp(alert["startsAt"])
    ends = valid_timestamp(alert["endsAt"], allow_blank=True)
    if (status == "firing" and ends is not None) or (status == "resolved" and (ends is None or ends < starts)):
        raise ValueError("Invalid lifecycle timestamps")
    values = alert["values"]
    if not isinstance(values, dict) or not set(values).issubset(VALUE_KEYS):
        raise ValueError("Unexpected metric fields")
    metrics = {}
    for name in VALUE_KEYS:
        value = values.get(name)
        if value is not None and (
            not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(value) or not 0 <= value <= 1e12
        ):
            raise ValueError("Invalid numeric metric")
        metrics[name] = None if value is None else float(value)
    # Never store untrusted annotations, custom labels, arbitrary JSON, or request bodies.
    safe_alert = {
        "status": status, "labels": ALERT_LABELS, "fingerprint": FINGERPRINT,
        "startsAt": alert["startsAt"], "endsAt": alert["endsAt"], "values": metrics,
    }
    return status, safe_alert


def prepare_database(path=DB):
    with sqlite3.connect(path, timeout=10) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                event_id TEXT PRIMARY KEY,
                received_at TEXT NOT NULL,
                alert_name TEXT NOT NULL,
                status TEXT NOT NULL,
                namespace TEXT,
                pod TEXT,
                container TEXT,
                fingerprint TEXT,
                starts_at TEXT,
                ends_at TEXT,
                values_json TEXT,
                alert_json TEXT NOT NULL
            )
        """)
    os.chmod(path, 0o600)


def save_incident(alert, *, path=DB):
    received_at = datetime.now(timezone.utc).isoformat()
    status, starts_at, ends_at = alert["status"], alert["startsAt"], alert["endsAt"]
    event_id = hashlib.sha256(
        json.dumps([FINGERPRINT, status, starts_at, ends_at]).encode()
    ).hexdigest()
    with sqlite3.connect(path, timeout=10) as db:
        cursor = db.execute(
            "INSERT OR IGNORE INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id, received_at, ALERT_LABELS["alertname"], status,
                ALERT_LABELS["namespace"], None, None, FINGERPRINT,
                starts_at, ends_at,
                json.dumps(alert["values"], sort_keys=True, allow_nan=False),
                json.dumps(alert, sort_keys=True, allow_nan=False),
            ),
        )
        return cursor.rowcount


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _fmt, *_args):
        # No headers, URLs, body or secrets in access logs.
        return

    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        if self.path != "/alerts":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if not 0 < size <= MAX_BODY_BYTES:
            self.send_error(413)
            return
        try:
            body = self.rfile.read(size)
            key = load_key(KEY_FILE)
        except (OSError, ValueError):
            self.send_error(503)
            return
        if not valid_signature(
            body, self.headers.get("X-KubeGuard-Timestamp"),
            self.headers.get("X-KubeGuard-Signature"), key,
        ):
            self.send_error(401)
            return
        try:
            status, safe_alert = sanitized_event(json.loads(body))
        except (ValueError, TypeError, KeyError):
            self.send_error(400)
            return
        try:
            saved = save_incident(safe_alert, path=DB)
        except sqlite3.Error:
            self.send_error(503)
            return
        print(json.dumps({"status": status, "saved": saved}), flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"received")


def main():
    # Refuse to expose an unauthenticated service if the Secret is missing.
    load_key(KEY_FILE)
    os.umask(0o077)
    prepare_database(DB)
    server = ThreadingHTTPServer(("0.0.0.0", 8081), Handler)
    print("KubeGuard authenticated incident receiver started", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
