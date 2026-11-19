#!/usr/bin/env python3
"""Authenticated incident ingestion plus strictly limited read-only evidence feed.

Never returns raw alert JSON, annotations, arbitrary labels or logs.
The evidence feed uses a DIFFERENT HMAC key from incident publishing.
"""
from __future__ import annotations

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
from urllib.parse import urlsplit, parse_qs

DB = "/data/incidents.sqlite3"
KEY_FILE = "/var/run/kubeguard-hmac/key"
EVIDENCE_KEY_FILE = "/var/run/kubeguard-evidence-key/key"
MAX_BODY_BYTES = 8192
MAX_CLOCK_SKEW = 60
SIGNING_PREFIX = b"kubeguard-alert-v1\n"
EVIDENCE_SIGNING_PREFIX = b"kubeguard-evidence-v1\n"
ALERT_LABELS = {
    "alertname": "KubeGuardAIHighLatency",
    "namespace": "kubeguard",
    "source": "kubeguard-ai",
    "detector_version": "v4",
    "rule": "average_latency",
    "severity": "warning",
}
FINGERPRINT = hashlib.sha256(json.dumps(ALERT_LABELS, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
VALUE_KEYS = frozenset({"avg_latency_seconds", "latency_threshold_seconds", "request_count_1m", "request_count_5m"})
ALERT_KEYS = frozenset({"status", "labels", "annotations", "fingerprint", "startsAt", "endsAt", "values"})
EVENT_ID_RE = re.compile(r"[a-f0-9]{64}\Z")
BATCH_SIZE = 20


def load_key(path=KEY_FILE):
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
    expected = hmac.new(key, SIGNING_PREFIX + timestamp.encode("ascii") + b"\n" + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, "sha256=" + expected)


def valid_evidence_signature(path, timestamp, signature, key, *, now=None):
    if not isinstance(path, str) or not path.startswith("/evidence/feed") or len(path) > 128:
        return False
    if not isinstance(timestamp, str) or not re.fullmatch(r"[0-9]{10,11}", timestamp):
        return False
    if not isinstance(signature, str) or not re.fullmatch(r"sha256=[0-9a-f]{64}", signature):
        return False
    now = int(time.time()) if now is None else int(now)
    if abs(now - int(timestamp)) > MAX_CLOCK_SKEW:
        return False
    mac = hmac.new(key, EVIDENCE_SIGNING_PREFIX + timestamp.encode("ascii") + b"\nGET\n" + path.encode("ascii"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, "sha256=" + mac)


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


def iso_timestamp(value):
    return valid_timestamp(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def sanitized_event(payload):
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
        if value is not None and (not isinstance(value, (int, float)) or isinstance(value, bool)
                                  or not math.isfinite(value) or not 0 <= value <= 1e12):
            raise ValueError("Invalid numeric metric")
        metrics[name] = None if value is None else float(value)
    return status, {"status": status, "labels": ALERT_LABELS, "fingerprint": FINGERPRINT,
                    "startsAt": alert["startsAt"], "endsAt": alert["endsAt"], "values": metrics}


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
    event_id = hashlib.sha256(json.dumps([FINGERPRINT, status, starts_at, ends_at]).encode()).hexdigest()
    with sqlite3.connect(path, timeout=10) as db:
        cursor = db.execute(
            "INSERT OR IGNORE INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, received_at, ALERT_LABELS["alertname"], status,
             ALERT_LABELS["namespace"], None, None, FINGERPRINT, starts_at, ends_at,
             json.dumps(alert["values"], sort_keys=True, allow_nan=False),
             json.dumps(alert, sort_keys=True, allow_nan=False)),
        )
        return cursor.rowcount


def _feed_event(row):
    """Strict, field-by-field projection of the database row. Never return alert_json."""
    status = row["status"]
    if status not in ("firing", "resolved") or not EVENT_ID_RE.fullmatch(row["event_id"]):
        raise ValueError("Invalid incident record")
    started = iso_timestamp(row["starts_at"])
    ended = iso_timestamp(row["ends_at"]) if row["ends_at"] else None
    if (status == "resolved") != (ended is not None):
        raise ValueError("Malformed incident lifecycle")
    raw = json.loads(row["values_json"] or "{}")
    if not isinstance(raw, dict):
        raise ValueError("Malformed numeric values")
    values = {}
    for k in VALUE_KEYS:
        v = raw.get(k)
        values[k] = (float(v) if isinstance(v, (int, float)) and not isinstance(v, bool)
                     and math.isfinite(v) and 0 <= v <= 1e12 else None)
    return {"event_id": row["event_id"], "status": status,
            "starts_at": started, "ends_at": ended,
            "received_at": iso_timestamp(row["received_at"]), "values": values}


def read_evidence_feed(after, *, path=DB):
    """Bootstrap at latest existing event, then page forward by a durable event ID."""
    if after is not None and after != "origin" and not EVENT_ID_RE.fullmatch(after):
        raise ValueError("Invalid cursor")
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10) as db:
        db.row_factory = sqlite3.Row
        where = "alert_name=? AND status IN ('firing','resolved')"
        if after is None:
            last = db.execute(f"SELECT event_id FROM incidents WHERE {where} ORDER BY received_at DESC,event_id DESC LIMIT 1",
                              (ALERT_LABELS["alertname"],)).fetchone()
            cursor = last["event_id"] if last else "origin"
            if cursor != "origin" and not EVENT_ID_RE.fullmatch(cursor):
                raise ValueError("Invalid stored cursor")
            return {"schema_version": 1, "bootstrap": True, "cursor": cursor, "more": False, "events": []}
        if after == "origin":
            rows = db.execute(f"SELECT event_id,status,starts_at,ends_at,received_at,values_json FROM incidents WHERE {where} "
                              "ORDER BY received_at ASC,event_id ASC LIMIT ?",
                              (ALERT_LABELS["alertname"], BATCH_SIZE + 1)).fetchall()
        else:
            previous = db.execute(f"SELECT received_at FROM incidents WHERE {where} AND event_id=?",
                                  (ALERT_LABELS["alertname"], after)).fetchone()
            if previous is None:
                raise LookupError("Cursor no longer present")
            rows = db.execute(f"SELECT event_id,status,starts_at,ends_at,received_at,values_json FROM incidents "
                              f"WHERE {where} AND (received_at > ? OR (received_at = ? AND event_id > ?)) "
                              "ORDER BY received_at ASC,event_id ASC LIMIT ?",
                              (ALERT_LABELS["alertname"], previous["received_at"], previous["received_at"], after,
                               BATCH_SIZE + 1)).fetchall()
    items = [_feed_event(row) for row in rows[:BATCH_SIZE]]
    return {"schema_version": 1, "bootstrap": False, "cursor": items[-1]["event_id"] if items else after,
            "more": len(rows) > BATCH_SIZE, "events": items}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _fmt, *_args):
        return

    def _json_response(self, status, payload):
        raw = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        parsed = urlsplit(self.path)
        if parsed.path != "/evidence/feed" or parsed.fragment or len(self.path) > 128:
            self.send_error(404)
            return
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if set(qs) - {"after"} or any(len(v) != 1 for v in qs.values()):
            self.send_error(400)
            return
        after = qs["after"][0] if "after" in qs else None
        if after is not None and after != "origin" and not EVENT_ID_RE.fullmatch(after):
            self.send_error(400)
            return
        try:
            key = load_key(EVIDENCE_KEY_FILE)
        except (OSError, ValueError):
            self.send_error(503)
            return
        if not valid_evidence_signature(self.path, self.headers.get("X-KubeGuard-Evidence-Timestamp"),
                                        self.headers.get("X-KubeGuard-Evidence-Signature"), key):
            self.send_error(401)
            return
        try:
            result = read_evidence_feed(after, path=DB)
        except LookupError:
            self.send_error(409)  # Fail closed rather than skipping missing cursor.
            return
        except (OSError, ValueError, sqlite3.Error):
            self.send_error(503)
            return
        self._json_response(200, result)

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
        if not valid_signature(body, self.headers.get("X-KubeGuard-Timestamp"),
                               self.headers.get("X-KubeGuard-Signature"), key):
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
    load_key(KEY_FILE)
    load_key(EVIDENCE_KEY_FILE)
    os.umask(0o077)
    prepare_database(DB)
    print("KubeGuard authenticated incident receiver with read-only evidence feed started", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()


if __name__ == "__main__":
    main()
