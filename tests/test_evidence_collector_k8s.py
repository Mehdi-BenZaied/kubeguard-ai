"""Offline end-to-end security, cursor, persistence and metrics tests."""
from __future__ import annotations
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import collect_incident_evidence_k8s as collector

spec = importlib.util.spec_from_file_location("receiver_evidence_test", ROOT / "monitoring/incident-receiver/receiver.py")
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


def sample(status="firing", start="2026-11-18T09:00:00Z"):
    return {"status": status, "alerts": [{
        "status": status, "labels": receiver.ALERT_LABELS,
        "annotations": {"summary": "private-token-SHOULD-NOT-LEAK"},
        "fingerprint": receiver.FINGERPRINT, "startsAt": start,
        "endsAt": "2026-11-18T09:04:00Z" if status == "resolved" else "",
        "values": {"avg_latency_seconds": 1.2, "latency_threshold_seconds": .25,
                   "request_count_1m": 60, "request_count_5m": 90},
    }]}


class FeedHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "incidents.sqlite3")
        self.pubkey = b"p" * 32
        self.readkey = b"r" * 32
        self.pubfile = Path(self.tmp.name) / "publish-key"
        self.readfile = Path(self.tmp.name) / "read-key"
        self.pubfile.write_bytes(self.pubkey)
        self.readfile.write_bytes(self.readkey)
        self.patches = [patch.object(receiver, "DB", self.db),
                        patch.object(receiver, "KEY_FILE", str(self.pubfile)),
                        patch.object(receiver, "EVIDENCE_KEY_FILE", str(self.readfile))]
        for p in self.patches: p.start()
        receiver.prepare_database(self.db)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), receiver.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)
        for p in reversed(self.patches): p.stop()
        self.tmp.cleanup()

    def request(self, method, path, body=b"", key=None, now=None):
        timestamp = str(int(time.time()) if now is None else now)
        headers = {}
        if key is not None and method == "GET":
            sig = hmac.new(key, receiver.EVIDENCE_SIGNING_PREFIX + timestamp.encode() + b"\nGET\n" + path.encode(), hashlib.sha256).hexdigest()
            headers = {"X-KubeGuard-Evidence-Timestamp": timestamp,
                       "X-KubeGuard-Evidence-Signature": "sha256=" + sig}
        if method == "POST":
            if isinstance(body, dict): body = json.dumps(body, separators=(",", ":")).encode()
            if key is not None:
                sig = hmac.new(key, receiver.SIGNING_PREFIX + timestamp.encode() + b"\n" + body, hashlib.sha256).hexdigest()
                headers = {"X-KubeGuard-Timestamp": timestamp, "X-KubeGuard-Signature": "sha256=" + sig}
        con = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=4)
        con.request(method, path, body=body, headers=headers)
        resp = con.getresponse()
        status = resp.status
        data = resp.read()
        con.close()
        return status, data

    def signed_alert(self, status="firing"):
        return self.request("POST", "/alerts", sample(status), self.pubkey)[0]

    def feed(self, after=None, key=None, now=None):
        path = "/evidence/feed" + ("?after=" + after if after is not None else "")
        code, body = self.request("GET", path, key=self.readkey if key is None else key, now=now)
        return code, json.loads(body) if code == 200 else None

    def test_unsigned_feed_denied(self):
        self.assertEqual(self.request("GET", "/evidence/feed")[0], 401)

    def test_publisher_key_cannot_read_feed(self):
        self.assertEqual(self.feed(key=self.pubkey)[0], 401)

    def test_read_key_cannot_publish_incidents(self):
        self.assertEqual(self.request("POST", "/alerts", sample(), self.readkey)[0], 401)
        self.assertEqual(self.db_count(), 0)

    def db_count(self):
        with sqlite3.connect(self.db) as db:
            return db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

    def test_bootstrap_empty_then_new_firing_and_resolved(self):
        code, boot = self.feed()
        self.assertEqual(code, 200)
        self.assertEqual((boot["bootstrap"], boot["cursor"], boot["events"]), (True, "origin", []))
        self.assertEqual(self.signed_alert("firing"), 200)
        code, data = self.feed("origin")
        self.assertEqual(code, 200)
        self.assertEqual(len(data["events"]), 1)
        e = data["events"][0]
        self.assertEqual(e["status"], "firing")
        self.assertEqual(set(e), {"event_id", "status", "starts_at", "ends_at", "received_at", "values"})
        self.assertNotIn("private-token", json.dumps(data))
        self.assertNotIn("annotations", json.dumps(data))
        self.assertEqual(self.signed_alert("resolved"), 200)
        code, data2 = self.feed(e["event_id"])
        self.assertEqual(code, 200)
        self.assertEqual(data2["events"][0]["status"], "resolved")
        self.assertEqual(len(data2["events"]), 1)
        self.assertEqual(self.db_count(), 2)

    def test_bootstrap_skips_existing_history(self):
        self.assertEqual(self.signed_alert(), 200)
        _, boot = self.feed()
        self.assertTrue(boot["bootstrap"])
        self.assertEqual(boot["events"], [])
        _, nxt = self.feed(boot["cursor"])
        self.assertEqual(nxt["events"], [])

    def test_feed_cursor_missing_fails_closed(self):
        self.assertEqual(self.feed("a" * 64)[0], 409)

    def test_old_evidence_signature_rejected(self):
        self.assertEqual(self.feed(now=int(time.time())-300)[0], 401)

    def test_query_validation_and_readonly(self):
        self.assertEqual(self.request("GET", "/evidence/feed?other=something", key=self.readkey)[0], 400)
        self.assertEqual(self.request("GET", "/evidence/feed?after=a&after=b", key=self.readkey)[0], 400)
        self.assertEqual(self.db_count(), 0)


class CollectorTests(unittest.TestCase):
    def test_signature_compatible_with_receiver(self):
        key = b"q" * 32
        headers = collector.feed_headers("/evidence/feed?after=origin", key, epoch=1795000000)
        self.assertTrue(receiver.valid_evidence_signature(
            "/evidence/feed?after=origin", headers["X-KubeGuard-Evidence-Timestamp"],
            headers["X-KubeGuard-Evidence-Signature"], key, now=1795000000))
        self.assertFalse(receiver.valid_evidence_signature(
            "/evidence/feed?after=abc", headers["X-KubeGuard-Evidence-Timestamp"],
            headers["X-KubeGuard-Evidence-Signature"], key, now=1795000000))

    def test_bootstrap_skips_history_then_saves_one_and_advances(self):
        with tempfile.TemporaryDirectory() as td:
            store = Path(td) / "evidence"
            first_id = "a"*64
            second_id = "b"*64
            event = {"event_id": second_id, "status": "firing", "starts_at": "2026-11-18T09:00:00Z",
                     "ends_at": None, "received_at": "2026-11-18T09:01:00Z",
                     "values": {k: 2.0 for k in collector.INCIDENT_VALUE_KEYS}}
            def feed(cursor):
                if cursor is None:
                    return {"schema_version":1,"bootstrap":True,"cursor":first_id,"more":False,"events":[]}
                return {"schema_version":1,"bootstrap":False,"cursor":second_id if cursor==first_id else cursor,
                        "more":False,"events":[event] if cursor==first_id else []}
            report = {"schema_version":1,"incident":event,"metrics":{}}
            one = collector.poll_once(store, feed=feed, collect=lambda e: report)
            self.assertEqual(one["status"], "BOOTSTRAPPED")
            self.assertEqual(list(store.glob("incident_*.json")), [])
            two = collector.poll_once(store, feed=feed, collect=lambda e: report)
            self.assertEqual(two["status"], "EVIDENCE_SAVED")
            self.assertEqual(collector.load_cursor(store/"cursor.json"), second_id)
            self.assertEqual(len(list(store.glob("incident_*.json"))), 1)
            self.assertEqual((store/"cursor.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual((store/("incident_"+second_id+".json")).stat().st_mode & 0o777,0o600)
            self.assertEqual(store.stat().st_mode & 0o777, 0o700)
            three = collector.poll_once(store, feed=feed, collect=lambda e: report)
            self.assertEqual(three["status"], "NO_NEW_INCIDENTS")

    def test_collect_failure_preserves_cursor(self):
        with tempfile.TemporaryDirectory() as td:
            store=Path(td)/"evidence"
            collector.atomic_json(store/"cursor.json",{"schema_version":1,"cursor":"a"*64})
            e={"event_id":"b"*64}
            def feed(_):
                return {"schema_version":1,"bootstrap":False,"cursor":"b"*64,"more":False,"events":[e]}
            with self.assertRaises(RuntimeError):
                collector.poll_once(store,feed=feed,collect=lambda _: (_ for _ in ()).throw(RuntimeError("bad query")))
            self.assertEqual(collector.load_cursor(store/"cursor.json"),"a"*64)

    def test_missing_numeric_metrics_are_missing_not_zero(self):
        e={"event_id":"d"*64,"status":"firing","starts_at":"2026-11-18T09:00:00Z",
           "ends_at":None,"received_at":"2026-11-18T09:00:30Z",
           "values":{k:None for k in collector.INCIDENT_VALUE_KEYS}}
        now=datetime(2026,11,18,9,1,tzinfo=timezone.utc)
        report=collector.build_evidence(e,now=now,query=lambda expr,left,right: {"sample_count":0,"min":None,"max":None,"last":None,"points":[]})
        self.assertIn("missing_container_restarts",report["evidence_gaps"])
        self.assertIsNone(report["metrics"]["container_restarts"]["last"])
        self.assertNotIn("raw_events",report)
        self.assertNotIn("kubernetes_secrets",report)

    def test_prometheus_outage_does_not_generate_empty_successful_evidence(self):
        e={"event_id":"d"*64,"status":"firing","starts_at":"2026-11-18T09:00:00Z",
           "ends_at":None,"received_at":"2026-11-18T09:00:30Z",
           "values":{k:None for k in collector.INCIDENT_VALUE_KEYS}}
        now=datetime(2026,11,18,9,1,tzinfo=timezone.utc)
        def unavailable(*_):
            raise OSError("Prometheus outage")
        with self.assertRaises(RuntimeError):
            collector.build_evidence(e,now=now,query=unavailable)

    def test_invalid_event_field_rejected(self):
        e={"event_id":"c"*64,"status":"firing","starts_at":"2026-11-18T09:00:00Z",
           "ends_at":None,"received_at":"2026-11-18T09:00:10Z",
           "values":{k:1 for k in collector.INCIDENT_VALUE_KEYS},"password":"secret"}
        with self.assertRaises(ValueError): collector.validate_event(e)

    def test_manifest_security(self):
        base=ROOT/"monitoring/evidence-collector"
        dep=(base/"deployment.yaml").read_text()
        net=(base/"networkpolicy.yaml").read_text()
        sa=(base/"serviceaccount.yaml").read_text()
        receiver=(ROOT/"monitoring/incident-receiver/deployment.yaml").read_text()
        self.assertIn("automountServiceAccountToken: false",dep)
        self.assertIn("readOnlyRootFilesystem: true",dep)
        self.assertIn("secretName: kubeguard-evidence-read-hmac",dep)
        self.assertNotIn("kubeguard-incident-hmac",dep)
        self.assertIn("ingress: []",net)
        self.assertIn("app: kubeguard-incident-receiver",net)
        self.assertIn("automountServiceAccountToken: false",sa)
        self.assertIn("kubeguard-evidence-read-hmac",receiver)
        self.assertNotIn("kind: Role",dep+net+sa)


if __name__ == "__main__": unittest.main()
