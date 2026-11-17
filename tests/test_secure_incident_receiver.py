"""Offline receiver security checks. Uses only localhost ephemeral HTTP server."""
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
import types
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "monitoring/incident-receiver/receiver.py"
spec = importlib.util.spec_from_file_location("kubeguard_secure_receiver_under_test", MODULE)
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


def sample(status="firing", extra=None):
    alert = {
        "status": status,
        "labels": dict(receiver.ALERT_LABELS),
        "annotations": {"summary": "Controlled test incident", "description": "No raw evidence"},
        "fingerprint": receiver.FINGERPRINT,
        "startsAt": "2026-11-16T21:31:04Z",
        "endsAt": "2026-11-16T21:37:37Z" if status == "resolved" else "",
        "values": {
            "avg_latency_seconds": 1.2,
            "latency_threshold_seconds": 0.25,
            "request_count_1m": 60,
            "request_count_5m": 80,
        },
    }
    if extra:
        alert.update(extra)
    return {"status": status, "alerts": [alert]}


def sign(key, body, now):
    stamp = str(now)
    mac = hmac.new(key, receiver.SIGNING_PREFIX + stamp.encode() + b"\n" + body, hashlib.sha256).hexdigest()
    return {"X-KubeGuard-Timestamp": stamp, "X-KubeGuard-Signature": "sha256=" + mac}


class ReceiverHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "incidents.sqlite3")
        self.keyfile = Path(self.tmp.name) / "key"
        self.key = os.urandom(32)
        self.keyfile.write_bytes(self.key)
        self.patch_db = patch.object(receiver, "DB", self.db)
        self.patch_key = patch.object(receiver, "KEY_FILE", str(self.keyfile))
        self.patch_db.start(); self.patch_key.start()
        receiver.prepare_database(self.db)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), receiver.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)
        self.patch_key.stop(); self.patch_db.stop()
        self.tmp.cleanup()

    def request(self, body=None, *, method="POST", signed=True, now=None, headers=None):
        if isinstance(body, dict):
            body = json.dumps(body, separators=(",", ":")).encode()
        body = body or b""
        ts = int(time.time()) if now is None else now
        h = {"Content-Type": "application/json"}
        if signed:
            h.update(sign(self.key, body, ts))
        if headers:
            h.update(headers)
        con = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        con.request(method, "/alerts" if method == "POST" else "/health", body=body, headers=h)
        resp = con.getresponse(); code = resp.status; resp.read(); con.close()
        return code

    def count(self):
        with sqlite3.connect(self.db) as db:
            return db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

    def test_unsigned_post_denied_and_not_written(self):
        self.assertEqual(self.request(sample(), signed=False), 401)
        self.assertEqual(self.count(), 0)

    def test_hmac_valid_single_event_and_dedup(self):
        payload = sample()
        self.assertEqual(self.request(payload), 200)
        self.assertEqual(self.request(payload), 200)
        self.assertEqual(self.count(), 1)
        with sqlite3.connect(self.db) as db:
            row = db.execute("SELECT alert_name,status,namespace,alert_json FROM incidents").fetchone()
        self.assertEqual(row[:3], ("KubeGuardAIHighLatency", "firing", "kubeguard"))
        self.assertNotIn("annotations", row[3])

    def test_firing_and_resolved_are_distinct_events(self):
        self.assertEqual(self.request(sample()), 200)
        self.assertEqual(self.request(sample("resolved")), 200)
        self.assertEqual(self.count(), 2)

    def test_body_modified_after_signing_rejected(self):
        good = json.dumps(sample(), separators=(",", ":")).encode()
        altered = json.dumps(sample("resolved"), separators=(",", ":")).encode()
        self.assertEqual(self.request(altered, signed=False, headers=sign(self.key, good, int(time.time()))), 401)
        self.assertEqual(self.count(), 0)

    def test_old_hmac_timestamp_rejected(self):
        self.assertEqual(self.request(sample(), now=int(time.time())-300), 401)
        self.assertEqual(self.count(), 0)

    def test_unknown_alert_rejected_even_if_signed(self):
        payload = sample()
        payload["alerts"][0]["labels"]["alertname"] = "UnauthorizedAlert"
        self.assertEqual(self.request(payload), 400)
        self.assertEqual(self.count(), 0)

    def test_custom_sensitive_field_rejected(self):
        self.assertEqual(self.request(sample(extra={"password": "dont-store-me"})), 400)
        self.assertEqual(self.count(), 0)

    def test_untrusted_annotation_never_stored(self):
        payload = sample()
        payload["alerts"][0]["annotations"]["description"] = "never-persist-this-string"
        self.assertEqual(self.request(payload), 200)
        with sqlite3.connect(self.db) as db:
            self.assertNotIn("never-persist-this-string", db.execute("SELECT alert_json FROM incidents").fetchone()[0])

    def test_invalid_recovery_timestamps_rejected(self):
        payload = sample("resolved", extra={"endsAt": ""})
        self.assertEqual(self.request(payload), 400)
        self.assertEqual(self.count(), 0)

    def test_health_remains_accessible(self):
        self.assertEqual(self.request(method="GET", signed=False), 200)

    def test_invalid_secret_key_denied(self):
        self.keyfile.write_bytes(b"weak")
        self.assertEqual(self.request(sample()), 503)
        self.assertEqual(self.count(), 0)

    def test_file_permissions_on_sqlite(self):
        self.assertEqual(Path(self.db).stat().st_mode & 0o777, 0o600)


class ManifestAndSenderTests(unittest.TestCase):
    def test_networkpolicy_selects_only_agent_for_receiver_ingress(self):
        policy = (ROOT / "monitoring/incident-receiver/networkpolicy.yaml").read_text()
        self.assertIn("app: kubeguard-incident-receiver", policy)
        self.assertIn("app: kubeguard-incident-agent", policy)
        self.assertIn("egress: []", policy)
        self.assertNotIn("ipBlock:", policy)

    def test_agent_remains_preview_with_secret_file(self):
        manifest = (ROOT / "monitoring/incident-agent/deployment.yaml").read_text()
        self.assertIn("secure_incident_agent_k8s.py", manifest)
        self.assertIn("automountServiceAccountToken: false", manifest)
        self.assertIn("secretName: kubeguard-incident-hmac", manifest)
        self.assertIn('args: ["--samples", "0", "--interval-sec", "30"]', manifest)

    def test_receiver_secret_and_kustomization(self):
        d = (ROOT / "monitoring/incident-receiver/deployment.yaml").read_text()
        k = (ROOT / "monitoring/incident-receiver/kustomization.yaml").read_text()
        self.assertIn("secretName: kubeguard-incident-hmac", d)
        self.assertIn("automountServiceAccountToken: false", d)
        self.assertIn("readOnlyRootFilesystem: true", d)
        self.assertIn("networkpolicy.yaml", k)
        self.assertIn("serviceaccount.yaml", k)

    def test_sender_signature_matches_receiver_validation(self):
        # Import the wrapper without bringing in Kubernetes or external services.
        core = types.SimpleNamespace(RECEIVER="http://example.invalid/alerts")
        telemetry = types.SimpleNamespace(DenyRedirects=object)
        with patch.dict(sys.modules, {"auto_incident_agent_k8s": core, "collect_live_training_data": telemetry}):
            spec = importlib.util.spec_from_file_location("tested_secure_sender", ROOT / "scripts/secure_incident_agent_k8s.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        data = b'{"test":"123"}'
        key = bytes(range(32)); now = 1794860000
        h = module.signed_headers(data, key, now=now)
        self.assertTrue(receiver.valid_signature(data, h["X-KubeGuard-Timestamp"], h["X-KubeGuard-Signature"], key, now=now))
        self.assertFalse(receiver.valid_signature(data+b"x", h["X-KubeGuard-Timestamp"], h["X-KubeGuard-Signature"], key, now=now))


if __name__ == "__main__":
    unittest.main()
