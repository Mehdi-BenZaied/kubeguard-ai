"""Offline tests of in-cluster polling wrapper, using a mocked collector module.
No Kubernetes, internet, Prometheus, or existing SQLite database required.
"""
from __future__ import annotations

import importlib.util
import io
import json
import signal
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect_live_training_data_k8s.py"


class InClusterWrapperTests(unittest.TestCase):
    def setUp(self):
        stub = ModuleType("collect_live_training_data")
        stub.collect_once = MagicMock()
        stub.initialize_database = MagicMock()
        stub.save_sample = MagicMock(return_value=True)
        self.old = sys.modules.get("collect_live_training_data")
        sys.modules["collect_live_training_data"] = stub
        spec = importlib.util.spec_from_file_location("collect_live_training_data_k8s_for_test", SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.stub = stub

    def tearDown(self):
        if self.old is None:
            sys.modules.pop("collect_live_training_data", None)
        else:
            sys.modules["collect_live_training_data"] = self.old

    def test_fixed_internal_endpoint_and_private_pvc(self):
        self.assertEqual(self.m.PROMETHEUS, "http://kubeguard-monitoring-kube-prometheus.monitoring.svc.cluster.local:9090")
        self.assertEqual(str(self.m.DATABASE), "/data/learning/observations.sqlite3")

    def test_idle_never_opens_database(self):
        self.stub.collect_once.return_value = {"status":"SKIPPED_IDLE", "timestamp_utc":"2026-11-16T20:00:00Z", "sample":None}
        conn, output = self.m.poll_once(1794860000, None)
        self.assertIsNone(conn)
        self.assertFalse(output["saved"])
        self.stub.initialize_database.assert_not_called()
        self.stub.save_sample.assert_not_called()

    def test_unknown_traffic_never_opens_database(self):
        self.stub.collect_once.return_value = {"status":"SKIPPED_UNKNOWN_TRAFFIC", "timestamp_utc":"2026-11-16T20:00:00Z", "sample":None}
        self.m.poll_once(1794860000, None)
        self.stub.initialize_database.assert_not_called()

    def test_active_opens_db_and_saves_only_once(self):
        sample = {"review_state":"candidate_unreviewed"}
        self.stub.collect_once.return_value = {"status":"ACTIVE_CANDIDATE_UNREVIEWED", "timestamp_utc":"2026-11-16T20:00:00Z", "sample":sample}
        conn = object()
        self.stub.initialize_database.return_value = conn
        returned, out = self.m.poll_once(1794860000, None)
        self.assertIs(returned, conn)
        self.assertTrue(out["saved"])
        self.assertNotIn("sample", out)  # No payload in logs
        self.stub.save_sample.assert_called_once_with(conn, sample)

    def test_existing_connection_reused(self):
        self.stub.collect_once.return_value = {"status":"ACTIVE_CANDIDATE_UNREVIEWED", "timestamp_utc":"2026-11-16T20:00:00Z", "sample":{"a":1}}
        conn = object()
        returned, out = self.m.poll_once(1794860000, conn)
        self.assertIs(returned, conn)
        self.stub.initialize_database.assert_not_called()

    def test_dry_run_prevents_db_writes(self):
        self.stub.collect_once.return_value = {"status":"ACTIVE_CANDIDATE_UNREVIEWED", "timestamp_utc":"2026-11-16T20:00:00Z", "sample":{"secret":"not-logged"}}
        _conn, out = self.m.poll_once(1794860000, None, dry_run=True)
        self.assertEqual(out["saved"], False)
        self.assertNotIn("secret", repr(out))
        self.stub.initialize_database.assert_not_called()

    def test_quarantine_keeps_review_state_from_collector(self):
        self.stub.collect_once.return_value = {"status":"ACTIVE_QUARANTINE_HIGH_LATENCY", "timestamp_utc":"2026-11-16T20:00:00Z", "sample":{"review_state":"quarantine_high_latency"}}
        conn = object()
        _, out = self.m.poll_once(1794860000, conn)
        self.assertEqual(out["status"], "ACTIVE_QUARANTINE_HIGH_LATENCY")
        self.stub.save_sample.assert_called_once_with(conn, {"review_state":"quarantine_high_latency"})

    def test_db_duplicate_reports_not_saved(self):
        self.stub.collect_once.return_value = {"status":"ACTIVE_CANDIDATE_UNREVIEWED", "timestamp_utc":"2026-11-16T20:00:00Z", "sample":{"a":1}}
        self.stub.save_sample.return_value = False
        _, out = self.m.poll_once(1794860000, object())
        self.assertFalse(out["saved"])

    def test_manifest_has_single_recreate_replica_and_no_token_or_k8s_rbac(self):
        base = SCRIPT.parents[1] / "monitoring" / "traffic-collector"
        deploy = (base / "deployment.yaml").read_text()
        self.assertIn("replicas: 1", deploy)
        self.assertIn("type: Recreate", deploy)
        self.assertIn("automountServiceAccountToken: false", deploy)
        self.assertIn("readOnlyRootFilesystem: true", deploy)
        self.assertIn('drop: ["ALL"]', deploy)
        self.assertNotIn("/var/run/secrets", deploy)
        policy = (base / "networkpolicy.yaml").read_text()
        self.assertIn("policyTypes:", policy)
        self.assertIn("Egress", policy)
        self.assertIn("Ingress", policy)
        self.assertNotIn("0.0.0.0/0", policy)
        self.assertTrue((base / "pvc.yaml").exists())
        self.assertTrue((base / "serviceaccount.yaml").exists())


if __name__ == "__main__":
    unittest.main()
