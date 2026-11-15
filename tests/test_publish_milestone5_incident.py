"""Offline, stdlib-only tests for the manually triggered incident publisher."""
import importlib.util
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "publish_milestone5_incident.py"
spec = importlib.util.spec_from_file_location("publisher", MODULE)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


def snap(ts, status, sufficient=True, count=2):
    return {
        "timestamp_utc": ts,
        "status": status,
        "available_replicas": 1,
        "baseline_anomaly": True,
        "sample_count_sufficient": sufficient,
        "required_latency_violations": 2,
        "consecutive_latency_violations": count,
        "latency_threshold_seconds": 0.25,
        "request_count_1m": 60,
        "request_count_5m": 120,
        "metrics": {"avg_latency_seconds": 1.2},
    }


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            snap("2026-11-15T17:51:32Z", "LOW_SAMPLE_COUNT", False, 0),
            snap("2026-11-15T17:52:02Z", "ANOMALY_PENDING", True, 1),
            snap("2026-11-15T17:52:32Z", "ANOMALY"),
            snap("2026-11-15T17:53:02Z", "ANOMALY", True, 3),
        ]

    def test_accepted_payload_schema_and_episode_start(self):
        obj = publisher.build_payload(self.rows)
        self.assertEqual(obj["status"], "firing")
        alert = obj["alerts"][0]
        self.assertEqual(alert["labels"]["alertname"], "KubeGuardAIHighLatency")
        self.assertEqual(alert["startsAt"], "2026-11-15T17:52:02Z")
        self.assertEqual(alert["values"]["request_count_1m"], 60.0)

    def test_replay_deterministic(self):
        self.assertEqual(publisher.build_payload(self.rows), publisher.build_payload(self.rows))

    def test_only_latest_episode_selected(self):
        rows = self.rows + [snap("2026-11-15T17:54:00Z", "NORMAL")]
        with self.assertRaises(ValueError):
            publisher.build_payload(rows)

    def test_pending_only_not_sent(self):
        with self.assertRaises(ValueError):
            publisher.build_payload(self.rows[:2])

    def test_low_sample_not_sent(self):
        rows = self.rows[:]
        rows[-1] = snap("2026-11-15T17:53:02Z", "ANOMALY", False, 3)
        with self.assertRaises(ValueError):
            publisher.build_payload(rows)

    def test_ml_only_not_sent(self):
        rows = self.rows[:]
        rows[-1]["baseline_anomaly"] = False
        with self.assertRaises(ValueError):
            publisher.build_payload(rows)

    def test_insufficient_confirmation_not_sent(self):
        rows = self.rows[:]
        rows[-1] = snap("2026-11-15T17:53:02Z", "ANOMALY", True, 1)
        with self.assertRaises(ValueError):
            publisher.build_payload(rows)

    def test_stale_log_rejected_when_recovered(self):
        rows = self.rows + [snap("2026-11-15T17:54:00Z", "INSUFFICIENT_DATA")]
        with self.assertRaises(ValueError):
            publisher.build_payload(rows)


if __name__ == "__main__":
    unittest.main()
