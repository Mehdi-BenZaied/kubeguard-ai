"""Offline tests for the restart-aware KubeGuard incident episode state machine."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "auto_publish_milestone5_incidents.py"
spec = importlib.util.spec_from_file_location("auto_lifecycle", MODULE)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def reading(when, status, baseline=None, sufficient=True, latency=1.2):
    return {
        "timestamp_utc": when,
        "status": status,
        "baseline_anomaly": baseline,
        "sample_count_sufficient": sufficient,
        "available_replicas": 1,
        "latency_threshold_seconds": 0.25,
        "request_count_1m": 30,
        "request_count_5m": 100,
        "metrics": {"avg_latency_seconds": latency},
    }


def advance(state, snap, ack=True):
    state, event = agent.step(state, snap)
    if ack and event:
        state["pending_payload"] = None
    return state, event


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.state = agent.new_state("preview")

    def test_no_event_for_missing_data(self):
        s, event = advance(self.state, reading("2026-11-15T10:00:00Z", "INSUFFICIENT_DATA"))
        self.assertIsNone(event)
        self.assertIsNone(s["active_start_at"])

    def test_firing_once_after_pending(self):
        s, e = advance(self.state, reading("2026-11-15T10:00:00Z", "ANOMALY_PENDING", True))
        self.assertIsNone(e)
        s, e = advance(s, reading("2026-11-15T10:00:30Z", "ANOMALY", True))
        self.assertEqual(e["status"], "firing")
        self.assertEqual(e["alerts"][0]["startsAt"], "2026-11-15T10:00:00Z")
        s, e = advance(s, reading("2026-11-15T10:01:00Z", "ANOMALY", True))
        self.assertIsNone(e)
        self.assertEqual(s["active_start_at"], "2026-11-15T10:00:00Z")

    def test_one_resolved_after_two_healthy_samples(self):
        s, _ = advance(self.state, reading("2026-11-15T10:00:00Z", "ANOMALY", True))
        s, e = advance(s, reading("2026-11-15T10:00:30Z", "ML_NOT_EVALUATED", False))
        self.assertIsNone(e)
        self.assertEqual(s["recovery_count"], 1)
        s, e = advance(s, reading("2026-11-15T10:01:00Z", "NORMAL", False))
        self.assertEqual(e["status"], "resolved")
        self.assertEqual(e["alerts"][0]["endsAt"], "2026-11-15T10:01:00Z")
        self.assertIsNone(s["active_start_at"])

    def test_missing_data_does_not_resolve(self):
        s, _ = advance(self.state, reading("2026-11-15T10:00:00Z", "ANOMALY", True))
        s, e = advance(s, reading("2026-11-15T10:00:30Z", "INSUFFICIENT_DATA", None, False))
        self.assertIsNone(e)
        self.assertIsNotNone(s["active_start_at"])

    def test_low_sample_never_resolves(self):
        s, _ = advance(self.state, reading("2026-11-15T10:00:00Z", "ANOMALY", True))
        s, e = advance(s, reading("2026-11-15T10:00:30Z", "LOW_SAMPLE_COUNT", True, False))
        self.assertIsNone(e)
        self.assertIsNotNone(s["active_start_at"])

    def test_ml_warning_is_eligible_for_recovery_when_rule_clear(self):
        s, _ = advance(self.state, reading("2026-11-15T10:00:00Z", "ANOMALY", True))
        s, _ = advance(s, reading("2026-11-15T10:00:30Z", "ML_SUSPICIOUS", False))
        s, e = advance(s, reading("2026-11-15T10:01:00Z", "ML_SUSPICIOUS", False))
        self.assertEqual(e["status"], "resolved")

    def test_outbox_blocks_next_sample_until_handled(self):
        s, e = advance(self.state, reading("2026-11-15T10:00:00Z", "ANOMALY", True), ack=False)
        self.assertIsNotNone(e)
        with self.assertRaises(ValueError):
            advance(s, reading("2026-11-15T10:00:30Z", "ANOMALY", True))

    def test_firing_and_resolved_share_fingerprint(self):
        s, fire = advance(self.state, reading("2026-11-15T10:00:00Z", "ANOMALY", True))
        s, _ = advance(s, reading("2026-11-15T10:00:30Z", "NORMAL", False))
        s, resolved = advance(s, reading("2026-11-15T10:01:00Z", "NORMAL", False))
        self.assertEqual(fire["alerts"][0]["fingerprint"], resolved["alerts"][0]["fingerprint"])
        self.assertEqual(fire["alerts"][0]["startsAt"], resolved["alerts"][0]["startsAt"])

    def test_atomic_state_roundtrip_and_mode_separation(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "state.json"
            state = agent.new_state("send")
            state["active_start_at"] = "2026-11-15T10:00:00Z"
            agent.save_state(file, state)
            self.assertEqual(agent.load_state(file, "send"), state)
            with self.assertRaises(ValueError):
                agent.load_state(file, "preview")

    def test_timestamp_ordering(self):
        s, _ = advance(self.state, reading("2026-11-15T10:00:00Z", "NORMAL", False))
        with self.assertRaises(ValueError):
            advance(s, reading("2026-11-15T10:00:00Z", "NORMAL", False))

    def test_recovery_streak_reset(self):
        s, _ = advance(self.state, reading("2026-11-15T10:00:00Z", "ANOMALY", True))
        s, _ = advance(s, reading("2026-11-15T10:00:30Z", "NORMAL", False))
        s, _ = advance(s, reading("2026-11-15T10:01:00Z", "LOW_SAMPLE_COUNT", True, False))
        self.assertEqual(s["recovery_count"], 0)
        s, e = advance(s, reading("2026-11-15T10:01:30Z", "NORMAL", False))
        self.assertIsNone(e)

    def test_new_episode_after_resolution(self):
        s, e = advance(self.state, reading("2026-11-15T10:00:00Z", "ANOMALY", True))
        s, _ = advance(s, reading("2026-11-15T10:00:30Z", "NORMAL", False))
        s, e = advance(s, reading("2026-11-15T10:01:00Z", "NORMAL", False))
        self.assertEqual(e["status"], "resolved")
        s, e = advance(s, reading("2026-11-15T10:01:30Z", "ANOMALY", True))
        self.assertEqual(e["status"], "firing")
        self.assertEqual(e["alerts"][0]["startsAt"], "2026-11-15T10:01:30Z")


if __name__ == "__main__":
    unittest.main()
