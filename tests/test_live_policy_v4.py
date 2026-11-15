"""Offline policy tests; no Prometheus, Kubernetes or real model required."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import live_detect_milestone5_v4 as v4


def raw(status="ANOMALY", baseline=True, ml=True, rps=1.0):
    return {
        "status": status,
        "baseline_anomaly": baseline,
        "isolation_forest_anomaly": ml,
        "metrics": {"request_rate_per_s": rps},
    }


def decide(snapshot, consecutive=0, n5=30, n1=10):
    return v4.apply_policy_v4(snapshot, consecutive, 2, 0.8, 2.2, n5, n1, 20, 5)


class PolicyTests(unittest.TestCase):
    def test_first_violation_pending(self):
        r, count = decide(raw())
        self.assertEqual((r["status"], count), ("ANOMALY_PENDING", 1))

    def test_second_violation_confirmed(self):
        r, count = decide(raw(), consecutive=1)
        self.assertEqual((r["status"], count), ("ANOMALY", 2))

    def test_low_five_minute_count(self):
        r, count = decide(raw(), consecutive=1, n5=4)
        self.assertEqual((r["status"], count), ("LOW_SAMPLE_COUNT", 0))
        self.assertTrue(r["baseline_anomaly"])

    def test_old_requests_but_no_recent_requests(self):
        r, count = decide(raw(), consecutive=1, n5=120, n1=0)
        self.assertEqual((r["status"], count), ("LOW_SAMPLE_COUNT", 0))

    def test_missing_counter_fails_closed(self):
        r, count = decide(raw(), consecutive=1, n5=None)
        self.assertEqual((r["status"], count), ("REQUEST_COUNT_UNKNOWN", 0))

    def test_ml_only_no_recent_traffic_is_advisory_only(self):
        r, count = decide(raw(status="ML_SUSPICIOUS", baseline=False), n5=3, n1=1)
        self.assertEqual((r["status"], count), ("ML_NOT_EVALUATED", 0))
        self.assertFalse(r["ml_decision_used"])

    def test_ml_only_with_enough_samples_is_suspicious(self):
        r, count = decide(raw(status="ML_SUSPICIOUS", baseline=False))
        self.assertEqual((r["status"], count), ("ML_SUSPICIOUS", 0))
        self.assertTrue(r["ml_decision_used"])

    def test_ml_outside_rps_envelope(self):
        r, count = decide(raw(status="ML_SUSPICIOUS", baseline=False, rps=0.4))
        self.assertEqual((r["status"], count), ("ML_NOT_EVALUATED", 0))

    def test_unavailable_takes_precedence(self):
        r, count = decide(raw(status="UNAVAILABLE", baseline=False), n5=None, n1=None)
        self.assertEqual((r["status"], count), ("UNAVAILABLE", 0))

    def test_missing_metrics_takes_precedence(self):
        r, count = decide(raw(status="INSUFFICIENT_DATA", baseline=False), n5=None, n1=None)
        self.assertEqual((r["status"], count), ("INSUFFICIENT_DATA", 0))

    def test_normal_if_enough_samples(self):
        r, count = decide(raw(status="NORMAL", baseline=False, ml=False))
        self.assertEqual((r["status"], count), ("NORMAL", 0))

    def test_consecutive_reset_by_nonviolation(self):
        r, count = decide(raw(status="NORMAL", baseline=False, ml=False), consecutive=1)
        self.assertEqual((r["status"], count), ("NORMAL", 0))


if __name__ == "__main__":
    unittest.main()
