"""Offline bounded-output tests; do not connect to Ollama or Kubernetes."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import analyze_real_incident_local_v3 as m


def evidence():
    e = {"schema_version": 1, "incident_type": "high_latency",
         "episode_start_utc": "2026-11-19T19:54:52Z", "evidence": []}
    for status in ("firing", "resolved"):
        metrics = {n: {"sample_count": 1, "min": 1.0, "max": 1.0, "last": 1.0}
                   for n in m.v2.METRICS}
        metrics["error_rate_pct"] = {"sample_count": 0, "min": None, "max": None, "last": None}
        metrics["cpu_millicores"] = {"sample_count": 1, "min": 2.5, "max": 2.5, "last": 2.5}
        e["evidence"].append({"status": status, "metrics": metrics,
                              "evidence_gaps": ["missing_error_rate_pct"]})
    return m.v2.validate_evidence(e)


class BoundedReportTests(unittest.TestCase):
    def test_approved_ids_only(self):
        options = m.permitted_checks(evidence())
        self.assertEqual(m.validate_ids({"check_ids": ["review_cpu"]}, options), ["review_cpu"])

    def test_unknown_id_rejected(self):
        with self.assertRaises(ValueError):
            m.validate_ids({"check_ids": ["kubectl delete pods"]}, m.permitted_checks(evidence()))

    def test_free_text_and_extra_fields_rejected(self):
        options = m.permitted_checks(evidence())
        for payload in ({"check_ids": ["review_cpu"], "diagnosis": "CPU caused latency"},
                        {"hypotheses": ["CPU saturation"]},
                        {"check_ids": "review_cpu"}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                m.validate_ids(payload, options)

    def test_duplicate_and_too_many_ids_rejected(self):
        opts = m.permitted_checks(evidence())
        for ids in (["review_cpu", "review_cpu"], list(opts)[:5], []):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                m.validate_ids({"check_ids": ids}, opts)

    def test_missing_error_rate_always_flagged(self):
        r = m.build_report(evidence(), ["review_latency"])
        self.assertTrue(any("missing error-rate" in s for s in r["analysis"]["read_only_checks"]))
        self.assertTrue(any("NOT zero" in s for s in r["analysis"]["observations"]))

    def test_no_invented_dynamic_model_prose(self):
        r = m.build_report(evidence(), ["review_latency", "review_cpu"])
        self.assertEqual(r["model_selected_check_ids"], ["review_latency", "review_cpu"])
        self.assertTrue(all("UNVERIFIED HYPOTHESIS" in h for h in r["analysis"]["possible_causes"]))
        self.assertTrue(all(c in m.CHECKS.values() for c in r["analysis"]["read_only_checks"]))

    def test_no_error_rate_gap_no_extra_check(self):
        e = evidence()
        for phase in e["evidence"]:
            phase["evidence_gaps"] = []
            phase["metrics"]["error_rate_pct"] = {"sample_count": 1, "min": 0.0, "max": 0.0, "last": 0.0}
        validated = m.v2.validate_evidence(e)
        options = m.permitted_checks(validated)
        self.assertNotIn("review_error_gap", options)
        self.assertEqual(len(m.build_report(validated, ["review_latency"])["analysis"]["read_only_checks"]), 1)


if __name__ == "__main__":
    unittest.main()
