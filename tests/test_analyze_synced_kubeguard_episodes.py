"""Offline tests: no live SSH, Kubernetes or Ollama requests."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import analyze_synced_kubeguard_episodes as worker


def episode(start="2026-11-23T01:00:00Z", *, error_gap=True):
    metrics = {m: {"sample_count": 1, "min": 2, "max": 2, "last": 2}
               for m in sorted(worker.v3.v2.METRICS)}
    gaps = []
    if error_gap:
        metrics["error_rate_pct"] = {"sample_count": 0, "min": None, "max": None, "last": None}
        gaps = ["missing_error_rate_pct"]
    data = {"schema_version": 1, "incident_type": "high_latency",
            "episode_start_utc": start,
            "evidence": [{"status": status, "metrics": metrics, "evidence_gaps": gaps}
                         for status in ("firing", "resolved")]}
    name = "episode_" + hashlib.sha256(start.encode()).hexdigest()[:32] + ".json"
    raw = json.dumps(data, separators=(",", ":")).encode()
    return name, raw


class LocalEpisodeAnalysisTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        private = Path(tmp.name) / "private"
        self.episodes = private / "synced" / "episodes"
        self.episodes.mkdir(parents=True)
        self.reports = worker.report_dir(self.episodes)
        self.name, self.raw = episode()
        (self.episodes / self.name).write_bytes(self.raw)
        self.calls = 0

    def fake_model(self, evidence, options):
        self.calls += 1
        self.assertNotIn("confirm_test_delay", options)
        self.assertIn("review_error_gap", options)
        return ["review_latency"]

    def test_validates_without_model_or_report(self):
        stats = worker.run_once(self.episodes, self.reports, validate_only=True,
                                model_fn=lambda *_: self.fail("model called"))
        self.assertEqual(stats["remaining"], 1)
        self.assertFalse(list(self.reports.glob("investigation_*.json")))

    def test_analyzes_once_and_skips_next_time(self):
        first = worker.run_once(self.episodes, self.reports, model_fn=self.fake_model)
        self.assertEqual(first["analyzed"], 1)
        self.assertEqual(self.calls, 1)
        second = worker.run_once(self.episodes, self.reports,
                                 model_fn=lambda *_: self.fail("duplicate model call"))
        self.assertEqual(second["already_analyzed"], 1)
        report = json.loads((self.reports / worker.report_name(self.name)).read_text())
        self.assertEqual(report["source_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(report["source_filename"], self.name)
        self.assertTrue(any("missing error-rate" in x for x in report["analysis"]["read_only_checks"]))
        self.assertFalse(any("controlled experiment" in x for x in report["analysis"]["possible_causes"]))

    def test_unknown_model_id_rejected(self):
        with self.assertRaises(ValueError):
            worker.run_once(self.episodes, self.reports, model_fn=lambda *_: ["delete_pod"])
        self.assertFalse(list(self.reports.glob("investigation_*.json")))

    def test_model_failure_retries(self):
        def unavailable(*_):
            raise RuntimeError("Ollama offline")
        with self.assertRaisesRegex(RuntimeError, "offline"):
            worker.run_once(self.episodes, self.reports, model_fn=unavailable)
        self.assertFalse(list(self.reports.glob("investigation_*.json")))
        self.assertEqual(worker.run_once(self.episodes, self.reports,
                                        model_fn=self.fake_model)["analyzed"], 1)

    def test_report_tampering_refused_without_overwrite(self):
        worker.run_once(self.episodes, self.reports, model_fn=self.fake_model)
        path = self.reports / worker.report_name(self.name)
        doc = json.loads(path.read_text())
        doc["analysis"]["possible_causes"].append("CPU definitely caused this")
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError, "disagrees"):
            worker.run_once(self.episodes, self.reports, model_fn=lambda *_: self.fail("model called"))
        self.assertIn("definitely caused", path.read_text())

    def test_input_tampering_refused(self):
        worker.run_once(self.episodes, self.reports, model_fn=self.fake_model)
        path = self.episodes / self.name
        doc = json.loads(path.read_text())
        doc["evidence"][0]["metrics"]["cpu_millicores"]["last"] = 1
        doc["evidence"][0]["metrics"]["cpu_millicores"]["min"] = 1
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError, "disagrees"):
            worker.run_once(self.episodes, self.reports, model_fn=lambda *_: self.fail("model called"))

    def test_invalid_input_rejected(self):
        (self.episodes / self.name).write_bytes(b"{}")
        with self.assertRaises(ValueError):
            worker.run_once(self.episodes, self.reports, model_fn=lambda *_: self.fail("model called"))

    def test_no_cached_files(self):
        (self.episodes / self.name).unlink()
        stats = worker.run_once(self.episodes, self.reports, model_fn=lambda *_: self.fail("model called"))
        self.assertEqual(stats["cached"], 0)

    def test_rejects_linked_report_folder(self):
        # Mock the path type rather than creating a Windows symlink, which may
        # require Developer Mode or administrator privileges.
        with patch.object(Path, "is_symlink", autospec=True,
                          side_effect=lambda path: path == self.reports):
            with self.assertRaises(ValueError):
                worker.report_dir(self.episodes)

    def test_prevent_overlapping_runs(self):
        lock = self.reports / ".kubeguard-analysis.lock"
        lock.write_text("running")
        with self.assertRaisesRegex(RuntimeError, "lock exists"):
            worker.run_once(self.episodes, self.reports, model_fn=lambda *_: self.fail("model called"))

    def test_max_one_new_episode(self):
        name2, raw2 = episode("2026-11-23T02:00:00Z")
        (self.episodes / name2).write_bytes(raw2)
        stats = worker.run_once(self.episodes, self.reports, model_fn=self.fake_model)
        self.assertEqual((stats["analyzed"], stats["remaining"]), (1, 1))
        self.assertEqual(self.calls, 1)

    def test_write_create_only(self):
        path = self.reports / "investigation_fake.json"
        path.write_text("original")
        with self.assertRaises(ValueError):
            worker.write_create_only(self.reports, path.name, {"test": 1})
        self.assertEqual(path.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
