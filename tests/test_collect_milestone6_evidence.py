"""Offline tests for KubeGuard evidence collection; no MicroK8s/Prometheus needed."""
from __future__ import annotations

import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import collect_milestone6_evidence as collector


NOW = datetime(2026, 11, 15, 19, 0, tzinfo=timezone.utc)


def sample_incident(resolved=True):
    return {
        "firing": {
            "alert_name": collector.ALERT, "status": "firing", "namespace": "kubeguard",
            "fingerprint": "fp123", "starts_at": "2026-11-15T18:46:13Z",
            "received_at": "2026-11-15T18:46:43Z", "event_id": "abc",
            "values_json": json.dumps({"avg_latency_seconds": 1.2}),
        },
        "resolved": {
            "status": "resolved", "fingerprint": "fp123", "starts_at": "2026-11-15T18:46:13Z",
            "ends_at": "2026-11-15T18:52:43Z", "received_at": "2026-11-15T18:52:44Z",
            "event_id": "xyz", "values_json": json.dumps({"avg_latency_seconds": .05}),
        } if resolved else None,
    }


class CollectorTests(unittest.TestCase):
    def test_sql_script_compiles(self):
        compile(collector.SQL_SCRIPT, "<remote sql>", "exec")

    def test_sql_script_selects_matching_resolved_event(self):
        # Run the EXACT remote query against an isolated SQLite fixture.
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "incidents.sqlite3"
            with sqlite3.connect(db) as conn:
                conn.execute("""CREATE TABLE incidents (
                    event_id TEXT, received_at TEXT, alert_name TEXT, status TEXT,
                    namespace TEXT, pod TEXT, container TEXT, fingerprint TEXT,
                    starts_at TEXT, ends_at TEXT, values_json TEXT, alert_json TEXT)""")
                def insert(id, start, status, ends="", fp="fp"):
                    conn.execute("INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                 (id,"2026-11-15T19:00Z",collector.ALERT,status,"kubeguard",None,None,
                                  fp,start,ends,"{}","{}"))
                insert("old", "2026-11-15T17:00:00Z", "firing")
                insert("new", "2026-11-15T18:46:13Z", "firing")
                insert("resolved", "2026-11-15T18:46:13Z", "resolved", "2026-11-15T18:52:43Z")
                insert("unrelated", "2026-11-15T18:46:13Z", "resolved", "2026-11-15T18:52:44Z", fp="other")
            script = collector.SQL_SCRIPT.replace("file:/data/incidents.sqlite3?mode=ro", f"file:{db}?mode=ro")
            response = subprocess.run([sys.executable, "-c", script, ""], capture_output=True,
                                      text=True, check=True)
            data = json.loads(response.stdout)
            self.assertEqual(data["firing"]["event_id"], "new")
            self.assertEqual(data["resolved"]["event_id"], "resolved")
            response = subprocess.run([sys.executable, "-c", script, "2026-11-15T17:00:00Z"],
                                      capture_output=True, text=True, check=True)
            data = json.loads(response.stdout)
            self.assertEqual(data["firing"]["event_id"], "old")
            self.assertIsNone(data["resolved"])

    def test_episode_parse_requires_timezone(self):
        with self.assertRaises(ValueError):
            collector.parse_utc("2026-11-15T18:46:13")
        self.assertEqual(collector.iso(collector.parse_utc("2026-11-15T18:46:13Z")),
                         "2026-11-15T18:46:13Z")

    def test_prometheus_only_localhost(self):
        self.assertEqual(collector.safe_local_prometheus("http://127.0.0.1:9090/"),
                         "http://127.0.0.1:9090")
        for url in ("https://127.0.0.1:9090", "http://example.org:9090",
                    "http://127.0.0.1:9090/secret", "http://root@localhost:9090",
                    "http://127.0.0.1:9090?x=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                collector.safe_local_prometheus(url)

    def test_incident_summary_values_and_status(self):
        result = collector.incident_summary(sample_incident())
        self.assertTrue(result["resolved"])
        self.assertEqual(result["resolution_at"], "2026-11-15T18:52:43Z")
        self.assertEqual(result["firing_values"]["avg_latency_seconds"], 1.2)

    def test_unresolved_incident_not_assumed_recovered(self):
        summary = collector.incident_summary(sample_incident(False))
        self.assertFalse(summary["resolved"])
        self.assertIsNone(summary["resolution_at"])

    def test_window_bounded_to_incident_and_margin(self):
        summary = collector.incident_summary(sample_incident())
        start, end, warn = collector.evidence_window(summary, NOW, 5, 5)
        self.assertEqual(collector.iso(start), "2026-11-15T18:41:13Z")
        self.assertEqual(collector.iso(end), "2026-11-15T18:57:43Z")
        self.assertEqual(warn, [])

    def test_window_capped_for_unresolved_old_incident(self):
        summary = collector.incident_summary(sample_incident(False))
        start, end, warn = collector.evidence_window(summary, NOW + timedelta(hours=2), 5, 5)
        self.assertEqual(end - start, timedelta(minutes=60))
        self.assertTrue(warn)

    def test_query_range_parses_valid_values_and_skips_nan(self):
        response = {"status":"success", "data":{"resultType":"matrix", "result":[
            {"metric": {}, "values": [[1794769200,"1.2"],[1794769230,"NaN"], [1794769260,"0.05"]]}
        ]}}
        with patch.object(collector, "urlopen", return_value=io.BytesIO(json.dumps(response).encode())) as opener:
            result = collector.query_prometheus("http://127.0.0.1:9090", "up", NOW, NOW, 30)
        self.assertEqual([r["value"] for r in result], [1.2, 0.05])
        self.assertIn("query=up", opener.call_args.args[0])

    def test_reject_multiple_prometheus_series(self):
        response = {"status":"success","data":{"resultType":"matrix","result":[{},{}]}}
        with patch.object(collector, "urlopen", return_value=io.BytesIO(json.dumps(response).encode())):
            with self.assertRaises(RuntimeError):
                collector.query_prometheus("http://127.0.0.1:9090", "foo", NOW, NOW, 30)

    def test_prometheus_missing_is_not_zero(self):
        self.assertEqual(collector.summarize_series([]), {"sample_count":0,"min":None,
                         "max":None,"first":None,"last":None})

    def test_prometheus_error_is_nonfatal_per_series(self):
        with patch.object(collector, "query_prometheus", side_effect=RuntimeError("offline")):
            data = collector.collect_prometheus("http://127.0.0.1:9090", NOW, NOW, 30)
        self.assertEqual(len(data["series"]), len(collector.QUERIES))
        self.assertTrue(data["warnings"])
        self.assertEqual(data["series"]["avg_latency_seconds"]["points"], [])

    def test_pod_filter_and_restart_summary(self):
        items = {"items": [
            {"metadata":{"name":"good","labels":{"app":"kubeguard-api"}},
             "spec":{"nodeName":"a"},"status":{"phase":"Running", "conditions":[{"type":"Ready","status":"True"}],
              "containerStatuses":[{"name":"kubeguard-api","restartCount":2,"ready":True,
                                    "lastState":{"terminated":{"reason":"Error","exitCode":1}}}]}},
            {"metadata":{"name":"other","labels":{"app":"other"}},"status":{"phase":"Running"}},
        ]}
        pod = collector.summarize_pods(items, {"app":"kubeguard-api"})
        self.assertEqual(len(pod), 1)
        self.assertEqual(pod[0]["containers"][0]["restart_count"], 2)
        self.assertEqual(pod[0]["pod_ready"], True)

    def test_events_only_for_relevant_pods(self):
        raw = {"items":[
            {"involvedObject":{"name":"good"},"reason":"BackOff","message":"bad"},
            {"involvedObject":{"name":"other"},"reason":"Error","message":"not relevant"},
        ]}
        events = collector.summarize_events(raw, {"good"})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["reason"], "BackOff")

    def test_kubectl_failure_does_not_claim_success(self):
        with patch.object(collector,"run_kubectl", side_effect=RuntimeError("forbidden")):
            result = collector.collect_kubernetes("2026-11-15T19:00:00Z")
        self.assertEqual(len(result["warnings"]),3)
        self.assertIsNone(result["deployment"])

    def test_cli_bundle_files_and_markdown_written_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Use dynamic timestamps so the incident always predates the test clock.
            now = datetime.now(timezone.utc)
            raw = sample_incident()
            start = now - timedelta(minutes=10)
            end = now - timedelta(minutes=5)
            raw["firing"]["starts_at"] = collector.iso(start)
            raw["resolved"]["starts_at"] = collector.iso(start)
            raw["resolved"]["ends_at"] = collector.iso(end)
            stats = {name:{"query":query, "summary":collector.summarize_series([]),
                           "points":[], "error":None} for name,query in collector.QUERIES.items()}
            metrics = {"kind":"historical_time_series", "series":stats, "warnings":["no metrics"]}
            k8s = {"kind":"current_snapshot_not_historical", "observed_at":collector.iso(now),
                   "deployment":None,"pods":[],"recent_events":[],"warnings":[]}
            with patch.object(collector,"fetch_incident",return_value=raw), \
                 patch.object(collector,"collect_prometheus",return_value=metrics), \
                 patch.object(collector,"collect_kubernetes",return_value=k8s):
                json_path, md_path, output = collector.collect(None,"http://localhost:9090",5,5,30,Path(tmp))
            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())
            self.assertEqual(json.loads(json_path.read_text())["schema_version"], 1)
            self.assertIn("CURRENT state", md_path.read_text())
            self.assertTrue(any("no metrics" in item for item in output["warnings"]))


if __name__ == "__main__":
    unittest.main()
