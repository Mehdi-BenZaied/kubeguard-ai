"""Offline tests for the traffic-aware collector. No cluster/Prometheus required."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collect_live_training_data as c

EPOCH = 1794850000


def active_metrics(**override):
    data = dict(request_count_1m=60.0, request_count_5m=120.0,
                available_replicas=1.0, avg_latency_seconds=.05,
                request_rate_per_s=1.0, cpu_millicores=3.0, memory_mib=57.0,
                error_rate_pct=None, p95_latency_seconds=.075, cpu_throttle_pct=0.0)
    data.update(override)
    return data


class CollectorTests(unittest.TestCase):
    def test_only_loopback_prometheus(self):
        self.assertEqual(c.local_prometheus_url('http://127.0.0.1:9090/'), 'http://127.0.0.1:9090')
        for url in ('http://10.0.0.1:9090', 'https://localhost:9090',
                    'http://user:pwd@localhost:9090', 'http://localhost:9090/a',
                    'http://localhost:9090?x=1', 'http://localhost', 'file:///tmp/a',
                    'http://localhost:nope'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                c.local_prometheus_url(url)

    def test_idle_writes_no_sample(self):
        r = c.decide_sample(active_metrics(request_count_1m=0), EPOCH, 5, 20, .25)
        self.assertEqual(r['status'], 'SKIPPED_IDLE')
        self.assertIsNone(r['sample'])

    def test_low_1m_volume_skips(self):
        self.assertEqual(c.decide_sample(active_metrics(request_count_1m=4), EPOCH, 5, 20, .25)['status'], 'SKIPPED_LOW_TRAFFIC')

    def test_low_5m_volume_skips(self):
        self.assertEqual(c.decide_sample(active_metrics(request_count_5m=19), EPOCH, 5, 20, .25)['status'], 'SKIPPED_LOW_TRAFFIC')

    def test_unknown_counts_skip(self):
        for value in (None, float('nan'), float('inf'), -1):
            with self.subTest(value=value):
                self.assertEqual(c.decide_sample(active_metrics(request_count_1m=value), EPOCH, 5, 20, .25)['status'], 'SKIPPED_UNKNOWN_TRAFFIC')

    def test_core_metric_missing_skips(self):
        self.assertEqual(c.decide_sample(active_metrics(cpu_millicores=None), EPOCH, 5, 20, .25)['status'], 'SKIPPED_MISSING_CORE_METRICS')

    def test_unavailable_replica_skips(self):
        self.assertEqual(c.decide_sample(active_metrics(available_replicas=0), EPOCH, 5, 20, .25)['status'], 'SKIPPED_UNAVAILABLE')

    def test_invalid_rate_skips(self):
        self.assertEqual(c.decide_sample(active_metrics(request_rate_per_s=0), EPOCH, 5, 20, .25)['status'], 'SKIPPED_MISSING_CORE_METRICS')

    def test_normal_is_unreviewed_not_trusted(self):
        r = c.decide_sample(active_metrics(), EPOCH, 5, 20, .25)
        self.assertEqual(r['sample']['review_state'], 'candidate_unreviewed')
        self.assertNotIn('label', r['sample'])
        self.assertFalse(r['saved'] if 'saved' in r else False)

    def test_high_latency_quarantined(self):
        r = c.decide_sample(active_metrics(avg_latency_seconds=1.2), EPOCH, 5, 20, .25)
        self.assertEqual(r['sample']['review_state'], 'quarantine_high_latency')

    def test_measured_errors_quarantined(self):
        r = c.decide_sample(active_metrics(error_rate_pct=1.1), EPOCH, 5, 20, .25)
        self.assertEqual(r['sample']['review_state'], 'quarantine_measured_errors')

    def test_optional_missing_preserved_as_null(self):
        r = c.decide_sample(active_metrics(error_rate_pct=None), EPOCH, 5, 20, .25)
        self.assertIsNone(r['sample']['error_rate_pct'])
        self.assertIn('error_rate_pct', json.loads(r['sample']['missing_optional_json']))

    def test_high_latency_priority_over_errors(self):
        r = c.decide_sample(active_metrics(error_rate_pct=5, avg_latency_seconds=.9), EPOCH, 5, 20, .25)
        self.assertEqual(r['sample']['review_state'], 'quarantine_high_latency')

    def test_idle_only_queries_two_counters(self):
        calls = []
        def query(base, promql, epoch):
            calls.append(promql)
            return 0.0
        result = c.collect_once('http://localhost:9090', EPOCH, query=query)
        self.assertEqual(result['status'], 'SKIPPED_IDLE')
        self.assertEqual(len(calls), 2)
        self.assertIn('[1m]', calls[0])
        self.assertIn('[5m]', calls[1])

    def test_active_queries_all_features(self):
        metrics = active_metrics()
        def query(base, promql, epoch):
            if '[1m]' in promql:
                return metrics['request_count_1m']
            if '[5m]' in promql and 'increase' in promql:
                return metrics['request_count_5m']
            return next((metrics[key] for key, q in c.PROMQL.items() if q == promql), None)
        result = c.collect_once('http://localhost:9090', EPOCH, query=query)
        self.assertEqual(result['sample']['review_state'], 'candidate_unreviewed')

    def test_optional_prometheus_failure_is_missing(self):
        def query(base, promql, epoch):
            if 'error' in promql:
                raise RuntimeError('down')
            if '[1m]' in promql:
                return 60
            if 'increase' in promql:
                return 120
            return next((active_metrics()[key] for key, q in c.PROMQL.items() if q == promql), None)
        r = c.collect_once('http://localhost:9090', EPOCH, query=query)
        self.assertIsNone(r['sample']['error_rate_pct'])

    def test_required_prometheus_failure_fails_closed(self):
        def query(base, promql, epoch):
            if '[1m]' in promql:
                return 60
            if 'increase' in promql:
                return 120
            raise RuntimeError('down')
        with self.assertRaises(RuntimeError):
            c.collect_once('http://localhost:9090', EPOCH, query=query)

    def test_sqlite_created_only_on_eligible_sample_and_deduped(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'private' / 'observations.sqlite3'
            self.assertFalse(path.exists())
            conn = c.initialize_database(path)
            try:
                sample = c.decide_sample(active_metrics(), EPOCH, 5, 20, .25)['sample']
                self.assertTrue(c.save_sample(conn, sample))
                self.assertFalse(c.save_sample(conn, sample))
                count = conn.execute('SELECT count(*) FROM telemetry_samples').fetchone()[0]
                self.assertEqual(count, 1)
                self.assertEqual(conn.execute('SELECT review_state FROM telemetry_samples').fetchone()[0], 'candidate_unreviewed')
                if os.name == 'posix':
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            finally:
                conn.close()

    def test_quarantine_separate_from_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            conn = c.initialize_database(Path(td) / 'db.sqlite3')
            try:
                c.save_sample(conn, c.decide_sample(active_metrics(), EPOCH, 5, 20, .25)['sample'])
                c.save_sample(conn, c.decide_sample(active_metrics(avg_latency_seconds=1.2), EPOCH + 30, 5, 20, .25)['sample'])
                rows = dict(conn.execute('SELECT review_state, count(*) FROM telemetry_samples GROUP BY review_state').fetchall())
                self.assertEqual(rows, {'candidate_unreviewed': 1, 'quarantine_high_latency': 1})
            finally:
                conn.close()

    def test_sqlite_schema_never_stores_secrets_logs_or_paths(self):
        with tempfile.TemporaryDirectory() as td:
            conn = c.initialize_database(Path(td) / 'db.sqlite3')
            try:
                sql = conn.execute('SELECT sql FROM sqlite_master WHERE name="telemetry_samples"').fetchone()[0]
                for prohibited in ('token', 'password', 'request_body', 'log_message', 'secret', 'request_url'):
                    self.assertNotIn(prohibited, sql.lower())
            finally:
                conn.close()


if __name__ == '__main__':
    unittest.main()
