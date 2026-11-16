"""Offline tests. In the full repository, these use the existing lifecycle module."""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import auto_incident_agent_k8s as agent
import auto_publish_milestone5_incidents as lifecycle

EPOCH = 1794860000


def metrics(*, count1=30, count5=90, replicas=1, latency=.05, rate=1):
    def query(_base, expr, _epoch):
        if 'increase(' in expr and '[1m]' in expr:
            return count1
        if 'increase(' in expr and '[5m]' in expr:
            return count5
        if expr == agent.PROMQL['available_replicas']:
            return replicas
        if expr == agent.PROMQL['avg_latency_seconds']:
            return latency
        if expr == agent.PROMQL['request_rate_per_s']:
            return rate
        raise AssertionError('Unexpected PromQL query: '+expr)
    return query


class RuleDetectionTests(unittest.TestCase):
    def test_idle_does_not_query_latency(self):
        result, n = agent.detect_once(EPOCH, 9, query=metrics(count1=0, count5=0))
        self.assertEqual(result['status'], 'SKIPPED_IDLE')
        self.assertEqual(n, 0)
        self.assertIsNone(result['baseline_anomaly'])

    def test_low_traffic_never_confirms(self):
        for c1,c5 in [(4,120),(30,19)]:
            with self.subTest(c1=c1,c5=c5):
                row,n = agent.detect_once(EPOCH,10,query=metrics(count1=c1,count5=c5,latency=1.5))
                self.assertEqual(row['status'],'LOW_SAMPLE_COUNT')
                self.assertEqual(n,0)

    def test_unknown_count_fails_closed(self):
        row,n = agent.detect_once(EPOCH,1,query=metrics(count1=None))
        self.assertEqual(row['status'],'REQUEST_COUNT_UNKNOWN')
        self.assertEqual(n,0)

    def test_unavailability_not_mislabeled_latency(self):
        row,n=agent.detect_once(EPOCH,3,query=metrics(replicas=0,latency=2))
        self.assertEqual(row['status'],'UNAVAILABLE')
        self.assertEqual(n,0)

    def test_missing_latency_fails_closed(self):
        row,n=agent.detect_once(EPOCH,7,query=metrics(latency=None))
        self.assertEqual(row['status'],'INSUFFICIENT_DATA')
        self.assertIsNone(row['baseline_anomaly'])
        self.assertEqual(n,0)

    def test_two_confirmations(self):
        first,n=agent.detect_once(EPOCH,0,query=metrics(latency=1.2))
        second,n=agent.detect_once(EPOCH+30,n,query=metrics(latency=1.2))
        self.assertEqual(first['status'],'ANOMALY_PENDING')
        self.assertEqual(second['status'],'ANOMALY')
        self.assertTrue(second['sample_count_sufficient'])
        self.assertEqual(n,2)

    def test_normal_resets_violations(self):
        row,n=agent.detect_once(EPOCH,2,query=metrics(latency=.04))
        self.assertEqual(row['status'],'NORMAL')
        self.assertIs(row['baseline_anomaly'], False)
        self.assertEqual(n,0)


class LifecycleTests(unittest.TestCase):
    def test_preview_lifecycle_and_unreliable_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            file=Path(td)/'preview.json'
            state=lifecycle.new_state('preview')
            calls=[]
            never_send=lambda _: calls.append('unexpected')
            times=[EPOCH+i*30 for i in range(7)]
            sequence=[metrics(latency=1.2), metrics(latency=1.2),
                      metrics(count1=0,count5=0), metrics(latency=.05),
                      metrics(count1=None), metrics(latency=.05), metrics(latency=.05)]
            outs=[]
            for t,query in zip(times,sequence):
                state,out=agent.tick(t,state,file,False,query=query,publisher=never_send)
                outs.append(out)
            self.assertEqual(outs[0]['event'],None)
            self.assertEqual(outs[1]['event'],'firing')
            self.assertTrue(outs[2]['active_incident'])
            self.assertTrue(outs[4]['active_incident'])
            self.assertEqual(outs[-1]['event'],'resolved')
            self.assertFalse(outs[-1]['active_incident'])
            self.assertEqual(calls,[])
            self.assertIsNone(lifecycle.load_state(file,'preview')['pending_payload'])

    def test_send_failure_preserves_pending_event_for_retry(self):
        with tempfile.TemporaryDirectory() as td:
            file=Path(td)/'send.json'
            state=lifecycle.new_state('send')
            state,_=agent.tick(EPOCH,state,file,True,query=metrics(latency=1.2),publisher=lambda p: None)
            sent=[]
            def fail(_):
                raise OSError('receiver unavailable')
            with self.assertRaises(OSError):
                agent.tick(EPOCH+30,state,file,True,query=metrics(latency=1.2),publisher=fail)
            recovered=lifecycle.load_state(file,'send')
            self.assertEqual(recovered['pending_payload']['status'],'firing')
            def succeed(payload):
                sent.append(payload)
            recovered,out=agent.tick(EPOCH+60,recovered,file,True,query=metrics(latency=1.2),publisher=succeed)
            self.assertEqual(len(sent),1)
            self.assertEqual(sent[0]['status'],'firing')
            self.assertEqual(sent[0]['alerts'][0]['startsAt'],
                             datetime.fromtimestamp(EPOCH,timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z'))
            self.assertIsNone(lifecycle.load_state(file,'send')['pending_payload'])

    def test_restart_gap_resets_old_confirmations(self):
        state=lifecycle.new_state('preview')
        state['consecutive_latency_violations']=1
        state['candidate_start_at']='2026-11-01T10:00:00Z'
        state['last_snapshot_at']='2026-11-01T10:00:00Z'
        state['active_start_at']='2026-11-01T09:00:00Z'
        agent._reset_stale_confirmation(state,EPOCH)
        self.assertEqual(state['consecutive_latency_violations'],0)
        self.assertIsNone(state['candidate_start_at'])
        self.assertEqual(state['active_start_at'],'2026-11-01T09:00:00Z')

    def test_state_mode_separated(self):
        self.assertNotEqual(agent.STATE_DIR/'preview_state.json',agent.STATE_DIR/'send_state.json')

    def test_fixed_urls_and_no_external_config(self):
        self.assertEqual(agent.PROMETHEUS,'http://kubeguard-monitoring-kube-prometheus.monitoring.svc.cluster.local:9090')
        self.assertEqual(agent.RECEIVER,'http://kubeguard-incident-receiver.monitoring.svc.cluster.local:8081/alerts')

    def test_security_manifests(self):
        base=ROOT/'monitoring/incident-agent'
        dep=(base/'deployment.yaml').read_text()
        net=(base/'networkpolicy.yaml').read_text()
        sa=(base/'serviceaccount.yaml').read_text()
        self.assertIn('automountServiceAccountToken: false',dep)
        self.assertIn('readOnlyRootFilesystem: true',dep)
        self.assertIn('type: Recreate',dep)
        self.assertIn('replicas: 1',dep)
        self.assertIn('ingress: []',net)
        self.assertIn('port: 9090',net)
        self.assertIn('port: 8081',net)
        self.assertIn('automountServiceAccountToken: false',sa)
        self.assertNotIn('kind: Role',dep+net+sa)
        self.assertNotIn('"--send"',dep)


if __name__=='__main__':
    unittest.main()
