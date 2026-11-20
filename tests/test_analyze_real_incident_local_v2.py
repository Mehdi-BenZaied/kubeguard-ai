"""Offline regression tests: no Ollama or cluster required."""
import importlib.util
import unittest
from pathlib import Path

MODULE=Path(__file__).resolve().parents[1] / 'scripts' / 'analyze_real_incident_local_v2.py'
spec=importlib.util.spec_from_file_location('kubeguard_v2',MODULE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def evidence():
    e={'schema_version':1,'incident_type':'high_latency',
       'episode_start_utc':'2026-11-19T19:54:52Z','evidence':[]}
    for state in ('firing','resolved'):
        metrics={n:{'sample_count':1,'min':1.,'max':1.,'last':1.} for n in m.METRICS}
        metrics['error_rate_pct']={'sample_count':0,'min':None,'max':None,'last':None}
        metrics['cpu_millicores']={'sample_count':3,'min':2.,'max':3.,'last':2.5}
        e['evidence'].append({'status':state,'metrics':metrics,'evidence_gaps':['missing_error_rate_pct']})
    return e


class GroundingTests(unittest.TestCase):
    def test_numeric_facts_cannot_be_rewritten_by_model(self):
        e=m.validate_evidence(evidence())
        facts=m.deterministic_observations(e)
        self.assertEqual(len(facts),20)
        self.assertTrue(any('firing window: cpu_millicores, n=3, min=2, max=3, last=2.5.' == x for x in facts))
        self.assertTrue(any('firing: error_rate_pct unavailable' in x for x in facts))
        self.assertFalse(any('CPU pressure' in x for x in facts))

    def test_unknowns_preserve_missing_error_metric(self):
        unknowns=m.deterministic_unknowns(evidence())
        self.assertTrue(any('missing_error_rate_pct' in x for x in unknowns))
        self.assertTrue(any('Desired replica count' in x for x in unknowns))

    def test_invalid_evidence_rejected(self):
        e=evidence();e['evidence'][1]['metrics']['error_rate_pct']['last']=0
        with self.assertRaises(ValueError):m.validate_evidence(e)

    def test_unapproved_metric_rejected(self):
        e=evidence();e['evidence'][0]['metrics']['api_key']='secret'
        with self.assertRaises(ValueError):m.validate_evidence(e)

    def test_obvious_mutating_or_sensitive_suggestions_rejected(self):
        for suggestion in ['kubectl delete pod a', 'kubectl apply -f abc', 'kubectl exec pod -- bash',
                           'Get secrets from Kubernetes', 'sudo systemctl restart kubelet']:
            with self.subTest(suggestion=suggestion):
                with self.assertRaises(ValueError):m.validate_model_suggestions([suggestion])

    def test_read_only_suggestions_allowed(self):
        m.validate_model_suggestions(['Compare the recorded p95 values to the baseline in Grafana.'])

if __name__=='__main__':unittest.main()
