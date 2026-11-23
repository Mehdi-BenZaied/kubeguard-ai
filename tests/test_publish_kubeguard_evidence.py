import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import publish_kubeguard_evidence as mod


def sample():
    metrics = {name: {'sample_count':1,'min':1.0,'max':1.0,'last':1.0} for name in mod.METRICS}
    metrics['error_rate_pct'] = {'sample_count':0, 'min':None,'max':None,'last':None}
    phase={'metrics':metrics,'evidence_gaps':['missing_error_rate_pct']}
    return {'schema_version':1,'incident_type':'high_latency','episode_start_utc':'2026-11-19T19:54:52Z',
            'evidence':[{'status':'firing',**copy.deepcopy(phase)}, {'status':'resolved',**copy.deepcopy(phase)}]}


class PublisherTests(unittest.TestCase):
    def test_valid_document(self):
        self.assertEqual(mod.validate_summary(sample())['incident_type'],'high_latency')
    def test_rejects_unapproved_metric(self):
        x=sample(); x['evidence'][0]['metrics']['customer_name']='secret'
        with self.assertRaises(ValueError): mod.encode(x)
    def test_rejects_nonfinite(self):
        x=sample(); x['evidence'][0]['metrics']['memory_mib']['last']=float('nan')
        with self.assertRaises(ValueError): mod.encode(x)
    def test_rejects_incomplete_lifecycle(self):
        x=sample(); x['evidence'].pop()
        with self.assertRaises(ValueError): mod.encode(x)
    def test_rejects_missing_metric_without_gap(self):
        x=sample(); x['evidence'][0]['evidence_gaps']=[]
        with self.assertRaises(ValueError): mod.encode(x)
    def test_atomic_create_skip_conflict(self):
        x=sample()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            name,status=mod.publish(root,x)
            self.assertEqual(status,'published')
            self.assertEqual(mod.strict_json((root/name).read_bytes()),x)
            self.assertEqual(mod.publish(root,x)[1],'already-published')
            x['evidence'][1]['metrics']['memory_mib']['last']=2.0
            x['evidence'][1]['metrics']['memory_mib']['max']=2.0
            with self.assertRaises(ValueError): mod.publish(root,x)
            self.assertEqual(len(list(root.iterdir())),1)
    def test_no_symlink_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); x=sample(); name=mod.filename_for(x)
            (root/name).symlink_to(root/'absent')
            with self.assertRaises(ValueError): mod.publish(root,x)
    def test_dry_run_never_publishes(self):
        data={'schema_version':1,'episodes':[sample()],'pending':0}
        with patch.object(mod,'read_collector',return_value=data):
            self.assertEqual(mod.main(['--dry-run']),0)
    def test_deny_duplicate_json_keys(self):
        with self.assertRaises(ValueError): mod.strict_json(b'{"k":1,"k":2}')

if __name__ == '__main__': unittest.main()
