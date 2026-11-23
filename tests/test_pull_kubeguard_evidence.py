"""Offline tests for the pinned historical SFTP download stage (no network)."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
# Support running directly from the downloaded file folder during development.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pull_kubeguard_evidence as pull


def example_payload() -> bytes:
    names = sorted(pull.validator.METRICS)
    def window(status):
        metrics = {}
        for name in names:
            if name == "error_rate_pct":
                metrics[name] = {"sample_count": 0, "min": None, "max": None, "last": None}
            else:
                metrics[name] = {"sample_count": 1, "min": 1, "max": 1, "last": 1}
        return {"status": status, "metrics": metrics,
                "evidence_gaps": ["missing_error_rate_pct"]}
    return json.dumps({"schema_version": 1, "incident_type": "high_latency",
                       "episode_start_utc": "2026-11-19T19:54:52Z",
                       "evidence": [window("firing"), window("resolved")]},
                      separators=(",", ":")).encode("utf8")


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.key = self.folder / "fake_private_key"
        self.key.write_text("not-a-real-private-key", encoding="ascii")
        self.valid = example_payload()
        self.digest = hashlib.sha256(self.valid).hexdigest()

    def fake_download(self, payload):
        def _run(target, key):
            self.assertEqual(key, self.key)
            target.write_bytes(payload)
        return _run

    def run_sync(self, payload=None):
        if payload is None:
            payload = self.valid
        with patch.object(pull, "download_via_sftp", side_effect=self.fake_download(payload)):
            return pull.sync_once(self.folder, self.key,
                                  expected_sha256=self.digest, expected_size=len(self.valid))

    def test_download_validated_atomic_and_repeat_skipped(self):
        self.assertEqual("downloaded", self.run_sync())
        destination = self.folder / pull.LOCAL_FILE
        self.assertEqual(self.valid, destination.read_bytes())
        with patch.object(pull, "download_via_sftp", side_effect=AssertionError("SFTP should not rerun")):
            self.assertEqual("already_synced", pull.sync_once(self.folder, self.key,
                  expected_sha256=self.digest, expected_size=len(self.valid)))
        self.assertFalse(list(self.folder.glob("*.partial")))
        self.assertFalse((self.folder / ".kubeguard-evidence-sync.lock").exists())

    def test_mismatch_hash_rejected_and_cleaned(self):
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            self.run_sync(payload=b"X" * len(self.valid))
        self.assertFalse((self.folder / pull.LOCAL_FILE).exists())
        self.assertFalse(list(self.folder.glob("*.partial")))
        self.assertFalse((self.folder / ".kubeguard-evidence-sync.lock").exists())

    def test_matching_hash_but_invalid_schema_rejected(self):
        garbage = b"{" + b" " * (len(self.valid) - 2) + b"}"
        with patch.object(pull, "download_via_sftp", side_effect=self.fake_download(garbage)):
            with self.assertRaises(ValueError):
                pull.sync_once(self.folder, self.key,
                    expected_sha256=hashlib.sha256(garbage).hexdigest(), expected_size=len(garbage))
        self.assertFalse((self.folder / pull.LOCAL_FILE).exists())

    def test_existing_different_file_never_overwritten(self):
        destination = self.folder / pull.LOCAL_FILE
        destination.write_bytes(b"not validated")
        with patch.object(pull, "download_via_sftp", side_effect=AssertionError("Should not download")):
            with self.assertRaises(ValueError):
                pull.sync_once(self.folder, self.key,
                    expected_sha256=self.digest, expected_size=len(self.valid))
        self.assertEqual(b"not validated", destination.read_bytes())

    def test_existing_lock_fails_closed(self):
        (self.folder / ".kubeguard-evidence-sync.lock").write_text("already running")
        with self.assertRaisesRegex(RuntimeError, "Sync lock exists"):
            self.run_sync()

    def test_failed_transfer_leaves_no_partial_or_destination(self):
        with patch.object(pull, "download_via_sftp", side_effect=RuntimeError("network failure")):
            with self.assertRaisesRegex(RuntimeError, "network failure"):
                pull.sync_once(self.folder, self.key,
                    expected_sha256=self.digest, expected_size=len(self.valid))
        self.assertFalse((self.folder / pull.LOCAL_FILE).exists())
        self.assertFalse(list(self.folder.glob("*.partial")))


if __name__ == "__main__":
    unittest.main()
