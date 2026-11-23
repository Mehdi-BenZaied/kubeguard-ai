"""Offline regression tests for KubeGuard dynamic episode SFTP sync."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sync_kubeguard_episodes as sync


def valid_payload(start="2026-11-22T01:00:00Z"):
    def phase(status):
        metrics = {
            name: {"sample_count": 1, "min": 1, "max": 1, "last": 1}
            for name in sorted(sync.validator.METRICS)
        }
        metrics["error_rate_pct"] = {"sample_count": 0, "min": None, "max": None, "last": None}
        return {"status": status, "metrics": metrics, "evidence_gaps": ["missing_error_rate_pct"]}
    data = {"schema_version": 1, "incident_type": "high_latency", "episode_start_utc": start,
            "evidence": [phase("firing"), phase("resolved")]}
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    name = "episode_" + hashlib.sha256(start.encode()).hexdigest()[:32] + ".json"
    return name, raw


class EpisodeSyncTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.key = self.folder / "ssh-test-key"
        self.key.write_text("placeholder", encoding="ascii")
        self.name, self.raw = valid_payload()

    def test_listing_accepts_only_episode_names_and_m6_legacy(self):
        output = f"sftp> ls -1\nm6_ai_evidence.json\n{self.name}\n"
        self.assertEqual([self.name], sync.parse_sftp_listing(output))

    def test_listing_rejects_path_traversal_and_unexpected_names(self):
        for bad in ("../evil.json", "episode_BAD.json", "episode_" + "0"*32 + ".json extra"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sync.parse_sftp_listing("sftp> ls -1\n" + bad + "\n")

    def test_listing_rejects_duplicates(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            sync.parse_sftp_listing(self.name + "\n" + self.name + "\n")

    def test_validate_strict_schema_and_filename(self):
        self.assertEqual("high_latency", sync.validate_episode_bytes(self.name, self.raw)["incident_type"])
        with self.assertRaisesRegex(ValueError, "filename"):
            sync.validate_episode_bytes("episode_" + "0"*32 + ".json", self.raw)

    def test_historical_pin_enforced(self):
        old = next(iter(sync.KNOWN_PINS))
        with self.assertRaises(ValueError):
            sync.validate_episode_bytes(old, self.raw)

    def test_reject_duplicate_json_fields(self):
        with self.assertRaises(ValueError):
            sync.validate_episode_bytes(self.name, b'{"schema_version":1,"schema_version":1}')

    def test_download_once_then_skip_without_remote_read(self):
        def fake_sftp(folder, key, cmds):
            self.assertTrue(cmds[1].startswith("get "))
            (self.folder / cmds[1].split()[-1]).write_bytes(self.raw)
            return ""
        with patch.object(sync, "run_sftp", side_effect=fake_sftp):
            self.assertEqual("downloaded", sync.download_one(self.folder, self.key, self.name)[0])
        with patch.object(sync, "run_sftp", side_effect=AssertionError("No re-download")):
            self.assertEqual("already_synced", sync.download_one(self.folder, self.key, self.name)[0])
        self.assertEqual(self.raw, (self.folder / self.name).read_bytes())
        self.assertFalse(list(self.folder.glob("*.partial")))

    def test_invalid_download_refused_and_cleaned(self):
        def fake_sftp(folder, key, cmds):
            (self.folder / cmds[1].split()[-1]).write_bytes(b"{}")
            return ""
        with patch.object(sync, "run_sftp", side_effect=fake_sftp):
            with self.assertRaises(ValueError):
                sync.download_one(self.folder, self.key, self.name)
        self.assertFalse((self.folder / self.name).exists())
        self.assertFalse(list(self.folder.glob("*.partial")))

    def test_existing_invalid_file_is_not_overwritten(self):
        target = self.folder / self.name
        target.write_text("invalid", encoding="utf-8")
        with patch.object(sync, "run_sftp", side_effect=AssertionError("No download")):
            with self.assertRaises(ValueError):
                sync.download_one(self.folder, self.key, self.name)
        self.assertEqual("invalid", target.read_text())

    def test_sync_once_lists_and_downloads_then_repeat_skips(self):
        def fake_sftp(folder, key, cmds):
            (self.folder / cmds[1].split()[-1]).write_bytes(self.raw)
            return ""
        with patch.object(sync, "list_published", return_value=[self.name]), patch.object(sync, "run_sftp", side_effect=fake_sftp):
            first = sync.sync_once(self.folder, self.key)
        self.assertEqual(first["downloaded"], 1)
        with patch.object(sync, "list_published", return_value=[self.name]), patch.object(sync, "run_sftp", side_effect=AssertionError("No duplicate download")):
            second = sync.sync_once(self.folder, self.key)
        self.assertEqual(second["already_synced"], 1)
        self.assertFalse((self.folder / ".kubeguard-episodes.lock").exists())

    def test_lock_exists_prevents_overlapping_runs(self):
        (self.folder / ".kubeguard-episodes.lock").write_text("existing")
        with self.assertRaisesRegex(RuntimeError, "lock"):
            sync.sync_once(self.folder, self.key)

    def test_sftp_fails_without_leaving_file(self):
        with patch.object(sync, "run_sftp", side_effect=RuntimeError("offline")):
            with self.assertRaisesRegex(RuntimeError, "offline"):
                sync.download_one(self.folder, self.key, self.name)
        self.assertFalse((self.folder / self.name).exists())


if __name__ == "__main__":
    unittest.main()
