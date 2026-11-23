#!/usr/bin/env python3
"""Windows-only, one-shot read-only SFTP discovery and sync for KubeGuard episodes.

- Runs as normal Windows user with a previously unlocked SSH key in ssh-agent.
- Uses pinned, previously accepted OpenSSH known_hosts and StrictHostKeyChecking.
- Remote account is restricted to read-only SFTP under /evidence.
- Downloads only episode_<32 lowercase hex>.json; never raw collector documents.
- Strictly checks the exported schema, metric allowlist, filename derived from
  episode start, duplicate JSON fields and bounded sizes before publication.
- Files are cached privately; existing files are validated and not overwritten.
- Never invokes Ollama, a Kubernetes client, SSH shell commands or remediation.

Deliberately *not* a scheduled service or remote publisher; run manually first.
Requires analyze_real_incident_local_v2.py beside this script.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from pathlib import Path

import analyze_real_incident_local_v2 as validator

REMOTE = "kubeguard-export@192.168.118.132"
EPISODE_RE = re.compile(r"episode_[a-f0-9]{32}\.json\Z")
MAX_FILE_BYTES = 32_768
MAX_DISCOVERED = 100
MAX_NEW_PER_RUN = 10
# The first historical export has been independently verified by the user
# against Ubuntu SHA256. Future episodes are checked by schema+SSH identity;
# digest pins for those files are only established locally on first download.
KNOWN_PINS = {
    "episode_5fa1537f82950d2d6ea4b7218bb78a92.json":
        "8f6674ad58c4c40ba2d6ffce92fa9e4e15d2d4ba1dc0b65bd10ae95ff33972de",
}


def sync_dir() -> Path:
    localapp = os.environ.get("LOCALAPPDATA")
    if not localapp:
        raise ValueError("LOCALAPPDATA must be set; use Windows PowerShell")
    private = Path(localapp) / "KubeGuardAI" / "private"
    if not private.is_dir() or private.is_symlink():
        raise ValueError("Private KubeGuardAI directory missing or linked")
    synced = private / "synced"
    if synced.is_symlink():
        raise ValueError("Refusing linked synced directory")
    synced.mkdir(mode=0o700, exist_ok=True)
    folder = synced / "episodes"
    if folder.is_symlink():
        raise ValueError("Refusing linked episodes directory")
    folder.mkdir(mode=0o700, exist_ok=True)
    if not folder.is_dir():
        raise ValueError("Invalid episodes directory")
    return folder


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_episode_bytes(filename: str, raw: bytes) -> dict:
    if not EPISODE_RE.fullmatch(filename):
        raise ValueError("Unapproved episode filename")
    if not 0 < len(raw) <= MAX_FILE_BYTES:
        raise ValueError("Unsafe episode size")
    data = validator.validate_evidence(validator.parse_json_no_duplicates(raw))
    episode = data["episode_start_utc"]
    expected = "episode_" + hashlib.sha256(episode.encode("ascii")).hexdigest()[:32] + ".json"
    if expected != filename:
        raise ValueError("Episode filename does not match the validated start time")
    pinned = KNOWN_PINS.get(filename)
    if pinned is not None and sha256_bytes(raw) != pinned:
        raise ValueError("Verified historical episode SHA256 mismatch")
    return data


def verify_existing(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Existing cached evidence is missing or linked")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Existing cached evidence is too large")
    return validate_episode_bytes(path.name, path.read_bytes())


def parse_sftp_listing(stdout: str) -> list[str]:
    names = []
    for row in stdout.splitlines():
        value = row.strip()
        if not value or value.startswith("sftp> "):
            continue
        # This directory also contains one deliberately published historical
        # m6_* test file. Everything else must conform to our episode format.
        if value == "m6_ai_evidence.json":
            continue
        if not EPISODE_RE.fullmatch(value):
            raise ValueError("Unexpected item in restricted SFTP listing")
        names.append(value)
        if len(names) > MAX_DISCOVERED:
            raise ValueError("Excessive number of published episodes")
    if len(names) != len(set(names)):
        raise ValueError("Duplicate episode in SFTP listing")
    return sorted(names)


def run_sftp(folder: Path, key: Path, commands: list[str]) -> str:
    """Execute only fixed SFTP protocol operations, not remote shell commands."""
    if not key.is_file() or key.is_symlink():
        raise ValueError("SSH private key missing or linked")
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError("Unsafe local output folder")
    # Batch files live in the private folder; never include user-supplied paths
    # or SFTP metacharacters in the remote commands.
    with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", newline="\n",
                                     prefix=".kubeguard-", suffix=".sftp",
                                     dir=folder, delete=False) as f:
        batch = Path(f.name)
        f.write("\n".join(commands) + "\n")
    try:
        args = [
            "sftp", "-b", str(batch),
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no", "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
            "-i", str(key), REMOTE,
        ]
        try:
            result = subprocess.run(args, capture_output=True, text=True,
                                    errors="replace", timeout=60, check=False)
        except FileNotFoundError as exc:
            raise RuntimeError("Windows OpenSSH sftp.exe not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("SFTP timed out (no report saved)") from exc
        if result.returncode != 0:
            raise RuntimeError("SFTP failed; verify the SSH agent, host key and VM network. "
                               f"Exit code {result.returncode}; {result.stderr.strip()[:240]}")
        if len(result.stdout) > 65_536:
            raise ValueError("SFTP listing or response unexpectedly large")
        return result.stdout
    finally:
        batch.unlink(missing_ok=True)


def list_published(folder: Path, key: Path) -> list[str]:
    return parse_sftp_listing(run_sftp(folder, key, ["ls -1"]))


def download_one(folder: Path, key: Path, filename: str) -> tuple[str, dict]:
    if not EPISODE_RE.fullmatch(filename):
        raise ValueError("Unapproved download name")
    target = folder / filename
    if target.is_symlink():
        raise ValueError("Refusing symlinked destination")
    if target.exists():
        return "already_synced", verify_existing(target)

    with tempfile.NamedTemporaryFile(mode="wb", prefix=".kubeguard-download-",
                                     suffix=".partial", dir=folder, delete=False) as f:
        pending = Path(f.name)
    try:
        local = folder.resolve().as_posix()
        if any(c in local for c in ('"', '\r', '\n')):
            raise ValueError("Unsafe local SFTP directory")
        # 'get' is read-only on the server; file names match a strict regex.
        # The pending file is created within our private working directory.
        run_sftp(folder, key, [f'lcd "{local}"', f'get {filename} {pending.name}'])
        if pending.is_symlink() or pending.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("Downloaded file too large or linked")
        raw = pending.read_bytes()
        evidence = validate_episode_bytes(filename, raw)
        if target.exists() or target.is_symlink():
            raise RuntimeError("Destination appeared mid-sync; refusing overwrite")
        # Atomic create-only publication on local NTFS; os.link fails if the
        # destination already exists. Unlinking pending leaves one real file.
        os.link(pending, target)
        return "downloaded", evidence
    finally:
        pending.unlink(missing_ok=True)


def sync_once(folder: Path, key: Path) -> dict[str, int]:
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError("Unsafe episode sync destination")
    lock = folder / ".kubeguard-episodes.lock"
    if lock.is_symlink():
        raise ValueError("Linked sync lock")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RuntimeError("Another sync may be running (lock exists)") from exc
    os.close(fd)
    stats = {"discovered": 0, "downloaded": 0, "already_synced": 0, "remaining": 0}
    try:
        names = list_published(folder, key)
        stats["discovered"] = len(names)
        for index, filename in enumerate(names):
            target = folder / filename
            if target.is_symlink():
                raise ValueError("Linked cached episode")
            if target.exists():
                verify_existing(target)  # Fail closed on local corruption
                print("Already synced:", filename)
                stats["already_synced"] += 1
                continue
            if stats["downloaded"] >= MAX_NEW_PER_RUN:
                stats["remaining"] += 1
                continue
            status, evidence = download_one(folder, key, filename)
            stats[status] += 1
            print("Downloaded and validated:", filename,
                  "|", evidence["incident_type"],
                  "|", ",".join(e["status"] for e in evidence["evidence"]),
                  "| SHA256", hashlib.sha256((folder / filename).read_bytes()).hexdigest().upper())
        return stats
    finally:
        lock.unlink(missing_ok=True)


def main() -> int:
    print("KubeGuard read-only SFTP episode sync (no AI inference)")
    key = Path.home() / ".ssh" / "kubeguard_evidence_ed25519"
    stats = sync_once(sync_dir(), key)
    print("Summary:", stats)
    print("No Kubernetes actions, automatic remediation, or Ollama requests.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError, KeyError, TypeError) as exc:
        raise SystemExit(f"KubeGuard episode sync stopped safely: {type(exc).__name__}: {exc}")
