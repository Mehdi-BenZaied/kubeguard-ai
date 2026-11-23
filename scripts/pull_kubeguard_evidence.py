#!/usr/bin/env python3
"""One-shot, fail-closed Windows SFTP sync of a *known* KubeGuard evidence file.

Milestone 8 stage A only: fixed, already-approved historical file, pinned SHA256.
No remote listing, unbounded fetch, Ollama call, cluster access, or remediation.
Use a separate future manifest/publisher for new incidents; do not broaden the
remote filename or remove the pinned digest just to make future files work.

Requires analyze_real_incident_local_v2.py in the same scripts/ directory.
Runs with an already-unlocked key in Windows OpenSSH Agent.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

import analyze_real_incident_local_v2 as validator

REMOTE = "kubeguard-export@192.168.118.132"
REMOTE_FILE = "/evidence/m6_ai_evidence.json"
LOCAL_FILE = "m6_ai_evidence.json"
EXPECTED_SIZE = 3255
EXPECTED_SHA256 = "ad077b633066429446450e9adf424e1f42d98016fbc3149a01029d57a2c1b5b2"
MAX_BYTES = 32768


def private_sync_dir() -> Path:
    root = os.environ.get("LOCALAPPDATA")
    if not root:
        raise ValueError("LOCALAPPDATA is missing: this tool runs on Windows")
    private = Path(root) / "KubeGuardAI" / "private"
    if not private.is_dir() or private.is_symlink():
        raise ValueError("The expected private Windows directory is absent or is a link")
    folder = private / "synced"
    if folder.is_symlink():
        raise ValueError("Refusing symlinked sync folder")
    folder.mkdir(mode=0o700, exist_ok=True)
    if not folder.is_dir():
        raise ValueError("Private sync destination isn't a directory")
    return folder


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_file(path: Path, expected_sha256: str = EXPECTED_SHA256,
                  expected_size: int = EXPECTED_SIZE) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Evidence path missing or linked")
    size = path.stat().st_size
    if size != expected_size or not 0 < size <= MAX_BYTES:
        raise ValueError(f"Evidence size is not the pinned {expected_size} bytes")
    actual = sha256(path)
    if actual.lower() != expected_sha256.lower():
        raise ValueError(f"Evidence SHA256 mismatch: received {actual}")
    evidence = validator.validate_evidence(validator.parse_json_no_duplicates(path.read_bytes()))
    return evidence


def download_via_sftp(download_path: Path, key: Path) -> None:
    """Get a single hardcoded remote filename using a short-lived SFTP batch.

    No shell command executed on the remote. All paths controlled by this code.
    No password/passphrase prompt is permitted by BatchMode=yes.
    """
    if not key.is_file():
        raise FileNotFoundError(f"SSH private key not found: {key}")
    local_folder = download_path.parent.resolve().as_posix()
    if '"' in local_folder or '\n' in local_folder or '\r' in local_folder:
        raise ValueError("Unsafe local path for SFTP batch")
    # tempfile paths are within Windows private folder, never in Git checkout.
    with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", newline="\n",
                                     prefix=".kubeguard-batch-", suffix=".sftp",
                                     dir=download_path.parent, delete=False) as batch:
        batch_path = Path(batch.name)
        # Same lcd/get pattern already verified in interactive and batch SFTP.
        batch.write(f'lcd "{local_folder}"\n')
        batch.write(f'get {REMOTE_FILE} "{download_path.name}"\n')
    try:
        args = [
            "sftp", "-b", str(batch_path),
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no",
            "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10",
            "-o", "ConnectionAttempts=1", "-i", str(key), REMOTE,
        ]
        try:
            result = subprocess.run(args, capture_output=True, text=True,
                                    errors="replace", timeout=45, check=False)
        except FileNotFoundError as exc:
            raise RuntimeError("Windows OpenSSH 'sftp' was not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("SFTP timed out; existing evidence left unchanged") from exc
        if result.returncode != 0:
            raise RuntimeError(
                "Read-only SFTP failed (verify SSH agent, host key and VM network). "
                f"Exit code: {result.returncode}. "
                f"Details: {result.stderr.strip()[:350]}"
            )
    finally:
        batch_path.unlink(missing_ok=True)


def sync_once(folder: Path, key: Path, *,
              expected_sha256: str = EXPECTED_SHA256,
              expected_size: int = EXPECTED_SIZE) -> str:
    """Atomically synchronize; never overwrite a differing existing file."""
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError("Refusing unsafe local sync directory")
    destination = folder / LOCAL_FILE
    lock = folder / ".kubeguard-evidence-sync.lock"
    if lock.is_symlink():
        raise ValueError("Refusing linked lock file")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RuntimeError("Sync lock exists; another run may be active. Check before clearing") from exc
    os.close(fd)
    try:
        if destination.exists() or destination.is_symlink():
            evidence = validate_file(destination, expected_sha256, expected_size)
            print(f"Already synced: {destination}")
            print("Episode:", evidence["episode_start_utc"])
            return "already_synced"

        # Close the temporary file before SFTP writes it (Windows compatibility).
        with tempfile.NamedTemporaryFile(mode="wb", prefix=".kubeguard-download-",
                                         suffix=".partial", dir=folder, delete=False) as tmp:
            pending = Path(tmp.name)
        try:
            download_via_sftp(pending, key)
            evidence = validate_file(pending, expected_sha256, expected_size)
            if destination.exists() or destination.is_symlink():
                raise RuntimeError("Destination appeared during sync; refusing to overwrite")
            os.replace(pending, destination)
            print(f"Downloaded and validated: {destination}")
            print("Incident:", evidence["incident_type"])
            print("Lifecycle:", ", ".join(event["status"] for event in evidence["evidence"]))
            print("Episode:", evidence["episode_start_utc"])
            print("SHA256:", sha256(destination).upper())
            return "downloaded"
        finally:
            pending.unlink(missing_ok=True)
    finally:
        lock.unlink(missing_ok=True)


def main() -> int:
    private = private_sync_dir()
    key = Path.home() / ".ssh" / "kubeguard_evidence_ed25519"
    print("KubeGuard read-only sync (pinned historical evidence only)")
    sync_once(private, key)
    print("No Ollama inference or Kubernetes action was executed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        raise SystemExit(f"KubeGuard evidence sync stopped safely: {type(exc).__name__}: {exc}")
