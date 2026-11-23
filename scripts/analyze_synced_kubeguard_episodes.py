#!/usr/bin/env python3
"""KubeGuard M7: one-shot, local-only analysis of synchronized incident episodes.

Run manually on Windows, AFTER sync_kubeguard_episodes.py. Never connects to
Kubernetes/SFTP, never runs model-suggested commands, and does not perform
remediation. Uses v2's strict validator, sync's episode-file checks, and v3's
allowlisted investigation check IDs. Missing reports can be retried; existing
reports are independently verified and never overwritten.

Only the localhost Ollama endpoint is accessed during analysis. Keep inputs,
reports and SSH keys outside the public repository. No scheduling yet.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

import analyze_real_incident_local_v3 as v3
import sync_kubeguard_episodes as sync

MAX_NEW_PER_RUN = 1  # Start with one bounded, human-reviewed inference per invocation.


def report_dir(episodes: Path) -> Path:
    """Store reports alongside the private synced tree, never inside Git."""
    if episodes.is_symlink() or not episodes.is_dir():
        raise ValueError("Unsafe episode directory")
    base = episodes.parent.parent
    if base.is_symlink() or not base.is_dir() or base.name != "private":
        raise ValueError("Unexpected private data directory")
    folder = base / "reports"
    if folder.is_symlink():
        raise ValueError("Refusing linked report directory")
    folder.mkdir(mode=0o700, exist_ok=True)
    if not folder.is_dir():
        raise ValueError("Invalid report directory")
    return folder


def report_name(episode_name: str) -> str:
    if not sync.EPISODE_RE.fullmatch(episode_name):
        raise ValueError("Unexpected episode filename")
    return "investigation_" + episode_name[len("episode_"):]


def load_episode(path: Path) -> tuple[dict, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Refusing non-file or linked evidence")
    if not 0 < path.stat().st_size <= sync.MAX_FILE_BYTES:
        raise ValueError("Evidence size out of bounds")
    raw = path.read_bytes()
    evidence = sync.validate_episode_bytes(path.name, raw)
    return evidence, hashlib.sha256(raw).hexdigest()


def approved_options(evidence: dict) -> dict[str, str]:
    # The sanitized evidence contains NO traffic-generator configuration.
    # Therefore do not ask the model to validate a controlled test delay.
    options = v3.permitted_checks(evidence).copy()
    options.pop("confirm_test_delay", None)
    if not options:
        raise ValueError("No approved investigation checks")
    return options


def create_report(evidence: dict, name: str, digest: str, check_ids: list[str]) -> dict:
    allowed = approved_options(evidence)
    v3.validate_ids({"check_ids": check_ids}, allowed)
    report = v3.build_report(evidence, check_ids)
    # v3's stand-alone historical test report always included an experiment
    # hypothesis. That is unsuitable for future unknown episodes, so use only
    # unconditional, explicitly unverified, fixed hypotheses here.
    report["analysis"]["possible_causes"] = list(v3.HYPOTHESES[1:])
    report["source_filename"] = name
    report["source_sha256"] = digest
    return report


def verify_existing(path: Path, evidence: dict, name: str, digest: str) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65_536:
        raise ValueError("Invalid or linked existing report; refusing overwrite")
    raw = path.read_bytes()
    if not raw:
        raise ValueError("Empty existing report")
    report = v3.v2.parse_json_no_duplicates(raw)
    if type(report) is not dict or type(report.get("model_selected_check_ids")) is not list:
        raise ValueError("Malformed existing report")
    # Rebuild every deterministic field instead of trusting a status marker.
    expected = create_report(evidence, name, digest, report["model_selected_check_ids"])
    if report != expected:
        raise ValueError("Existing report disagrees with validated evidence; refusing overwrite")
    return report


def write_create_only(folder: Path, filename: str, report: dict) -> Path:
    path = folder / filename
    if path.exists() or path.is_symlink():
        raise ValueError("Report already exists; refusing overwrite")
    # Same-directory temporary + hardlink gives an atomic create-only final
    # pathname on NTFS; no invalid/partial final report should be published.
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=folder,
                                     prefix=".kubeguard-analysis-", suffix=".partial",
                                     delete=False) as f:
        temp = Path(f.name)
        try:
            json.dump(report, f, indent=2, ensure_ascii=False, allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            temp.unlink(missing_ok=True)
            raise
    try:
        os.link(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    return path


def run_once(episodes: Path, reports: Path, *, validate_only: bool = False,
             model_fn=None) -> dict[str, int]:
    if model_fn is None:
        model_fn = v3.call_model_for_check_ids
    if reports.is_symlink() or not reports.is_dir() or episodes.is_symlink() or not episodes.is_dir():
        raise ValueError("Unsafe analysis folders")
    lock = reports / ".kubeguard-analysis.lock"
    if lock.is_symlink():
        raise ValueError("Linked analysis lock")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RuntimeError("An analysis may already be running (lock exists)") from exc
    os.close(fd)
    stats = {"cached": 0, "analyzed": 0, "already_analyzed": 0, "remaining": 0}
    try:
        names = sorted(p.name for p in episodes.iterdir() if sync.EPISODE_RE.fullmatch(p.name))
        if len(names) > sync.MAX_DISCOVERED:
            raise ValueError("Too many cached episodes")
        stats["cached"] = len(names)
        for name in names:
            evidence, digest = load_episode(episodes / name)
            target = reports / report_name(name)
            if target.exists() or target.is_symlink():
                verify_existing(target, evidence, name, digest)
                print("Already analyzed:", name)
                stats["already_analyzed"] += 1
                continue
            if validate_only:
                print("Validated; needs analysis:", name)
                stats["remaining"] += 1
                continue
            if stats["analyzed"] >= MAX_NEW_PER_RUN:
                stats["remaining"] += 1
                continue
            # The evidence is strictly validated, and the model may only return
            # IDs from a constrained, read-only catalog. No commands are run.
            options = approved_options(evidence)
            ids = model_fn(evidence, options)
            report = create_report(evidence, name, digest, ids)
            output = write_create_only(reports, report_name(name), report)
            print("Analyzed:", name)
            print("Private report:", output)
            stats["analyzed"] += 1
        return stats
    finally:
        lock.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-only", action="store_true",
                        help="Check cached evidence and existing reports without calling Ollama")
    args = parser.parse_args()
    episodes = sync.sync_dir()
    reports = report_dir(episodes)
    print("KubeGuard local-only episode investigation (no cluster access)")
    stats = run_once(episodes, reports, validate_only=args.validate_only)
    print("Summary:", stats)
    print("No Kubernetes actions or automatic remediation; human review required.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        raise SystemExit(f"KubeGuard local analysis stopped safely: {type(exc).__name__}: {exc}")
