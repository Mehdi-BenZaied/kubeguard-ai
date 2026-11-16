#!/usr/bin/env python3
"""KubeGuard traffic collector runtime for the Kubernetes Deployment.

Uses the existing, tested collect_live_training_data module. This wrapper is
intentionally fixed to the one in-cluster Prometheus Service and dedicated PVC.
It has no Kubernetes client, no service-account token, no LLM, and no model fit.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import collect_live_training_data as collector

# These are fixed in source. Never take arbitrary network addresses from user
# input or untrusted incident/event content.
PROMETHEUS = "http://kubeguard-monitoring-kube-prometheus.monitoring.svc.cluster.local:9090"
DATABASE = Path("/data/learning/observations.sqlite3")
INTERVAL_SECONDS = 30


def _stop(_signum, _frame):
    raise KeyboardInterrupt


def poll_once(epoch: int, conn: sqlite3.Connection | None,
              dry_run: bool = False) -> tuple[sqlite3.Connection | None, dict]:
    """One poll: observe, maybe persist a candidate, never auto-label as normal."""
    result = collector.collect_once(PROMETHEUS, epoch)
    sample = result.get("sample")
    saved = False
    if sample is not None and not dry_run:
        if conn is None:
            conn = collector.initialize_database(DATABASE)
        saved = collector.save_sample(conn, sample)
    return conn, {
        "timestamp_utc": result["timestamp_utc"],
        "status": result["status"],
        "saved": saved,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=0, help="0 = run until stopped")
    parser.add_argument("--interval-sec", type=int, default=INTERVAL_SECONDS)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.samples < 0 or not 10 <= args.interval_sec <= 3600:
        parser.error("--samples must be >= 0; --interval-sec must be 10..3600")

    os.umask(0o077)
    signal.signal(signal.SIGTERM, _stop)
    print("KubeGuard traffic collector in MicroK8s (read-only metrics; no training).", file=sys.stderr)
    print("Idle/low/unknown traffic is excluded; candidates remain unreviewed.", file=sys.stderr)
    conn = None
    n = 0
    try:
        while args.samples == 0 or n < args.samples:
            tick = time.monotonic()
            epoch = int(time.time())
            try:
                conn, output = poll_once(epoch, conn, args.dry_run)
            except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
                output = {
                    "timestamp_utc": datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds"),
                    "status": "ERROR",
                    "saved": False,
                    "reason": type(exc).__name__,  # no raw telemetry or URLs in logs
                }
            print(json.dumps(output, allow_nan=False), flush=True)
            n += 1
            if args.samples and n >= args.samples:
                break
            time.sleep(max(0.0, args.interval_sec - (time.monotonic() - tick)))
    except KeyboardInterrupt:
        print("Stopping traffic collector; SQLite transactions already committed.", file=sys.stderr)
    finally:
        if conn is not None:
            conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
