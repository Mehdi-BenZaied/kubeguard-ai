#!/usr/bin/env python3
"""KubeGuard AI: traffic-aware read-only collection of application training candidates.

Ubuntu VM, launched from repository root. Queries an existing Prometheus
localhost port-forward, never writes to Kubernetes and never fits an ML model.
No sample is stored while idle/low-traffic/unknown. Active observations are
stored as UNREVIEWED candidates or quarantined observations, never as trusted
training labels. No application logs, request URLs/bodies, secrets or env vars.

Examples:
    python scripts/collect_live_training_data.py --samples 1 --dry-run
    python scripts/collect_live_training_data.py --samples 0 --interval-sec 30
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

from build_milestone4_dataset import PROMQL

APPLICATION_ID = "kubeguard-api"
DEFAULT_DB = Path("data/learning/observations.sqlite3")
DEFAULT_PROMETHEUS = "http://127.0.0.1:9090"
REQUEST_COUNT_QUERY = (
    'sum(increase(kubeguard_request_duration_seconds_count'
    '{namespace="kubeguard"}[%s]))'
)
# Only these known aggregate metrics. No logs, labels, secrets, or arbitrary PromQL input.
FEATURES = (
    "available_replicas", "avg_latency_seconds", "request_rate_per_s",
    "cpu_millicores", "memory_mib", "error_rate_pct",
    "p95_latency_seconds", "cpu_throttle_pct",
)
REQUIRED = (
    "available_replicas", "avg_latency_seconds", "request_rate_per_s",
    "cpu_millicores", "memory_mib",
)
OPTIONAL = tuple(n for n in FEATURES if n not in REQUIRED)
COLUMNS = (
    "application_id", "epoch_seconds", "timestamp_utc", "review_state",
    "request_count_1m", "request_count_5m", *FEATURES,
    "missing_optional_json",
)


def local_prometheus_url(raw: str) -> str:
    try:
        u = urlsplit(raw)
        port = u.port
    except ValueError as exc:
        raise ValueError("Invalid Prometheus URL/port") from exc
    if (u.scheme != "http" or u.hostname not in ("127.0.0.1", "localhost", "::1")
            or port is None or u.username or u.password or u.query or u.fragment
            or u.path not in ("", "/")):
        raise ValueError("Use a local Prometheus port-forward, e.g. http://127.0.0.1:9090")
    return raw.rstrip("/")


class DenyRedirects(HTTPRedirectHandler):
    """Prevent a loopback server from redirecting metric queries off-host."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def query_instant(base_url: str, promql: str, epoch: int) -> float | None:
    url = base_url + "/api/v1/query?" + urlencode({"query": promql, "time": epoch})
    # Do not allow HTTP_PROXY/HTTPS_PROXY to forward even local telemetry queries.
    opener = build_opener(ProxyHandler({}), DenyRedirects())
    try:
        with opener.open(url, timeout=8) as response:
            data = json.load(response)
    except (OSError, HTTPError, URLError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f"Prometheus query failed: {type(exc).__name__}") from exc
    if data.get("status") != "success" or data.get("data", {}).get("resultType") != "vector":
        raise RuntimeError("Unexpected Prometheus query response")
    rows = data["data"].get("result", [])
    if len(rows) > 1:
        raise RuntimeError("Expected one aggregated result, got multiple")
    if not rows:
        return None
    try:
        value = float(rows[0]["value"][1])
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise RuntimeError("Prometheus returned an invalid scalar") from exc
    return value if math.isfinite(value) else None


def _valid_nonnegative(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


def decide_sample(metrics: dict, epoch: int, min_1m: float, min_5m: float,
                  latency_limit_seconds: float) -> dict:
    """Pure decision function. No idle records and no automatically trusted data."""
    c1, c5 = metrics.get("request_count_1m"), metrics.get("request_count_5m")
    stamp = datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    if not _valid_nonnegative(c1) or not _valid_nonnegative(c5):
        return {"status": "SKIPPED_UNKNOWN_TRAFFIC", "timestamp_utc": stamp, "sample": None}
    if c1 == 0:
        return {"status": "SKIPPED_IDLE", "timestamp_utc": stamp, "sample": None}
    if c1 < min_1m or c5 < min_5m:
        return {"status": "SKIPPED_LOW_TRAFFIC", "timestamp_utc": stamp, "sample": None}

    if not all(_valid_nonnegative(metrics.get(n)) for n in REQUIRED):
        return {"status": "SKIPPED_MISSING_CORE_METRICS", "timestamp_utc": stamp, "sample": None}
    if metrics["available_replicas"] < 1:
        return {"status": "SKIPPED_UNAVAILABLE", "timestamp_utc": stamp, "sample": None}
    if metrics["request_rate_per_s"] <= 0:
        return {"status": "SKIPPED_MISSING_CORE_METRICS", "timestamp_utc": stamp, "sample": None}

    # Optional metrics can be absent. We do not silently turn them into zeros.
    optional = {n: (metrics.get(n) if _valid_nonnegative(metrics.get(n)) else None) for n in OPTIONAL}
    if metrics["avg_latency_seconds"] > latency_limit_seconds:
        review_state = "quarantine_high_latency"
    elif optional["error_rate_pct"] is not None and optional["error_rate_pct"] > 0:
        review_state = "quarantine_measured_errors"
    else:
        review_state = "candidate_unreviewed"

    sample = {
        "application_id": APPLICATION_ID,
        "epoch_seconds": epoch,
        "timestamp_utc": stamp,
        "review_state": review_state,
        "request_count_1m": float(c1),
        "request_count_5m": float(c5),
        **{name: float(metrics[name]) for name in REQUIRED},
        **optional,
        "missing_optional_json": json.dumps(sorted(n for n, v in optional.items() if v is None)),
    }
    return {"status": "ACTIVE_" + review_state.upper(), "timestamp_utc": stamp, "sample": sample}


def collect_once(base_url: str, epoch: int, min_1m: float = 5.0,
                 min_5m: float = 20.0, latency_limit_seconds: float = 0.25,
                 query=query_instant) -> dict:
    # Query request counters FIRST; avoid downloading other metrics on idle ticks.
    c1 = query(base_url, REQUEST_COUNT_QUERY % "1m", epoch)
    c5 = query(base_url, REQUEST_COUNT_QUERY % "5m", epoch)
    metrics = {"request_count_1m": c1, "request_count_5m": c5}
    early = decide_sample(metrics, epoch, min_1m, min_5m, latency_limit_seconds)
    if early["status"] in ("SKIPPED_UNKNOWN_TRAFFIC", "SKIPPED_IDLE", "SKIPPED_LOW_TRAFFIC"):
        return early
    for field in FEATURES:
        try:
            metrics[field] = query(base_url, PROMQL[field], epoch)
        except RuntimeError:
            # An optional query failing should not fabricate a zero result.
            if field in REQUIRED:
                raise
            metrics[field] = None
    return decide_sample(metrics, epoch, min_1m, min_5m, latency_limit_seconds)


def initialize_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Tighten the project's dedicated data directory as well as the SQLite file.
    os.chmod(path.parent, 0o700)
    conn = sqlite3.connect(path, timeout=10)
    try:
        os.chmod(path, 0o600)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_samples (
                application_id TEXT NOT NULL,
                epoch_seconds INTEGER NOT NULL,
                timestamp_utc TEXT NOT NULL,
                review_state TEXT NOT NULL CHECK (review_state IN (
                    'candidate_unreviewed', 'quarantine_high_latency',
                    'quarantine_measured_errors'
                )),
                request_count_1m REAL NOT NULL,
                request_count_5m REAL NOT NULL,
                available_replicas REAL NOT NULL,
                avg_latency_seconds REAL NOT NULL,
                request_rate_per_s REAL NOT NULL,
                cpu_millicores REAL NOT NULL,
                memory_mib REAL NOT NULL,
                error_rate_pct REAL,
                p95_latency_seconds REAL,
                cpu_throttle_pct REAL,
                missing_optional_json TEXT NOT NULL,
                PRIMARY KEY (application_id, epoch_seconds)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS telemetry_review_idx ON telemetry_samples(review_state, epoch_seconds)")
        conn.commit()
    except BaseException:
        conn.close()
        raise
    return conn


def save_sample(conn: sqlite3.Connection, sample: dict) -> bool:
    statement = "INSERT OR IGNORE INTO telemetry_samples (" + ", ".join(COLUMNS) + ") VALUES (" + ", ".join("?" for _ in COLUMNS) + ")"
    with conn:
        cur = conn.execute(statement, tuple(sample[column] for column in COLUMNS))
    return cur.rowcount == 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prometheus", default=DEFAULT_PROMETHEUS)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--samples", type=int, default=1, help="0 = continuously until Ctrl+C; 1 = single poll")
    parser.add_argument("--interval-sec", type=int, default=30)
    parser.add_argument("--min-requests-1m", type=float, default=5.0)
    parser.add_argument("--min-requests-5m", type=float, default=20.0)
    parser.add_argument("--latency-threshold-ms", type=float, default=250.0)
    parser.add_argument("--dry-run", action="store_true", help="Only query and print status; never create database")
    args = parser.parse_args()
    if args.samples < 0 or not 10 <= args.interval_sec <= 3600:
        parser.error("--samples must be >= 0 and --interval-sec 10..3600")
    if not all(math.isfinite(x) and x >= 1 for x in (args.min_requests_1m, args.min_requests_5m)):
        parser.error("Request thresholds must be finite and >= 1")
    if not math.isfinite(args.latency_threshold_ms) or args.latency_threshold_ms <= 0:
        parser.error("Latency threshold must be positive")
    try:
        url = local_prometheus_url(args.prometheus)
    except ValueError as exc:
        parser.error(str(exc))
    print("KubeGuard read-only, traffic-aware collector. No training, alerting or remediation.", file=sys.stderr)
    print(f"Mode: {'dry-run' if args.dry_run else 'local SQLite'}; application: {APPLICATION_ID}", file=sys.stderr)
    # Linux-only project environment: restrictive permissions for temp SQLite journals too.
    os.umask(0o077)
    conn = None
    n = 0
    try:
        while args.samples == 0 or n < args.samples:
            tick = time.monotonic()
            epoch = int(time.time())
            try:
                result = collect_once(url, epoch, args.min_requests_1m,
                                      args.min_requests_5m, args.latency_threshold_ms / 1000)
                sample = result["sample"]
                if sample and not args.dry_run:
                    if conn is None:
                        conn = initialize_database(args.db)
                    inserted = save_sample(conn, sample)
                    result["saved"] = inserted
                else:
                    result["saved"] = False
            except (OSError, RuntimeError, sqlite3.Error, ValueError) as exc:
                result = {"status": "ERROR", "timestamp_utc": datetime.fromtimestamp(epoch,timezone.utc).isoformat(),
                          "saved": False, "reason": f"{type(exc).__name__}: collector/Prometheus unavailable"}
            # No raw response bodies, URLs, labels or secrets printed.
            print(json.dumps({k: v for k, v in result.items() if k != "sample"}, allow_nan=False), flush=True)
            n += 1
            if args.samples and n >= args.samples:
                break
            time.sleep(max(0.0, args.interval_sec - (time.monotonic() - tick)))
    except KeyboardInterrupt:
        print("Stopped. Existing SQLite observations preserved.", file=sys.stderr)
    finally:
        if conn is not None:
            conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
