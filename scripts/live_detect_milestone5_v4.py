#!/usr/bin/env python3
"""KubeGuard AI Milestone 5 — read-only V4 detection policy.

Adds request-volume/freshness safeguards to V3. Requires the existing
live_detect_milestone5_v2.py, live_detect_milestone5_v3.py and trained
model in the same KubeGuard project. Does not write to Kubernetes, send
alerts, or change model training.

Run with Prometheus forwarded to localhost:9090:
    python scripts/live_detect_milestone5_v4.py --samples 0 --interval-sec 30
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import live_detect_milestone5_v2 as v2
import live_detect_milestone5_v3 as v3

# Both queries count requests completed by the KubeGuard API. Prometheus
# increase() estimates changes in the counter over each lookback window;
# values may be non-integers because of extrapolation.
_REQUEST_COUNT = (
    'sum(increase(kubeguard_request_duration_seconds_count'
    '{namespace="kubeguard"}[%s]))'
)


def apply_policy_v4(
    raw: dict,
    consecutive: int,
    required: int,
    min_rps: float,
    max_rps: float,
    requests_5m: float | None,
    requests_1m: float | None,
    min_requests_5m: float,
    min_requests_1m: float,
) -> tuple[dict, int]:
    """Apply V3's policy, but require evidence of sufficient *recent* traffic.

    Safety precedence: no available replicas > missing core metrics > missing
    counter data > low sample volume > normal V3 classification.
    """
    result, next_consecutive = v3.apply_policy(
        raw, consecutive, required, min_rps, max_rps
    )
    result["request_count_5m"] = requests_5m
    result["request_count_1m"] = requests_1m
    result["minimum_request_count_5m"] = min_requests_5m
    result["minimum_request_count_1m"] = min_requests_1m

    valid_counts = all(
        isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
        for value in (requests_5m, requests_1m)
    )
    sufficient = valid_counts and (
        requests_5m >= min_requests_5m
        and requests_1m >= min_requests_1m
    )
    result["sample_count_sufficient"] = sufficient if valid_counts else None

    if raw.get("status") in ("UNAVAILABLE", "INSUFFICIENT_DATA"):
        # This also resets sustained-latency confirmation on missing evidence.
        return result, next_consecutive

    if not valid_counts:
        result.update(
            status="REQUEST_COUNT_UNKNOWN",
            decision_reason="Request counters unavailable; cannot confirm anomaly",
            consecutive_latency_violations=0,
            ml_decision_used=False,
        )
        return result, 0

    if not sufficient:
        was_high_latency = raw.get("baseline_anomaly") is True
        result.update(
            status="LOW_SAMPLE_COUNT" if was_high_latency else "ML_NOT_EVALUATED",
            decision_reason=(
                "High latency, but insufficient requests in 5m or 1m; no confirmation"
                if was_high_latency
                else "Insufficient recent requests for reliable ML evaluation"
            ),
            consecutive_latency_violations=0,
            ml_decision_used=False,
        )
        return result, 0

    return result, next_consecutive


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--prometheus", default="http://127.0.0.1:9090")
    p.add_argument("--model", type=Path, default=Path("data/milestone5/detector.joblib"))
    p.add_argument("--once", action="store_true")
    p.add_argument("--samples", type=int, default=1, help="0: until Ctrl+C")
    p.add_argument("--interval-sec", type=int, default=30)
    p.add_argument("--log-file", type=Path)
    p.add_argument("--rule-consecutive", type=int, default=2)
    p.add_argument("--ml-min-rps", type=float, default=0.8)
    p.add_argument("--ml-max-rps", type=float, default=2.2)
    p.add_argument("--min-requests-5m", type=float, default=20.0)
    p.add_argument("--min-requests-1m", type=float, default=5.0)
    args = p.parse_args()

    u = urlsplit(args.prometheus)
    if (
        u.scheme != "http" or u.hostname not in ("127.0.0.1", "localhost", "::1")
        or u.username or u.password or u.query or u.fragment
    ):
        p.error("--prometheus must be a local HTTP port-forward")
    if args.samples < 0 or not 1 <= args.interval_sec <= 3600 or args.rule_consecutive < 1:
        p.error("Invalid samples, interval or rule confirmation count")
    if not (0 <= args.ml_min_rps < args.ml_max_rps <= 10):
        p.error("Invalid ML request-rate envelope")
    if not (
        math.isfinite(args.min_requests_5m) and args.min_requests_5m >= 1
        and math.isfinite(args.min_requests_1m) and args.min_requests_1m >= 1
    ):
        p.error("Minimum request counts must be finite and >= 1")
    if args.once and args.samples != 1:
        p.error("Use --once or --samples N, not both")

    detector = v2.load_detector(args.model)
    if args.log_file:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)

    print("KubeGuard V4: read-only; no alert publishing or remediation.", file=sys.stderr)
    print(
        f"Confirmation: {args.rule_consecutive} consecutive snapshots; "
        f"minimum requests: 5m={args.min_requests_5m:g}, "
        f"1m={args.min_requests_1m:g}; "
        f"ML RPS range={args.ml_min_rps:g}..{args.ml_max_rps:g}",
        file=sys.stderr,
    )

    consecutive = 0
    seen = 0
    try:
        while args.samples == 0 or seen < args.samples:
            started = time.monotonic()
            epoch = int(time.time())
            raw = v2.detect_once(args.prometheus, detector, epoch)
            # Same evaluation time for all 3 Prometheus requests.
            requests_5m = v2.query_instant(
                args.prometheus, _REQUEST_COUNT % "5m", epoch
            )
            requests_1m = v2.query_instant(
                args.prometheus, _REQUEST_COUNT % "1m", epoch
            )
            result, consecutive = apply_policy_v4(
                raw, consecutive, args.rule_consecutive,
                args.ml_min_rps, args.ml_max_rps,
                requests_5m, requests_1m,
                args.min_requests_5m, args.min_requests_1m,
            )
            line = json.dumps(result, allow_nan=False)
            print(line, flush=True)
            if args.log_file:
                with args.log_file.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
            seen += 1
            if args.samples and seen >= args.samples:
                break
            time.sleep(max(0.0, args.interval_sec - (time.monotonic() - started)))
    except KeyboardInterrupt:
        print("Stopped by user", file=sys.stderr)
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
