#!/usr/bin/env python3
"""KubeGuard AI Milestone 5: experimental read-only detection policy (V3).

Wraps live_detect_milestone5_v2.py without changing the trained model.
- Operational latency violations require consecutive observations before confirmation.
- Out-of-domain request rates cannot produce an escalated ML-only status.
- ML flags remain advisory, never remediating or creating alerts/incidents.

These are laboratory policy choices, not production SLOs or validated ML thresholds.
Run: python scripts/live_detect_milestone5_v3.py --samples 0 --interval-sec 30
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


def apply_policy(snapshot: dict, consecutive: int, required: int, min_rps: float, max_rps: float) -> tuple[dict, int]:
    """Turn raw V2 signals into conservative statuses. Pure; simple to test."""
    result = dict(snapshot)
    baseline = snapshot.get("baseline_anomaly") is True
    # A missing/unknown measurement must not count as sustained evidence.
    consecutive = consecutive + 1 if baseline else 0
    result["consecutive_latency_violations"] = consecutive
    result["required_latency_violations"] = required

    rate = snapshot.get("metrics", {}).get("request_rate_per_s")
    applicable = (isinstance(rate, (int, float)) and math.isfinite(rate)
                  and min_rps <= rate <= max_rps)
    result["ml_rate_in_training_envelope"] = applicable
    result["ml_rate_envelope_rps"] = [min_rps, max_rps]
    result["ml_decision_used"] = False

    # Unavailability and missing-data checks come from the raw detector.
    if snapshot.get("status") in ("UNAVAILABLE", "INSUFFICIENT_DATA"):
        return result, consecutive
    if baseline:
        if consecutive >= required:
            result["status"] = "ANOMALY"
            result["decision_reason"] = "Sustained latency rule violation"
        else:
            result["status"] = "ANOMALY_PENDING"
            result["decision_reason"] = "Latency rule breached; awaiting confirmation"
    elif not applicable:
        result["status"] = "ML_NOT_EVALUATED"
        result["decision_reason"] = "Request rate outside the trained 1–2 RPS conditions; ML score advisory only"
    elif snapshot.get("isolation_forest_anomaly") is True:
        result["status"] = "ML_SUSPICIOUS"
        result["decision_reason"] = "ML-only warning; review possible training drift"
        result["ml_decision_used"] = True
    else:
        result["status"] = "NORMAL"
        result["decision_reason"] = "No rule violation or in-envelope ML warning"
        result["ml_decision_used"] = True
    return result, consecutive


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--prometheus", default="http://127.0.0.1:9090")
    p.add_argument("--model", type=Path, default=Path("data/milestone5/detector.joblib"))
    p.add_argument("--once", action="store_true", help="Read one snapshot; cannot confirm sustained violations")
    p.add_argument("--samples", type=int, default=1, help="0: run until Ctrl+C")
    p.add_argument("--interval-sec", type=int, default=30)
    p.add_argument("--log-file", type=Path)
    p.add_argument("--rule-consecutive", type=int, default=2)
    p.add_argument("--ml-min-rps", type=float, default=0.8)
    p.add_argument("--ml-max-rps", type=float, default=2.2)
    args = p.parse_args()

    u = urlsplit(args.prometheus)
    if u.scheme != "http" or u.hostname not in ("127.0.0.1", "localhost", "::1") or u.username or u.password or u.query or u.fragment:
        p.error("--prometheus must be a local HTTP port-forward")
    if args.samples < 0 or not (1 <= args.interval_sec <= 3600) or args.rule_consecutive < 1:
        p.error("Invalid samples, interval or rule confirmation count")
    if not (0 <= args.ml_min_rps < args.ml_max_rps <= 10):
        p.error("Invalid ML request-rate envelope")
    if args.once and args.samples != 1:
        p.error("Use --once or --samples N, not both")
    detector = v2.load_detector(args.model)
    if args.log_file:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
    print("KubeGuard V3: read-only monitoring; no alert publishing or remediation.", file=sys.stderr)
    print(f"Latency confirmation: {args.rule_consecutive} consecutive samples; ML RPS envelope: {args.ml_min_rps:g}..{args.ml_max_rps:g}", file=sys.stderr)

    consecutive = 0
    seen = 0
    try:
        while args.samples == 0 or seen < args.samples:
            started = time.monotonic()
            raw = v2.detect_once(args.prometheus, detector, int(time.time()))
            result, consecutive = apply_policy(raw, consecutive, args.rule_consecutive,
                                               args.ml_min_rps, args.ml_max_rps)
            line = json.dumps(result, allow_nan=False)
            print(line, flush=True)
            if args.log_file:
                with args.log_file.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
            seen += 1
            if args.samples and seen >= args.samples:
                break
            time.sleep(max(0, args.interval_sec - (time.monotonic() - started)))
    except KeyboardInterrupt:
        print("Stopped by user", file=sys.stderr)
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
