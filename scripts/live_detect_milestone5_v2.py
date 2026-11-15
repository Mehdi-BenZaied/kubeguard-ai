#!/usr/bin/env python3
"""KubeGuard AI: read-only live Prometheus anomaly detection (Milestone 5).

Runs on the Ubuntu VM with Prometheus port-forwarded to localhost:9090.
Reuses the exact training feature queries from build_milestone4_dataset.py.
No Kubernetes writes, remediation, alerts, or model fitting are performed.

Example:
    python scripts/live_detect_milestone5.py --once
    python scripts/live_detect_milestone5.py --samples 5 --interval-sec 30 \
        --log-file data/milestone5/live_detections.jsonl

Install: python -m pip install -r requirements-ml.txt
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import urlopen

try:
    import joblib
    import numpy as np
except ImportError as exc:
    raise SystemExit("Missing ML dependencies: activate .venv and install requirements-ml.txt") from exc

# Import the *same* PromQL expressions used to create the training CSV.
from build_milestone4_dataset import PROMQL

EXPECTED_FEATURES = (
    "avg_latency_seconds",
    "request_rate_per_s",
    "cpu_millicores",
    "memory_mib",
)


def utc_time(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


def query_instant(base_url: str, expression: str, evaluation_time: int) -> float | None:
    url = base_url.rstrip("/") + "/api/v1/query?" + urlencode({"query": expression, "time": evaluation_time})
    try:
        with urlopen(url, timeout=10) as response:
            payload = json.load(response)
    except (OSError, URLError, HTTPError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f"Prometheus query failed: {exc}") from exc

    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus error: {payload.get('error', payload)}")
    data = payload.get("data", {})
    if data.get("resultType") != "vector":
        raise RuntimeError(f"Expected vector result, got {data.get('resultType')}")
    items = data.get("result", [])
    if len(items) > 1:
        raise RuntimeError(f"Expected one aggregated metric, got {len(items)}")
    if not items:
        return None
    try:
        value = float(items[0]["value"][1])
    except (TypeError, ValueError, IndexError, KeyError) as exc:
        raise RuntimeError("Prometheus returned an invalid sample") from exc
    return value if math.isfinite(value) else None


def load_detector(path: Path) -> tuple[object, object, tuple[str, ...], float]:
    # joblib uses pickle internally. Never load untrusted model files.
    bundle = joblib.load(path)
    if not isinstance(bundle, dict):
        raise ValueError("Unexpected detector format")
    features = tuple(bundle["features"])
    if len(features) != len(EXPECTED_FEATURES) or set(features) != set(EXPECTED_FEATURES):
        raise ValueError(f"Unexpected model features: {features!r}")
    threshold = float(bundle["baseline_threshold_seconds"])
    if not math.isfinite(threshold) or threshold <= 0:
        raise ValueError("Invalid baseline threshold in model")
    return bundle["model"], bundle["scaler"], features, threshold


def detect_once(base_url: str, detector: tuple, epoch: int) -> dict:
    model, scaler, features, threshold = detector
    fields = ("available_replicas", *features)
    metrics = {name: query_instant(base_url, PROMQL[name], epoch) for name in dict.fromkeys(fields)}

    missing = [name for name in features if metrics[name] is None]
    replicas = metrics["available_replicas"]
    result = {
        "timestamp_utc": utc_time(epoch),
        "status": "INSUFFICIENT_DATA",
        "decision_reason": "Missing metrics or no recent traffic",
        "available_replicas": replicas,
        "metrics": metrics,
        "missing_features": missing,
        "latency_threshold_seconds": threshold,
        "baseline_anomaly": None,
        "isolation_forest_anomaly": None,
        "isolation_forest_score": None,
        "isolation_forest_score_cutoff": -float(model.offset_),
        "isolation_forest_decision_margin": None,
    }

    # Always report a known unavailability, even when request metrics are empty.
    if replicas is not None and replicas < 1:
        result["status"] = "UNAVAILABLE"
        result["decision_reason"] = "No available application replicas"
        return result

    # No traffic means the rate/latency feature vectors may be absent. Do not
    # replace absent latency with zero or claim the model scored idle traffic.
    if missing or metrics["request_rate_per_s"] <= 0 or replicas is None:
        return result

    vector = np.asarray([[metrics[name] for name in features]], dtype=float)
    scaled = scaler.transform(vector)
    score = -float(model.score_samples(scaled)[0])
    margin = float(model.decision_function(scaled)[0])
    forest_flag = bool(model.predict(scaled)[0] == -1)
    baseline_flag = bool(metrics["avg_latency_seconds"] > threshold)
    result.update({
        "status": (
            "ANOMALY" if baseline_flag
            else "ML_SUSPICIOUS" if forest_flag
            else "NORMAL"
        ),
        "decision_reason": (
            "Latency exceeded configured threshold"
            if baseline_flag else
            "Isolation Forest only; investigate before escalating"
            if forest_flag else
            "No detector flagged the current metrics"
        ),
        "baseline_anomaly": baseline_flag,
        "isolation_forest_anomaly": forest_flag,
        "isolation_forest_score": round(score, 6),
        "isolation_forest_decision_margin": round(margin, 6),
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prometheus", default="http://127.0.0.1:9090")
    parser.add_argument("--model", type=Path, default=Path("data/milestone5/detector.joblib"))
    parser.add_argument("--once", action="store_true", help="Score one snapshot (default)")
    parser.add_argument("--samples", type=int, default=1, help="Snapshots to collect; 0 means until Ctrl+C")
    parser.add_argument("--interval-sec", type=int, default=30, help="Seconds between snapshots")
    parser.add_argument("--log-file", type=Path, help="Optional append-only JSONL result log")
    args = parser.parse_args()

    parsed = urlsplit(args.prometheus)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1") or parsed.username or parsed.password or parsed.query or parsed.fragment:
        parser.error("--prometheus must be a local HTTP port-forward (http://127.0.0.1:9090)")
    if args.samples < 0 or not 1 <= args.interval_sec <= 3600:
        parser.error("--samples must be >= 0 and --interval-sec must be 1..3600")
    if args.once and args.samples != 1:
        parser.error("Use either --once or --samples N, not both")

    detector = load_detector(args.model)
    print("Read-only KubeGuard live detector. No remediation will be performed.", file=sys.stderr)
    print(f"ML anomaly-score cutoff: {-float(detector[0].offset_):.6f} (larger = more unusual)", file=sys.stderr)
    if args.log_file:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)

    index = 0
    try:
        while args.samples == 0 or index < args.samples:
            started = time.monotonic()
            epoch = int(time.time())
            result = detect_once(args.prometheus, detector, epoch)
            line = json.dumps(result, allow_nan=False)
            print(line, flush=True)
            if args.log_file:
                with args.log_file.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            index += 1
            if args.samples and index >= args.samples:
                break
            time.sleep(max(0.0, args.interval_sec - (time.monotonic() - started)))
    except KeyboardInterrupt:
        print("\nStopped by user", file=sys.stderr)
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
