#!/usr/bin/env python3
"""Label clean V2 KubeGuard metrics from independently recorded experiments.

Only points whose entire preceding five-minute PromQL rate window falls within
one completed scenario are eligible. This is a small proof-of-concept labeling
utility, not an ML training or model evaluation tool.

Requires Python standard library only.
"""

import argparse
import csv
import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median

LABELS = {"normal_traffic_v2": 0, "high_latency_v2": 1}
WINDOW = timedelta(minutes=5)
FEATURES = (
    "available_replicas",
    "request_rate_per_s",
    "avg_latency_seconds",
    "p95_latency_seconds",
    "cpu_millicores",
    "memory_mib",
    "cpu_throttle_pct",
)
REQUIRED = (
    "available_replicas",
    "request_rate_per_s",
    "avg_latency_seconds",
    "cpu_millicores",
    "memory_mib",
)


def parse_utc(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"Timestamp lacks timezone: {value}")
    return dt.astimezone(timezone.utc)


def load_csv(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def numeric_or_empty(value):
    if value is None or not value.strip():
        return ""
    try:
        number = float(value)
        return value if math.isfinite(number) else ""
    except ValueError:
        return ""


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--metrics", type=Path, default=Path("data/milestone4/v2-export/metrics.csv"))
    p.add_argument("--scenarios", type=Path, default=Path("data/milestone4/scenarios_v2.csv"))
    p.add_argument("--output", type=Path, default=Path("data/milestone4/v2-export/labeled_metrics.csv"))
    args = p.parse_args()

    scenarios = []
    for row in load_csv(args.scenarios):
        name = row["scenario"]
        if name not in LABELS:
            continue
        if row["status"] != "complete":
            print(f"Skipping incomplete scenario: {name}")
            continue
        if int(row["failed_requests"]) or int(row["skipped_slots"]) or not int(row["successful_requests"]):
            print(f"Skipping scenario with failed/skipped traffic: {name}")
            continue
        start, end = parse_utc(row["start_utc"]), parse_utc(row["end_utc"])
        if end <= start + WINDOW:
            print(f"Skipping scenario shorter than required 5-minute window: {name}")
            continue
        scenarios.append((name, LABELS[name], start, end))

    if not scenarios:
        p.error("No complete, valid V2 scenarios found")

    samples, eligible_count, excluded_missing, excluded_ambiguous = [], 0, 0, 0
    for row in load_csv(args.metrics):
        ts = parse_utc(row["timestamp_utc"])
        matches = [s for s in scenarios if s[2] <= ts - WINDOW and ts <= s[3]]
        if len(matches) > 1:
            excluded_ambiguous += 1
            continue
        if not matches:
            continue
        eligible_count += 1
        name, label, _, _ = matches[0]
        sample = {"timestamp_utc": row["timestamp_utc"]}
        sample.update({feature: numeric_or_empty(row.get(feature)) for feature in FEATURES})
        if any(sample[f] == "" for f in REQUIRED):
            excluded_missing += 1
            continue
        sample.update({"label": label, "scenario": name})
        samples.append(sample)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["timestamp_utc", *FEATURES, "label", "scenario"])
        writer.writeheader()
        writer.writerows(samples)

    print(f"Created: {args.output}")
    print(f"Eligible clean-window timestamps: {eligible_count}")
    print(f"Excluded (missing required metrics): {excluded_missing}")
    print(f"Excluded (overlapping scenarios): {excluded_ambiguous}")
    print(f"Total labeled samples: {len(samples)}")
    counts = Counter(s["scenario"] for s in samples)
    for name in LABELS:
        group = [s for s in samples if s["scenario"] == name]
        print(f"\n{name}: {counts[name]} sample(s)")
        if group:
            print("  Median average latency: {:.4f} s".format(median(float(x["avg_latency_seconds"]) for x in group)))
            print("  Median request rate: {:.4f} req/s".format(median(float(x["request_rate_per_s"]) for x in group)))
            p95 = [float(x["p95_latency_seconds"]) for x in group if x["p95_latency_seconds"]]
            print("  Median estimated p95: {}".format("{:.4f} s".format(median(p95)) if p95 else "missing"))
            print(f"  First/last: {group[0]['timestamp_utc']} .. {group[-1]['timestamp_utc']}")
    if len(samples) < 1:
        raise SystemExit("No labeled samples: inspect export coverage and scenario timestamps")
    print("\nProof-of-concept labels only; these rows are not independent training/test sessions.")


if __name__ == "__main__":
    main()
