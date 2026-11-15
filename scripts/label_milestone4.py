#!/usr/bin/env python3
"""Create a first *experimental* labeled KubeGuard AI dataset.

Run on the Ubuntu VM from the repository root:
    python3 scripts/label_milestone4.py

Reads data/milestone4/metrics.csv and scenarios.csv.
Does NOT query Prometheus or modify either source CSV.
"""

import argparse
import csv
import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median

# Labels describe the controlled experiment, NOT a verified incident root cause.
SCENARIO_LABELS = {
    "normal_traffic_long": 0,
    "high_latency_long": 1,
}
RATE_WINDOW = timedelta(minutes=5)

FEATURES = [
    "available_replicas",
    "request_rate_per_s",
    "avg_latency_seconds",
    "p95_latency_seconds",
    "cpu_millicores",
    "memory_mib",
    "cpu_throttle_pct",
]
# p95 may legitimately be absent; don't turn missing values into zeros.
REQUIRED_FEATURES = [
    "available_replicas",
    "request_rate_per_s",
    "avg_latency_seconds",
    "cpu_millicores",
    "memory_mib",
]


def utc_timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_scenarios(path):
    scenarios = []
    with path.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            name = row["scenario"]
            if name not in SCENARIO_LABELS:
                continue  # Ignore earlier short experiments.
            start = utc_timestamp(row["start_utc"])
            end = utc_timestamp(row["end_utc"])
            if end <= start:
                raise ValueError(f"Scenario {name!r} has an invalid time interval")
            scenarios.append((name, SCENARIO_LABELS[name], start, end))
    if not scenarios:
        raise ValueError("No long normal/high-latency scenarios found")
    return scenarios


def numeric_or_blank(value):
    if value is None or not value.strip():
        return ""
    try:
        number = float(value)
    except ValueError:
        return ""
    return value if math.isfinite(number) else ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default="data/milestone4")
    args = parser.parse_args()
    data_dir = Path(args.data_dir)
    scenarios = load_scenarios(data_dir / "scenarios.csv")
    labeled = []
    missing_required = 0
    eligible = 0

    with (data_dir / "metrics.csv").open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        missing_columns = set(FEATURES + ["timestamp_utc"]) - set(reader.fieldnames or [])
        if missing_columns:
            raise ValueError(f"Metrics CSV missing columns: {sorted(missing_columns)}")

        for row in reader:
            timestamp = utc_timestamp(row["timestamp_utc"])
            window_start = timestamp - RATE_WINDOW
            # A point is eligible ONLY when its entire trailing 5-minute rate
            # window fits in precisely one known scenario.
            matching = [
                s for s in scenarios if s[2] <= window_start and timestamp <= s[3]
            ]
            if len(matching) != 1:
                continue
            eligible += 1
            name, label, _, _ = matching[0]
            entry = {"timestamp_utc": row["timestamp_utc"], "scenario": name, "label": label}
            entry.update({feature: numeric_or_blank(row.get(feature)) for feature in FEATURES})
            if any(entry[feature] == "" for feature in REQUIRED_FEATURES):
                missing_required += 1
                continue
            labeled.append(entry)

    output = data_dir / "labeled_metrics.csv"
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["timestamp_utc", *FEATURES, "label", "scenario"])
        writer.writeheader()
        writer.writerows(labeled)

    print(f"Created: {output}")
    print(f"Eligible clean-window samples: {eligible}")
    print(f"Excluded (required metrics missing): {missing_required}")
    print(f"Total labeled samples: {len(labeled)}")
    counts = Counter(row["scenario"] for row in labeled)
    for name in SCENARIO_LABELS:
        group = [row for row in labeled if row["scenario"] == name]
        print(f"\n{name}: {counts[name]} sample(s)")
        if not group:
            continue
        avg = median(float(row["avg_latency_seconds"]) for row in group)
        print(f"  Median average latency: {avg:.4f} s")
        p95 = [float(row["p95_latency_seconds"]) for row in group if row["p95_latency_seconds"]]
        print(f"  Median p95 estimate: {median(p95):.4f} s" if p95 else "  P95: no valid samples")
        print(f"  First/last: {group[0]['timestamp_utc']} .. {group[-1]['timestamp_utc']}")

    if not labeled:
        raise SystemExit("No usable samples; check metric coverage and scenario times")
    print("\nThese labels are for a controlled proof of concept, not a production ML benchmark.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, ValueError) as error:
        raise SystemExit(f"ERROR: {error}") from error
