#!/usr/bin/env python3
"""KubeGuard AI Milestone 5 — first experimental anomaly detector.

Train an Isolation Forest on *normal-only* V2 experiment samples and compare
its novelty predictions to a simple, explicit latency rule.

This is a proof of concept. Multiple rows from one eight-minute experiment
are strongly correlated; training normals are also present in the diagnostic
output. Do not interpret row counts as an independent test-set evaluation.

Install: python -m pip install 'scikit-learn>=1.3,<2' joblib
Run: python scripts/train_milestone5.py
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from statistics import median

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError as exc:
    raise SystemExit(
        "Missing ML libraries. In an Ubuntu virtual environment, run: "
        "python -m pip install 'scikit-learn>=1.3,<2' joblib"
    ) from exc

FEATURES = ("avg_latency_seconds", "request_rate_per_s", "cpu_millicores", "memory_mib")
REQUIRED = ("timestamp_utc", "scenario", "label", *FEATURES)


def read_samples(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        missing = set(REQUIRED) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"CSV missing required columns: {sorted(missing)}")
        rows = []
        seen = set()
        for idx, row in enumerate(reader, start=2):
            ts = row["timestamp_utc"]
            if ts in seen:
                raise ValueError(f"Duplicate timestamp at CSV line {idx}: {ts}")
            seen.add(ts)
            try:
                label = int(row["label"])
                values = [float(row[f]) for f in FEATURES]
            except (ValueError, TypeError, KeyError) as exc:
                raise ValueError(f"Missing or nonnumeric metric at CSV line {idx}") from exc
            if label not in (0, 1) or not all(map(math.isfinite, values)):
                raise ValueError(f"Invalid label/non-finite metric at CSV line {idx}")
            row["_label"] = label
            row["_vector"] = values
            rows.append(row)
    if not rows:
        raise ValueError("Input CSV is empty")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/milestone4/combined_labeled_metrics.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/milestone5"))
    parser.add_argument("--min-latency-threshold-ms", type=float, default=250.0,
                        help="Practical lower bound for the latency rule; not learned from data")
    args = parser.parse_args()
    if args.min_latency_threshold_ms <= 0:
        parser.error("Latency threshold must be positive")

    rows = read_samples(args.input)
    normals = [r for r in rows if r["_label"] == 0]
    anomalies = [r for r in rows if r["_label"] == 1]
    if len(normals) < 6 or not anomalies:
        parser.error("Need at least six normal rows and one known anomaly for this demonstration")

    # Training uses *only normal samples*. The known anomaly labels are for
    # post-hoc diagnostics; they are never passed into the model's fit().
    x_train = np.asarray([r["_vector"] for r in normals], dtype=float)
    x_all = np.asarray([r["_vector"] for r in rows], dtype=float)
    scaler = StandardScaler().fit(x_train)
    forest = IsolationForest(n_estimators=200, contamination=0.1, random_state=42)
    forest.fit(scaler.transform(x_train))
    # Negative score_samples is an anomaly score: larger = more unusual.
    anomaly_scores = -forest.score_samples(scaler.transform(x_all))
    forest_flags = forest.predict(scaler.transform(x_all)) == -1

    normal_latencies = [float(r["avg_latency_seconds"]) for r in normals]
    normal_median = median(normal_latencies)
    mad = median(abs(x - normal_median) for x in normal_latencies)
    # Deliberately conservative latency baseline for this proof of concept.
    # Real SLOs must be chosen from the service's performance requirements.
    latency_threshold = max(
        args.min_latency_threshold_ms / 1000.0,
        3.0 * normal_median,
        normal_median + 8.0 * 1.4826 * mad,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_csv = args.output_dir / "predictions.csv"
    fieldnames = ["timestamp_utc", "scenario", "request_rate_per_s", "known_label",
                  "used_for_training", "avg_latency_seconds", "baseline_anomaly",
                  "isolation_forest_anomaly", "isolation_forest_score"]
    predictions = []
    for i, row in enumerate(rows):
        pred = {
            "timestamp_utc": row["timestamp_utc"],
            "scenario": row["scenario"],
            "request_rate_per_s": row["request_rate_per_s"],
            "known_label": row["_label"],
            "used_for_training": int(row["_label"] == 0),
            "avg_latency_seconds": row["avg_latency_seconds"],
            "baseline_anomaly": int(float(row["avg_latency_seconds"]) > latency_threshold),
            "isolation_forest_anomaly": int(forest_flags[i]),
            "isolation_forest_score": f"{anomaly_scores[i]:.6f}",
        }
        predictions.append(pred)
    with output_csv.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(predictions)

    groups = defaultdict(list)
    for p in predictions:
        groups[(p["scenario"], float(p["request_rate_per_s"]))].append(p)
    group_stats = []
    for (scenario, rps), ps in sorted(groups.items(), key=lambda item: (item[0][1], item[0][0])):
        group_stats.append({
            "scenario": scenario,
            "rps": rps,
            "rows": len(ps),
            "known_label": ps[0]["known_label"],
            "baseline_flags": sum(p["baseline_anomaly"] for p in ps),
            "isolation_forest_flags": sum(p["isolation_forest_anomaly"] for p in ps),
        })

    report = {
        "purpose": "proof_of_concept_not_independent_evaluation",
        "source_csv": str(args.input),
        "rows": len(rows),
        "normal_training_rows": len(normals),
        "known_anomaly_rows_not_used_in_fit": len(anomalies),
        "features": list(FEATURES),
        "baseline_latency_threshold_seconds": latency_threshold,
        "baseline_normal_median_seconds": normal_median,
        "baseline_normal_mad_seconds": mad,
        "isolation_forest": {"n_estimators": 200, "contamination": 0.1, "random_state": 42},
        "groups": group_stats,
        "limitations": [
            "Only four independent traffic experiments in the current dataset",
            "Normal samples were used for fitting and are included in the diagnostic table",
            "Isolation Forest scores need not increase for values far beyond the training range",
            "The latency rule is a configurable heuristic, not a validated SLO",
        ],
    }
    (args.output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    joblib.dump({
        "model": forest,
        "scaler": scaler,
        "features": FEATURES,
        "baseline_threshold_seconds": latency_threshold,
        "warning": "Proof of concept — do not deploy for automated remediation",
    }, args.output_dir / "detector.joblib")

    print(f"Input: {args.input}")
    print(f"Training: {len(normals)} normal rows (all normal experiments)")
    print(f"Known anomalies held out of fit: {len(anomalies)} rows")
    print(f"Latency-rule threshold: {latency_threshold:.4f}s")
    print("\nGroup diagnostics (not independent test-set accuracy):")
    for g in group_stats:
        print(f"  {g['scenario']:<22} {g['rps']:g} RPS | {g['rows']:2} rows | "
              f"rule {g['baseline_flags']}/{g['rows']} | "
              f"IsolationForest {g['isolation_forest_flags']}/{g['rows']}")
    print(f"\nWrote {output_csv}")
    print(f"Wrote {args.output_dir / 'report.json'}")
    print(f"Wrote {args.output_dir / 'detector.joblib'}")
    print("IMPORTANT: Model scores and row-level counts do not establish real-world accuracy.")


if __name__ == "__main__":
    main()
