#!/usr/bin/env python3
"""KubeGuard AI Milestone 4: export Prometheus samples and Grafana alert events.

Run on the Ubuntu VM while Prometheus is port-forwarded to localhost:9090.
Requires Python 3 standard library only and access to MicroK8s.
"""

import argparse
import csv
import json
import math
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen

PROMQL = {
    "available_replicas": 'max(kube_deployment_status_replicas_available{namespace="kubeguard",deployment="kubeguard-api"})',
    "request_rate_per_s": 'sum(rate(kubeguard_requests_total{namespace="kubeguard"}[5m]))',
    "error_rate_pct": '100 * sum(rate(kubeguard_requests_total{namespace="kubeguard",outcome="error"}[5m])) / clamp_min(sum(rate(kubeguard_requests_total{namespace="kubeguard"}[5m])), 1e-9)',
    "p95_latency_seconds": 'histogram_quantile(0.95, sum by (le) (rate(kubeguard_request_duration_seconds_bucket{namespace="kubeguard"}[5m])))',
    "avg_latency_seconds": (
    'sum(rate(kubeguard_request_duration_seconds_sum{namespace="kubeguard"}[5m])) '
    '/ sum(rate(kubeguard_request_duration_seconds_count{namespace="kubeguard"}[5m]))'),
    "cpu_millicores": '1000 * sum(rate(container_cpu_usage_seconds_total{namespace="kubeguard",container="kubeguard-api"}[5m]))',
    "memory_mib": 'sum(container_memory_working_set_bytes{namespace="kubeguard",container="kubeguard-api"}) / 1024 / 1024',
    "cpu_throttle_pct": '100 * sum(rate(container_cpu_cfs_throttled_periods_total{namespace="kubeguard",container="kubeguard-api"}[5m])) / clamp_min(sum(rate(container_cpu_cfs_periods_total{namespace="kubeguard",container="kubeguard-api"}[5m])), 1e-9)',
}

# The OOM demo ran in a separate Pod. Never label FastAPI metrics as an OOM
# training example merely because that other Pod had an OOM event.
APPLICATION_ALERTS = {"KubeGuardAPIHighLatency", "KubeGuardAPIUnavailable"}

SQL_EXPORT = '''
import json, sqlite3
con = sqlite3.connect("/data/incidents.sqlite3")
con.row_factory = sqlite3.Row
rows = con.execute("""SELECT event_id, alert_name, status, namespace, pod,
container, fingerprint, starts_at, ends_at, received_at
FROM incidents ORDER BY received_at""").fetchall()
print(json.dumps([dict(r) for r in rows]))
'''


def unix_time(value):
    if not value or value.startswith("0001-"):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def export_incidents():
    command = [
        "microk8s", "kubectl", "exec", "-n", "monitoring",
        "deployment/kubeguard-incident-receiver", "-c", "receiver", "--",
        "python", "-c", SQL_EXPORT,
    ]
    try:
        proc = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        return json.loads(proc.stdout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        raise RuntimeError(f"Could not read incident SQLite database through Kubernetes: {exc}") from exc


def range_query(base_url, expression, start, end, step):
    args = urlencode({"query": expression, "start": start, "end": end, "step": step})
    url = f"{base_url.rstrip('/')}/api/v1/query_range?{args}"
    try:
        with urlopen(url, timeout=30) as response:
            payload = json.load(response)
    except (URLError, HTTPError, TimeoutError) as exc:
        raise RuntimeError(f"Unable to query Prometheus at {base_url}: {exc}") from exc
    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus query error: {payload.get('error', payload)}")
    data = payload.get("data", {})
    if data.get("resultType") != "matrix":
        raise RuntimeError(f"Expected matrix from query_range, received {data.get('resultType')}")
    rows = data.get("result", [])
    if len(rows) > 1:
        raise RuntimeError(f"Expected one aggregated series, received {len(rows)}")
    samples = {}
    for series in rows:
        for timestamp, raw in series.get("values", []):
            try:
                value = float(raw)
            except (TypeError, ValueError):
                continue
            if math.isfinite(value):
                samples[int(round(float(timestamp)))] = round(value, 6)
    return samples


def write_csv(path, fieldnames, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hours", type=int, default=6, help="How many previous hours to export (default 6)")
    parser.add_argument("--step", type=int, default=30, help="Sample interval in seconds (default 30)")
    parser.add_argument("--prometheus", default="http://127.0.0.1:9090")
    parser.add_argument("--output", default="data/milestone4")
    args = parser.parse_args()
    if not 1 <= args.hours <= 24 or not 15 <= args.step <= 300:
        parser.error("--hours must be 1..24 and --step must be 15..300 seconds")

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    end = (int(time.time()) // args.step) * args.step
    start = end - args.hours * 3600

    print("Reading stored Grafana notifications from SQLite...")
    incidents = export_incidents()
    incident_cols = ["event_id", "alert_name", "status", "namespace", "pod", "container", "fingerprint", "starts_at", "ends_at", "received_at"]
    write_csv(output / "incidents.csv", incident_cols, incidents)
    print(f"  Exported {len(incidents)} incident event(s)")

    print(f"Querying {args.hours} hour(s) of Prometheus metrics every {args.step}s...")
    metrics = {}
    for name, query in PROMQL.items():
        metrics[name] = range_query(args.prometheus, query, start, end, args.step)
        print(f"  {name}: {len(metrics[name])} valid points")

    # This is an exploratory *alert proximity* flag, NOT a ground-truth ML label.
    firing_events = []
    for event in incidents:
        if event.get("status") != "firing" or event.get("alert_name") not in APPLICATION_ALERTS:
            continue
        when = unix_time(event.get("starts_at"))
        if when is not None:
            firing_events.append((when, event["alert_name"]))

    fieldnames = ["timestamp_utc", *PROMQL, "near_application_alert"]
    samples = []
    for timestamp in range(start, end + 1, args.step):
        event_types = sorted({
            alert for event_time, alert in firing_events
            if event_time - 300 <= timestamp <= event_time + 60
        })
        sample = {"timestamp_utc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()}
        for metric in PROMQL:
            sample[metric] = metrics[metric].get(timestamp, "")
        sample["near_application_alert"] = ";".join(event_types)
        samples.append(sample)
    write_csv(output / "metrics.csv", fieldnames, samples)
    print(f"Created {output / 'metrics.csv'} with {len(samples)} rows")
    print(f"Created {output / 'incidents.csv'} with {len(incidents)} rows")
    if all(not metric for metric in metrics.values()):
        print("WARNING: Every metric is missing. Check Prometheus scrape targets and port-forward.", file=sys.stderr)
    print("Missing values are left blank (never silently treated as zero).")
    print("Alert proximity is for exploration; it is NOT a validated training label.")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
