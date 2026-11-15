#!/usr/bin/env python3
"""KubeGuard AI: controlled, concurrent traffic experiments (Milestone 4).

Run on Ubuntu while the FastAPI Service is port-forwarded to localhost:18080.
Stdlib only. Records each run in a separate V2 experiment CSV without
modifying any previously collected Prometheus data or scenario files.
"""

import argparse
import csv
import math
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import urlopen


SCENARIOS = {
    "normal": ("normal_traffic_v2", 50),
    "latency": ("high_latency_v2", 1200),
}
COLUMNS = [
    "scenario", "start_utc", "end_utc", "requested_duration_sec",
    "delay_ms", "target_rps", "max_in_flight", "successful_requests",
    "failed_requests", "skipped_slots", "observed_rps",
    "mean_http_seconds", "p95_http_seconds", "status",
]


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def request_once(url, timeout):
    start = time.perf_counter()
    try:
        with urlopen(url, timeout=timeout) as response:
            response.read()
            status = response.status
        duration = time.perf_counter() - start
        if status != 200:
            return False, duration, f"HTTP {status}"
        return True, duration, ""
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        return False, time.perf_counter() - start, str(exc)


def percentile(values, percentile_value):
    ordered = sorted(values)
    if not ordered:
        return float("nan")
    rank = (len(ordered) - 1) * percentile_value
    lo = math.floor(rank)
    hi = math.ceil(rank)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (rank - lo)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    parser.add_argument("--duration-sec", type=int, default=480)
    parser.add_argument("--rps", type=float, default=1.0, help="Target request starts per second")
    parser.add_argument("--max-in-flight", type=int, default=4)
    parser.add_argument("--timeout-sec", type=float, default=5.0)
    parser.add_argument("--url", default="http://127.0.0.1:18080/work")
    parser.add_argument("--output", type=Path, default=Path("data/milestone4/scenarios_v2.csv"))
    args = parser.parse_args()

    # Conservative limits: this is a small single-node Kubernetes laboratory.
    if not (1 <= args.duration_sec <= 1800):
        parser.error("--duration-sec must be 1..1800")
    if not (0.1 <= args.rps <= 5.0):
        parser.error("--rps must be 0.1..5.0")
    if not (1 <= args.max_in_flight <= 10):
        parser.error("--max-in-flight must be 1..10")
    if not (1 <= args.timeout_sec <= 30):
        parser.error("--timeout-sec must be 1..30")
    parsed_url = urlsplit(args.url)
    if parsed_url.scheme != "http" or parsed_url.hostname not in ("127.0.0.1", "localhost", "::1"):
        parser.error("--url must be a local HTTP port-forward (localhost / 127.0.0.1)")
    if parsed_url.path != "/work" or parsed_url.query or parsed_url.fragment:
        parser.error("--url must end in /work without query parameters")

    scenario_name, delay_ms = SCENARIOS[args.scenario]
    request_url = args.url + "?" + urlencode({"delay_ms": delay_ms})
    print(f"Experiment: {scenario_name} | delay={delay_ms}ms | target={args.rps:g} req/s")
    print(f"Duration: {args.duration_sec}s | maximum concurrent requests: {args.max_in_flight}")
    print("Keep FastAPI port-forward running. Press Ctrl+C to abort (no CSV row recorded).", flush=True)

    started_at = utc_now()
    start = time.monotonic()
    end = start + args.duration_sec
    next_due = start
    interval = 1.0 / args.rps
    in_flight = set()
    results = []
    skipped = 0
    with ThreadPoolExecutor(max_workers=args.max_in_flight) as executor:
        while True:
            now = time.monotonic()
            if now >= end:
                break
            if now < next_due:
                time.sleep(min(next_due - now, end - now))
                continue

            completed = {f for f in in_flight if f.done()}
            for future in completed:
                results.append(future.result())
            in_flight.difference_update(completed)

            if len(in_flight) < args.max_in_flight:
                in_flight.add(executor.submit(request_once, request_url, args.timeout_sec))
            else:
                skipped += 1

            next_due += interval
            now = time.monotonic()
            if now > next_due:
                missed = math.floor((now - next_due) / interval) + 1
                skipped += missed
                next_due += missed * interval

        for future in in_flight:
            results.append(future.result())

    ended_at = utc_now()
    successes = [duration for ok, duration, _ in results if ok]
    failures = [message for ok, _, message in results if not ok]
    expected_slots = math.ceil(args.duration_sec * args.rps)
    passed = (not failures and not skipped and len(successes) >= 0.95 * expected_slots)
    status = "complete" if passed else "incomplete"
    row = {
        "scenario": scenario_name,
        "start_utc": started_at,
        "end_utc": ended_at,
        "requested_duration_sec": args.duration_sec,
        "delay_ms": delay_ms,
        "target_rps": args.rps,
        "max_in_flight": args.max_in_flight,
        "successful_requests": len(successes),
        "failed_requests": len(failures),
        "skipped_slots": skipped,
        "observed_rps": f"{len(successes) / args.duration_sec:.4f}",
        "mean_http_seconds": f"{statistics.mean(successes):.4f}" if successes else "",
        "p95_http_seconds": f"{percentile(successes, 0.95):.4f}" if successes else "",
        "status": status,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    existing = args.output.exists()
    with args.output.open("a", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS)
        if not existing or args.output.stat().st_size == 0:
            writer.writeheader()
        writer.writerow(row)

    print(f"Finished: {status}")
    print(f"Successful={len(successes)}, failed={len(failures)}, skipped_slots={skipped}")
    print(f"Observed throughput={row['observed_rps']} req/s")
    print(f"Mean HTTP duration={row['mean_http_seconds']}s, p95 HTTP={row['p95_http_seconds']}s")
    if failures:
        print("Example error(s):", *failures[:3], sep="\n  ")
    print(f"Recorded in {args.output}")
    if not passed:
        print("WARNING: The experiment is marked incomplete; do not use as clean training data.")


if __name__ == "__main__":
    main()
