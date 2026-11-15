#!/usr/bin/env python3
"""KubeGuard AI Milestone 6: read-only incident evidence collector.

Sources:
  - Existing incident-receiver SQLite (SELECT via microk8s kubectl exec).
  - Prometheus historical /api/v1/query_range on a localhost port-forward.
  - Current Kubernetes deployment/pod summaries and namespace events.

Writes ONLY local JSON/Markdown evidence files. No cluster mutations, log or
secret collection, notification delivery, ML inference, or AI diagnosis.

Run from repository root:
  python scripts/collect_milestone6_evidence.py
  python scripts/collect_milestone6_evidence.py --episode-start 2026-11-15T18:46:13Z
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import urlopen

from build_milestone4_dataset import PROMQL

UTC = timezone.utc
ALERT = "KubeGuardAIHighLatency"
NAMESPACE = "kubeguard"
DEPLOYMENT = "kubeguard-api"

# Exact label selectors / recording queries already used by the KubeGuard app.
QUERIES = {name: PROMQL[name] for name in (
    "available_replicas", "request_rate_per_s", "avg_latency_seconds",
    "p95_latency_seconds", "error_rate_pct", "cpu_millicores",
    "memory_mib", "cpu_throttle_pct",
)}
QUERIES.update({
    "requests_1m": 'sum(increase(kubeguard_request_duration_seconds_count{namespace="kubeguard"}[1m]))',
    "requests_5m": 'sum(increase(kubeguard_request_duration_seconds_count{namespace="kubeguard"}[5m]))',
})

# This script is executed remotely as `python -c <SQL_SCRIPT> <start-or-empty>`.
# Use sqlite read-only mode, fixed queries and SQL placeholders, never eval.
SQL_SCRIPT = r'''
import json, sqlite3, sys
con = sqlite3.connect('file:/data/incidents.sqlite3?mode=ro', uri=True)
con.row_factory = sqlite3.Row
start = sys.argv[1]
row = con.execute(''' + '"""' + r'''
SELECT event_id, alert_name, status, namespace, fingerprint,
       starts_at, ends_at, received_at, values_json
FROM incidents
WHERE alert_name=? AND status='firing' AND (?='' OR starts_at=?)
ORDER BY starts_at DESC, received_at DESC LIMIT 1
''' + '"""' + r''', ('KubeGuardAIHighLatency', start, start)).fetchone()
if row is None:
    print(json.dumps({'firing': None, 'resolved': None}))
else:
    firing = dict(row)
    match = con.execute(''' + '"""' + r'''
SELECT event_id, alert_name, status, namespace, fingerprint,
       starts_at, ends_at, received_at, values_json
FROM incidents
WHERE alert_name=? AND status='resolved' AND fingerprint=? AND starts_at=?
ORDER BY received_at DESC LIMIT 1
''' + '"""' + r''', ('KubeGuardAIHighLatency', firing['fingerprint'], firing['starts_at'])).fetchone()
    print(json.dumps({'firing': firing, 'resolved': dict(match) if match else None}))
'''


def parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("Missing incident timestamp")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Incident timestamp must include a timezone")
    return dt.astimezone(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_local_prometheus(url: str) -> str:
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/") or parsed.port is None):
        raise ValueError("Prometheus must be a localhost HTTP port-forward, e.g. http://127.0.0.1:9090")
    return url.rstrip("/")


def run_kubectl(arguments: list[str], timeout: int = 25) -> str:
    command = ["microk8s", "kubectl", *arguments]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise RuntimeError(f"kubectl read failed ({arguments[0]}): {exc}") from exc
    if proc.returncode:
        # Do not include noisy full command/environment in error; stdout unused.
        raise RuntimeError(f"kubectl {arguments[0]} failed: {proc.stderr.strip()[:350]}")
    return proc.stdout


def fetch_incident(episode_start: str | None) -> dict:
    if episode_start:
        parse_utc(episode_start)
    result = run_kubectl([
        "exec", "-n", "monitoring", "deployment/kubeguard-incident-receiver",
        "-c", "receiver", "--", "python", "-c", SQL_SCRIPT, episode_start or "",
    ], timeout=35)
    try:
        payload = json.loads(result)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Incident receiver returned invalid JSON") from exc
    firing = payload.get("firing")
    if not firing:
        raise RuntimeError("No matching KubeGuardAIHighLatency firing incident found in SQLite")
    resolved = payload.get("resolved")
    if firing.get("status") != "firing" or firing.get("alert_name") != ALERT:
        raise RuntimeError("Unexpected incident returned from SQLite")
    if resolved and (resolved.get("status") != "resolved" or
                     resolved.get("fingerprint") != firing.get("fingerprint") or
                     resolved.get("starts_at") != firing.get("starts_at")):
        raise RuntimeError("Resolved event does not match firing event")
    return payload


def incident_summary(rows: dict) -> dict:
    firing, resolved = rows["firing"], rows["resolved"]
    def values(item):
        if not item or not item.get("values_json"):
            return {}
        try:
            val = json.loads(item["values_json"])
            return val if isinstance(val, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {
        "alert_name": firing["alert_name"],
        "namespace": firing.get("namespace"),
        "fingerprint": firing.get("fingerprint"),
        "episode_start_at": firing["starts_at"],
        "firing_event_id": firing.get("event_id"),
        "firing_received_at": firing.get("received_at"),
        "firing_values": values(firing),
        "resolved": resolved is not None,
        "resolution_at": resolved.get("ends_at") if resolved else None,
        "resolved_event_id": resolved.get("event_id") if resolved else None,
        "resolved_received_at": resolved.get("received_at") if resolved else None,
        "resolved_values": values(resolved),
    }


def evidence_window(incident: dict, now: datetime, before: int, after: int,
                    max_minutes: int = 60) -> tuple[datetime, datetime, list[str]]:
    start = parse_utc(incident["episode_start_at"])
    if start > now + timedelta(minutes=1):
        raise ValueError("Incident start is in the future")
    left = start - timedelta(minutes=before)
    right = (parse_utc(incident["resolution_at"]) + timedelta(minutes=after)
             if incident["resolved"] else now)
    if right > now:
        right = now
    if right < left:
        raise ValueError("Invalid incident window")
    warnings = []
    if right - left > timedelta(minutes=max_minutes):
        right = left + timedelta(minutes=max_minutes)
        warnings.append(f"Time range capped at {max_minutes} minutes; evidence window may omit later observations")
    return left, right, warnings


def query_prometheus(base_url: str, expression: str, start: datetime,
                     end: datetime, step_seconds: int) -> list[dict]:
    url = base_url + "/api/v1/query_range?" + urlencode({
        "query": expression, "start": int(start.timestamp()),
        "end": int(end.timestamp()), "step": step_seconds,
    })
    try:
        with urlopen(url, timeout=20) as response:
            payload = json.load(response)
    except (OSError, URLError, HTTPError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f"Prometheus request failed: {exc}") from exc
    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus returned {payload.get('error', 'non-success response')}")
    data = payload.get("data", {})
    if data.get("resultType") != "matrix":
        raise RuntimeError("Expected query_range matrix")
    series = data.get("result", [])
    if len(series) > 1:
        raise RuntimeError("Expected single aggregated series, got multiple")
    samples = []
    if series:
        for pair in series[0].get("values", []):
            try:
                timestamp, raw = pair
                number = float(raw)
                stamp = float(timestamp)
            except (ValueError, TypeError):
                continue
            if math.isfinite(number) and math.isfinite(stamp):
                samples.append({"timestamp_utc": iso(datetime.fromtimestamp(stamp, UTC)),
                                "value": round(number, 6)})
    return samples


def summarize_series(samples: list[dict]) -> dict:
    if not samples:
        return {"sample_count": 0, "min": None, "max": None, "first": None, "last": None}
    numbers = [p["value"] for p in samples]
    return {"sample_count": len(samples), "min": min(numbers), "max": max(numbers),
            "first": numbers[0], "last": numbers[-1]}


def collect_prometheus(url: str, left: datetime, right: datetime,
                       step: int) -> dict:
    results, warnings = {}, []
    for name, expression in QUERIES.items():
        try:
            points = query_prometheus(url, expression, left, right, step)
            if not points:
                warnings.append(f"No Prometheus samples for {name}; absence is not zero")
            results[name] = {"query": expression, "summary": summarize_series(points),
                             "points": points, "error": None}
        except RuntimeError as exc:
            warnings.append(f"{name}: {exc}")
            results[name] = {"query": expression, "summary": summarize_series([]),
                             "points": [], "error": str(exc)}
    return {"kind": "historical_time_series", "series": results, "warnings": warnings}


def _short(value, length: int = 260) -> str | None:
    if value is None:
        return None
    return str(value)[:length]


def summarize_deployment(item: dict) -> dict:
    spec, status = item.get("spec", {}), item.get("status", {})
    return {"name": item.get("metadata", {}).get("name"),
            "desired_replicas": spec.get("replicas", 1),
            "available_replicas": status.get("availableReplicas", 0),
            "ready_replicas": status.get("readyReplicas", 0),
            "updated_replicas": status.get("updatedReplicas", 0),
            "generation": item.get("metadata", {}).get("generation"),
            "observed_generation": status.get("observedGeneration"),
            "conditions": [{"type": c.get("type"), "status": c.get("status"),
                            "reason": _short(c.get("reason"), 100)}
                           for c in status.get("conditions", [])],
            "selector_match_labels": spec.get("selector", {}).get("matchLabels") or {}}


def summarize_pods(pod_list: dict, match_labels: dict) -> list[dict]:
    result = []
    for item in pod_list.get("items", []):
        metadata = item.get("metadata", {})
        labels = metadata.get("labels") or {}
        if match_labels and not all(labels.get(k) == v for k, v in match_labels.items()):
            continue
        status = item.get("status", {})
        result.append({
            "name": metadata.get("name"),
            "phase": status.get("phase"),
            "node": item.get("spec", {}).get("nodeName"),
            "created_at": metadata.get("creationTimestamp"),
            "pod_ready": next((c.get("status") == "True" for c in status.get("conditions", [])
                               if c.get("type") == "Ready"), None),
            "containers": [{
                "name": c.get("name"), "ready": c.get("ready"),
                "restart_count": c.get("restartCount", 0),
                "waiting_reason": _short((c.get("state") or {}).get("waiting", {}).get("reason"), 100),
                "terminated_reason": _short((c.get("lastState") or {}).get("terminated", {}).get("reason"), 100),
                "last_exit_code": (c.get("lastState") or {}).get("terminated", {}).get("exitCode"),
            } for c in status.get("containerStatuses", [])],
        })
    return sorted(result, key=lambda row: row.get("name") or "")


def summarize_events(events: dict, pod_names: set[str]) -> list[dict]:
    out = []
    for event in events.get("items", []):
        reference = event.get("involvedObject") or event.get("regarding") or {}
        name = reference.get("name")
        if not (name in pod_names or name == DEPLOYMENT):
            continue
        out.append({
            "timestamp_utc": event.get("eventTime") or event.get("lastTimestamp") or
                             event.get("metadata", {}).get("creationTimestamp"),
            "type": event.get("type"), "reason": _short(event.get("reason"), 100),
            "message": _short(event.get("message") or event.get("note")),
            "count": event.get("count"), "involved_object": name,
        })
    return sorted(out, key=lambda row: row.get("timestamp_utc") or "", reverse=True)[:20]


def collect_kubernetes(observed_at: str) -> dict:
    result = {"kind": "current_snapshot_not_historical", "observed_at": observed_at,
              "deployment": None, "pods": [], "recent_events": [], "warnings": []}
    selector = {"app": DEPLOYMENT}  # fallback only if deployment query fails
    for label, args in (
        ("deployment", ["get", "deployment", DEPLOYMENT, "-n", NAMESPACE, "-o", "json"]),
        ("pods", ["get", "pods", "-n", NAMESPACE, "-o", "json"]),
        ("events", ["get", "events", "-n", NAMESPACE, "-o", "json"]),
    ):
        try:
            data = json.loads(run_kubectl(args))
            if label == "deployment":
                result["deployment"] = summarize_deployment(data)
                selector = result["deployment"]["selector_match_labels"] or selector
            elif label == "pods":
                result["pods"] = summarize_pods(data, selector)
            else:
                result["recent_events"] = summarize_events(data, {p["name"] for p in result["pods"]})
        except (RuntimeError, ValueError, KeyError, TypeError) as exc:
            result["warnings"].append(f"Kubernetes {label} query failed: {exc}")
    return result


def format_markdown(report: dict) -> str:
    inc = report["incident"]
    p = report["prometheus"]["series"]
    k = report["kubernetes"]
    lines = [
        "# KubeGuard AI — Incident evidence", "",
        f"- Alert: `{inc['alert_name']}`",
        f"- Episode start: `{inc['episode_start_at']}`",
        f"- Episode resolved: `{inc['resolution_at']}`" if inc["resolved"] else "- Episode resolution: not recorded",
        f"- Historical metrics window: `{report['window']['start_utc']}` to `{report['window']['end_utc']}`",
        f"- Kubernetes snapshot obtained: `{k['observed_at']}` (CURRENT state, not state at incident time)",
        "", "## Historical Prometheus observations", "",
        "| Metric | Samples | Minimum | Maximum | Last |", "|---|---:|---:|---:|---:|",
    ]
    for name, details in p.items():
        stats = details["summary"]
        def fmt(v):
            return "n/a" if v is None else f"{v:.4f}"
        lines.append(f"| `{name}` | {stats['sample_count']} | {fmt(stats['min'])} | {fmt(stats['max'])} | {fmt(stats['last'])} |")
    lines += ["", "*Missing series mean unavailable evidence, not a measured zero. Prometheus p95 is an estimated histogram quantile.*",
              "", "## Current Kubernetes snapshot", ""]
    dep = k["deployment"]
    if dep:
        lines.append(f"- Deployment `{dep['name']}`: desired={dep['desired_replicas']}, ready={dep['ready_replicas']}, available={dep['available_replicas']}")
    else:
        lines.append("- Deployment information unavailable")
    if k["pods"]:
        for pod in k["pods"]:
            total = sum(c.get("restart_count") or 0 for c in pod["containers"])
            lines.append(f"- Pod `{pod['name']}`: phase={pod['phase']}, ready={pod['pod_ready']}, current container restart counts total={total}")
    else:
        lines.append("- No matching pod snapshots available")
    lines.append(f"- Matching recent Kubernetes events: {len(k['recent_events'])} (events may have expired)")
    lines += ["", "## Evidence gaps and cautions", ""]
    all_warnings = report["warnings"]
    lines.extend(f"- {w}" for w in all_warnings)
    lines += ["", "**No cause has been inferred.** This evidence bundle is intended for later, evidence-grounded investigation.", ""]
    return "\n".join(lines)


def atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".kubeguard-evidence-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def collect(episode_start: str | None, prometheus: str, before: int,
            after: int, step: int, output: Path) -> tuple[Path, Path, dict]:
    base = safe_local_prometheus(prometheus)
    now = datetime.now(UTC)
    raw_incident = fetch_incident(episode_start)
    incident = incident_summary(raw_incident)
    left, right, window_warnings = evidence_window(incident, now, before, after)
    metrics = collect_prometheus(base, left, right, step)
    k8s = collect_kubernetes(iso(datetime.now(UTC)))
    warnings = window_warnings + metrics["warnings"] + k8s["warnings"] + [
        "Kubernetes deployment, pod and event data are collected NOW, not reconstructed historically",
        "Kubernetes events can expire; their absence does not prove that no events occurred",
        "Prometheus retention can remove older incident metrics; absence is not zero",
        "This is evidence collection only; no root cause, ML classification or remediation is asserted",
    ]
    report = {
        "schema_version": 1, "generated_at": iso(datetime.now(UTC)),
        "source": "kubeguard-ai-milestone6-read-only",
        "incident": incident,
        "window": {"start_utc": iso(left), "end_utc": iso(right), "step_seconds": step},
        "prometheus": metrics,
        "kubernetes": k8s,
        "warnings": warnings,
    }
    stamp = re.sub(r"[^0-9TZ]", "", iso(parse_utc(incident["episode_start_at"])))
    prefix = f"incident_evidence_{stamp}"
    json_path = output / (prefix + ".json")
    md_path = output / (prefix + ".md")
    atomic_text(json_path, json.dumps(report, indent=2, allow_nan=False) + "\n")
    atomic_text(md_path, format_markdown(report))
    return json_path, md_path, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--episode-start", help="Optional exact startsAt timestamp to select an older incident")
    parser.add_argument("--prometheus", default="http://127.0.0.1:9090")
    parser.add_argument("--before-minutes", type=int, default=5)
    parser.add_argument("--after-minutes", type=int, default=5)
    parser.add_argument("--step-seconds", type=int, default=30)
    parser.add_argument("--output-dir", type=Path, default=Path("data/milestone6"))
    args = parser.parse_args()
    if not 0 <= args.before_minutes <= 30 or not 0 <= args.after_minutes <= 30:
        parser.error("before/after must be 0..30 minutes")
    if not 15 <= args.step_seconds <= 300:
        parser.error("step-seconds must be 15..300")
    try:
        json_path, md_path, report = collect(
            args.episode_start, args.prometheus, args.before_minutes,
            args.after_minutes, args.step_seconds, args.output_dir)
    except (RuntimeError, ValueError, OSError, TypeError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Evidence JSON: {json_path}")
    print(f"Evidence Markdown: {md_path}")
    print(f"Incident: {report['incident']['episode_start_at']} | resolved={report['incident']['resolved']}")
    successes = sum(bool(s["points"]) for s in report["prometheus"]["series"].values())
    print(f"Prometheus metrics with data: {successes}/{len(QUERIES)}")
    print(f"Kubernetes pods: {len(report['kubernetes']['pods'])}; events: {len(report['kubernetes']['recent_events'])}")
    print(f"Warnings/cautions: {len(report['warnings'])}")
    print("Read-only collector. No Kubernetes changes, incident notifications or AI diagnosis.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
