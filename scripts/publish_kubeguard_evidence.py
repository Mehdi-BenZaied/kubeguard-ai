#!/usr/bin/env python3
"""Publish approved KubeGuard incident summaries from a MicroK8s evidence PVC.

Ubuntu host only. Reads raw collector files *inside* the collector container.
Only a fixed numeric allowlist leaves the pod; never raw alerts, log bodies,
receiver database, tokens, Kubernetes Secrets, or Prometheus point timestamps.
Publishes completed firing+resolved episodes only, atomically and immutably.
No remediation. No changes to existing Kubernetes Deployments/PVCs.

Requires an operator's pre-existing `microk8s kubectl exec` access. This is an
interim host-side publisher, NOT a least-privileged Kubernetes credential.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

METRICS = frozenset({
    "available_replicas", "running_pods", "container_restarts",
    "avg_latency_seconds", "p95_latency_seconds", "request_rate_per_s",
    "error_rate_pct", "cpu_millicores", "memory_mib", "cpu_throttle_pct",
})
GAPS = frozenset(prefix + name for prefix in ("missing_", "unavailable_") for name in METRICS)
MAX_REPORT_BYTES = 32_768
MAX_BUNDLE_BYTES = 524_288
MAX_FILES = 100

# This snippet runs inside the collector container.  It does not print raw
# evidence; it extracts and validates only the fields the AI is approved to see.
POD_READER = r'''
import json, math, os, re
from pathlib import Path
from datetime import datetime

root = Path('/data/evidence')
metrics = {'available_replicas', 'running_pods', 'container_restarts',
           'avg_latency_seconds', 'p95_latency_seconds', 'request_rate_per_s',
           'error_rate_pct', 'cpu_millicores', 'memory_mib', 'cpu_throttle_pct'}
gaps_allowed = {p + k for p in ('missing_', 'unavailable_') for k in metrics}
name_re = re.compile(r'incident_([a-f0-9]{64})\.json\Z')

def strict_json(raw):
    def unique(pairs):
        d={}
        for k, v in pairs:
            if k in d: raise ValueError('duplicate JSON field')
            d[k]=v
        return d
    def nonfinite(s): raise ValueError('nonfinite numeric literal')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)

def num(n):
    return type(n) in (int, float) and math.isfinite(n) and 0 <= n <= 1e12

def iso(s):
    if type(s) is not str or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', s):
        raise ValueError('invalid UTC timestamp')
    datetime.fromisoformat(s.replace('Z', '+00:00'))
    return s

def summary(obj, event_id):
    if type(obj) is not dict or set(obj) != {
        'schema_version','purpose','generated_at','incident','window','metrics',
        'evidence_gaps','cautions'} or type(obj['schema_version']) is not int or obj['schema_version'] != 1:
        raise ValueError('unexpected collector document')
    ev=obj['incident']
    if type(ev) is not dict or set(ev) != {
        'event_id','status','starts_at','ends_at','received_at','values'}:
        raise ValueError('unexpected incident structure')
    if ev['event_id'] != event_id or ev['status'] not in ('firing','resolved'):
        raise ValueError('invalid event identity')
    start=iso(ev['starts_at'])
    if ev['status'] == 'firing':
        if ev['ends_at'] is not None: raise ValueError('firing has end timestamp')
    else:
        end=iso(ev['ends_at'])
        if end < start: raise ValueError('resolution before firing')
    source=obj['metrics']
    if type(source) is not dict or set(source) != metrics:
        raise ValueError('unexpected metric set')
    gaps=obj['evidence_gaps']
    if (type(gaps) is not list or len(gaps)>20 or len(gaps)!=len(set(gaps)) or
        any(type(g) is not str or g not in gaps_allowed for g in gaps)):
        raise ValueError('unexpected evidence gap')
    out={}
    for name in sorted(metrics):
        m=source[name]
        if type(m) is not dict or set(m) != {'sample_count','min','max','last','points'}:
            raise ValueError('unexpected metric shape')
        count=m['sample_count']
        if type(count) is not int or count<0 or count>20:
            raise ValueError('invalid sample count')
        values=[m[k] for k in ('min','max','last')]
        if count == 0:
            if any(v is not None for v in values) or not (('missing_'+name) in gaps or ('unavailable_'+name) in gaps):
                raise ValueError('missing series consistency')
        else:
            if not all(num(v) for v in values) or not (values[0] <= values[2] <= values[1]):
                raise ValueError('invalid metric range')
            if ('missing_'+name) in gaps or ('unavailable_'+name) in gaps:
                raise ValueError('metric incorrectly marked missing')
        out[name]={'sample_count':count, 'min':m['min'], 'max':m['max'], 'last':m['last']}
    return start, {'status':ev['status'], 'metrics':out, 'evidence_gaps':sorted(gaps)}

paths=sorted(root.iterdir())
files=[p for p in paths if name_re.fullmatch(p.name)]
if len(files)>100: raise ValueError('more than 100 evidence files; fail closed')
episodes={}
for p in files:
    if p.is_symlink() or not p.is_file() or p.stat().st_size>32768:
        raise ValueError('unsafe evidence file')
    with p.open('rb') as f: raw=f.read(32769)
    if len(raw)>32768: raise ValueError('oversized evidence')
    eid=name_re.fullmatch(p.name).group(1)
    start, event=summary(strict_json(raw), eid)
    stages=episodes.setdefault(start,{})
    if event['status'] in stages: raise ValueError('duplicate lifecycle status')
    stages[event['status']]=event
bundle=[]
for start, stages in sorted(episodes.items()):
    if 'resolved' not in stages: continue  # Wait for full lifecycle.
    if set(stages) != {'firing','resolved'}: raise ValueError('resolved event missing firing pair')
    bundle.append({'schema_version':1, 'incident_type':'high_latency',
                   'episode_start_utc':start,
                   'evidence':[stages['firing'], stages['resolved']]})
print(json.dumps({'schema_version':1,'episodes':bundle,'pending':sum('resolved' not in s for s in episodes.values())},
                 separators=(',',':'), allow_nan=False))
'''


def strict_json(raw: bytes):
    def unique(pairs):
        value = {}
        for key, v in pairs:
            if key in value:
                raise ValueError("Duplicate JSON key")
            value[key] = v
        return value
    def nonfinite(token):
        raise ValueError("Nonfinite JSON literal")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def valid_number(n):
    return type(n) in (int, float) and math.isfinite(n) and 0 <= n <= 1e12


def validate_summary(report):
    """Re-validate all values on the Ubuntu host (pod output is untrusted)."""
    if type(report) is not dict or set(report) != {"schema_version", "incident_type", "episode_start_utc", "evidence"}:
        raise ValueError("Invalid summary keys")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1 or report["incident_type"] != "high_latency":
        raise ValueError("Unexpected incident type or version")
    start = report["episode_start_utc"]
    if type(start) is not str or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", start):
        raise ValueError("Unexpected episode timestamp")
    datetime.fromisoformat(start.replace("Z", "+00:00"))
    phases=report["evidence"]
    if type(phases) is not list or len(phases) != 2 or [p.get("status") if type(p) is dict else None for p in phases] != ["firing", "resolved"]:
        raise ValueError("Episode is not a complete firing/resolved pair")
    for phase in phases:
        if set(phase) != {"status", "metrics", "evidence_gaps"}:
            raise ValueError("Unexpected phase keys")
        m=phase["metrics"]
        if type(m) is not dict or set(m) != METRICS:
            raise ValueError("Unexpected metric name")
        gaps=phase["evidence_gaps"]
        if type(gaps) is not list or len(gaps)>20 or len(gaps)!=len(set(gaps)) or any(type(g) is not str or g not in GAPS for g in gaps):
            raise ValueError("Invalid gaps")
        for k, v in m.items():
            if type(v) is not dict or set(v) != {"sample_count", "min", "max", "last"}:
                raise ValueError("Invalid metric summary")
            n=v["sample_count"]
            if type(n) is not int or not 0<=n<=20:
                raise ValueError("Invalid sample count")
            values=[v[x] for x in ("min", "max", "last")]
            if n == 0:
                if any(x is not None for x in values) or not ("missing_"+k in gaps or "unavailable_"+k in gaps):
                    raise ValueError("Inconsistent missing metric")
            elif (not all(valid_number(x) for x in values) or not values[0]<=values[2]<=values[1]
                  or "missing_"+k in gaps or "unavailable_"+k in gaps):
                raise ValueError("Invalid numeric range")
    return report


def filename_for(report):
    validate_summary(report)
    return "episode_" + hashlib.sha256(report["episode_start_utc"].encode("ascii")).hexdigest()[:32] + ".json"


def encode(report):
    validate_summary(report)
    data=(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    if len(data)>MAX_REPORT_BYTES:
        raise ValueError("Summary too large")
    return data


def publish(directory: Path, report):
    """Atomic create-only; existing differing file is a conflict, never overwrite."""
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Publisher output must be an existing real directory")
    name=filename_for(report)
    payload=encode(report)
    destination=directory/name
    if destination.is_symlink():
        raise ValueError("Refusing symlink destination")
    if destination.exists():
        if not destination.is_file() or destination.stat().st_size>MAX_REPORT_BYTES:
            raise ValueError("Invalid existing published file")
        if destination.read_bytes() != payload:
            raise ValueError("Published episode already exists with different content; stop")
        return name, "already-published"
    fd,tmp=tempfile.mkstemp(prefix=".kubeguard-",dir=directory)
    try:
        with os.fdopen(fd,"wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(),0o640)
        # Use an atomic hardlink: unlike rename(), fails if the final file exists.
        os.link(tmp, destination)
        dfd=os.open(directory,os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return name, "published"


def read_collector():
    argv=["microk8s","kubectl", "-n", "monitoring", "exec", "deployment/kubeguard-evidence-collector",
          "-c", "collector", "--", "python3", "-c", POD_READER]
    done=subprocess.run(argv,capture_output=True,timeout=40,check=False)
    if done.returncode:
        raise RuntimeError(f"Collector read failed (exit={done.returncode}); no raw stderr emitted")
    if len(done.stdout)>MAX_BUNDLE_BYTES:
        raise ValueError("Collector response too large")
    return strict_json(done.stdout)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true", help="Validate without publishing")
    p.add_argument("--output-dir",type=Path,default=Path('/srv/kubeguard-sftp/evidence'))
    args=p.parse_args(argv)
    os.umask(0o077)
    data=read_collector()
    if (type(data) is not dict or set(data)!={"schema_version", "episodes", "pending"} or
        type(data["schema_version"]) is not int or data["schema_version"]!=1 or
        type(data["episodes"]) is not list or len(data["episodes"])>MAX_FILES or
        type(data["pending"]) is not int or not 0<=data["pending"]<=MAX_FILES):
        raise ValueError("Invalid collector response")
    reports=data["episodes"]
    names=set()
    for report in reports:
        name=filename_for(report)
        if name in names: raise ValueError("Duplicate episode in collector response")
        names.add(name)
        encode(report)
    print(f"Validated complete episodes: {len(reports)}; incomplete episodes skipped: {data['pending']}")
    if args.dry_run:
        print("Dry-run only: no files published, no changes to Kubernetes.")
        return 0
    for report in reports:
        name,status=publish(args.output_dir,report)
        print(f"{status}: {name}")
    print("Published only approved numeric summaries. No raw evidence was exported.")
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"KubeGuard publication stopped: {type(exc).__name__}: {exc}",file=sys.stderr)
        raise SystemExit(1)
