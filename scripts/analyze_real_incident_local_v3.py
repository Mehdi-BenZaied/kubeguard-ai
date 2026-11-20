#!/usr/bin/env python3
"""KubeGuard AI M7 v3 — bounded local AI investigation.

Run on Windows from scripts/ after installing the v2 analyzer beside it.
The LLM may select only known read-only check IDs; Python owns every
observation, unknown, and unverified hypothesis. No Kubernetes access,
external service, secrets, arbitrary model text in reports, or remediation.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, ProxyHandler, build_opener

import analyze_real_incident_local_v2 as v2

MODEL = v2.MODEL
OLLAMA = v2.OLLAMA

# No commands, credentials, pod names, raw logs or mutable operations in these
# catalog entries. Model text is never copied into the stored report.
CHECKS = {
    "confirm_test_delay": (
        "Compare the controlled traffic generator's scenario and timing with the incident; "
        "verify whether an artificial application delay was intentionally enabled."
    ),
    "review_latency": (
        "Compare the approved average and p95 latency time series with a baseline; "
        "inspect histogram buckets and query window semantics."
    ),
    "review_dependency": (
        "As an operator, review already-approved read-only application/dependency latency "
        "metrics, if available; do not export raw logs or sensitive request data."
    ),
    "review_request_rate": (
        "Compare request-rate samples against known traffic-generator settings and baseline "
        "capacity; these aggregate rates cannot prove saturation."
    ),
    "review_restarts": (
        "Inspect read-only container restart deltas and recorded restart reasons/timestamps "
        "through operator-approved monitoring; the cumulative count alone is not an incident cause."
    ),
    "review_cpu": (
        "Compare CPU millicores and throttling against configured CPU limits and higher-" 
        "resolution monitoring; a few millicores do not establish CPU pressure."
    ),
    "review_error_gap": (
        "Inspect the error-rate PromQL and instrumentation using read-only monitoring; "
        "missing error-rate samples do not establish zero errors."
    ),
}

# This catalog is explicitly NOT a root cause determination. Each entry names
# a falsifiable possibility and the evidence needed to evaluate it.
HYPOTHESES = [
    "UNVERIFIED HYPOTHESIS — The controlled experiment may have added deliberate "
    "application delay. Required evidence: experiment scenario and delay implementation.",
    "UNVERIFIED HYPOTHESIS — A request handler or downstream dependency may "
    "have waited. Required evidence: approved per-operation or dependency timing metrics.",
    "UNVERIFIED HYPOTHESIS — Histogram/query-window semantics may partly affect "
    "reported latency percentiles. Required evidence: histogram configuration and query definitions.",
]


def permitted_checks(evidence: dict) -> dict[str, str]:
    gaps = set().union(*(set(stage["evidence_gaps"]) for stage in evidence["evidence"]))
    options = dict(CHECKS)
    if not any(g.endswith("error_rate_pct") for g in gaps):
        options.pop("review_error_gap")
    return options


def validate_ids(payload, options: dict[str, str]) -> list[str]:
    """Reject extra fields, model-provided prose, duplicates and unknown actions."""
    v2.check(type(payload) is dict and set(payload) == {"check_ids"},
             "Model response must contain only check_ids")
    chosen = payload["check_ids"]
    v2.check(type(chosen) is list and 1 <= len(chosen) <= 4,
             "Model must select 1 to 4 checks")
    v2.check(all(type(x) is str and x in options for x in chosen),
             "Model returned unapproved check ID")
    v2.check(len(chosen) == len(set(chosen)), "Model repeated a check")
    return chosen


def call_model_for_check_ids(evidence: dict, options: dict[str, str]) -> list[str]:
    prompt = (
        "You are a read-only Kubernetes incident TRIAGE RANKER, NOT a diagnosis model. "
        "Choose between one and four useful check IDs from the allowlist. "
        "Do not write explanations, commands, observations, hypotheses, or text. "
        "Only return JSON with exactly one key, check_ids, containing an array of "
        "unique allowlisted IDs. Missing data is unknown, not zero. Two cumulative "
        "restarts do not imply crashes during the incident. A few CPU millicores "
        "do not imply CPU contention. Low aggregate request rates do not prove "
        "overload. No raw logs, secrets, cluster modification, or remediation."
    )
    compact = {
        "incident_type": evidence["incident_type"],
        "phases": evidence["evidence"],
        "available_check_ids": list(options),
    }
    request = {
        "model": MODEL,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0, "num_predict": 160},
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(compact, separators=(",", ":"), allow_nan=False)},
        ],
    }
    req = Request(
        OLLAMA,
        data=json.dumps(request, allow_nan=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with build_opener(ProxyHandler({}), v2.RejectRedirects()).open(req, timeout=180) as resp:
            v2.check(resp.status == 200, "Ollama response not successful")
            raw = resp.read(32769)
    except URLError as exc:
        raise RuntimeError(
            "Local Ollama not reachable. Check http://127.0.0.1:11434/api/version "
            "and start the local Ollama server."
        ) from exc
    v2.check(len(raw) <= 32768, "Ollama response too large")
    body = v2.parse_json_no_duplicates(raw)
    v2.check(type(body) is dict and type(body.get("message")) is dict,
             "Invalid Ollama response envelope")
    content = body["message"].get("content")
    v2.check(type(content) is str and len(content) <= 2048,
             "Invalid Ollama response content")
    return validate_ids(v2.parse_json_no_duplicates(content), options)


def build_report(evidence: dict, selected: list[str]) -> dict:
    options = permitted_checks(evidence)
    selected = validate_ids({"check_ids": selected}, options)
    checks = [options[k] for k in selected]
    # Do not allow the model to suppress investigation of a measured data gap.
    if "review_error_gap" in options and "review_error_gap" not in selected:
        checks.append(options["review_error_gap"])
    return {
        "schema_version": 3,
        "source_incident_start_utc": evidence["episode_start_utc"],
        "model": MODEL,
        "status": "Triage suggestions require human review; no confirmed root cause",
        "analysis": {
            "observations": v2.deterministic_observations(evidence),
            "possible_causes": list(HYPOTHESES),
            "unknowns": v2.deterministic_unknowns(evidence),
            "read_only_checks": checks,
        },
        "model_selected_check_ids": selected,
    }


def save_report(folder: Path, report: dict) -> Path:
    path = folder / "m7_ai_investigation_v3.json"
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=folder,
                                     prefix=".m7-v3-", suffix=".tmp", delete=False) as f:
        temp = Path(f.name)
        try:
            json.dump(report, f, indent=2, ensure_ascii=False, allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            temp.unlink(missing_ok=True)
            raise
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    return path


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--validate-only", action="store_true")
    args = cli.parse_args()
    path = v2.evidence_file()
    evidence = v2.validate_evidence(v2.parse_json_no_duplicates(path.read_bytes()))
    print("Evidence validated: schema 1; firing + resolved; 10 approved metrics per phase.")
    print("Evidence gaps:", ", ".join(sorted(set().union(
        *(set(e["evidence_gaps"]) for e in evidence["evidence"])))) or "none")
    if args.validate_only:
        print("Validation-only: no Ollama call or report written.")
        return 0
    options = permitted_checks(evidence)
    selected = call_model_for_check_ids(evidence, options)
    report = build_report(evidence, selected)
    output = save_report(path.parent, report)
    print(json.dumps(report["analysis"], indent=2, ensure_ascii=False))
    print("Private report:", output)
    print("Only known investigation checks were selected; no cluster actions executed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        raise SystemExit(f"KubeGuard v3 failed closed: {type(exc).__name__}: {exc}")
