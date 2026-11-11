"""Milestone 1: a small API with observable behaviour.

These endpoints deliberately simulate normal, slow and failed operations.
No Kubernetes, Machine Learning or remediation is implemented yet.
"""

import asyncio
from time import perf_counter

from fastapi import FastAPI, HTTPException, Query, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)

app = FastAPI(title="KubeGuard AI", version="0.1.0")

# Counter: total requests, separated by outcome.
REQUESTS = Counter(
    "kubeguard_requests_total",
    "Total number of simulated requests",
    ["outcome"],
)

# Histogram: observed request durations in seconds.
DURATION = Histogram(
    "kubeguard_request_duration_seconds",
    "Duration of simulated requests in seconds",
)


@app.get("/")
async def home():
    return {
        "project": "KubeGuard AI",
        "docs": "/docs",
        "health": "/health",
        "metrics": "/metrics",
    }


@app.get("/health")
async def health():
    """A simple check that the HTTP service is responding."""
    return {"status": "ok"}


@app.get("/work")
async def work(
    delay_ms: int = Query(default=50, ge=0, le=2000),
    fail: bool = False,
):
    """Run a safe, simulated workload with optional latency or failure."""
    started = perf_counter()
    outcome = "error" if fail else "success"

    try:
        await asyncio.sleep(delay_ms / 1000)
        if fail:
            raise HTTPException(status_code=503, detail="Simulated incident")
        return {"message": "OK", "delay_ms": delay_ms}
    finally:
        # 'finally' executes for both successful and failed requests.
        REQUESTS.labels(outcome=outcome).inc()
        DURATION.observe(perf_counter() - started)


@app.get("/metrics")
async def metrics():
    """Expose metrics in the Prometheus text format."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
