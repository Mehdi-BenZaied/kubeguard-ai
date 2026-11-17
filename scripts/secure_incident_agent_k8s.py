#!/usr/bin/env python3
"""Secure publishing entrypoint for the existing validated incident state machine.

Preview remains the default. In explicit --send mode, notifications use a short-
lived HMAC signature and a Secret file. No credentials go to logs or SQLite.
"""
import hashlib
import hmac
import json
import time
from pathlib import Path
from urllib.request import Request, build_opener, ProxyHandler

import auto_incident_agent_k8s as core
import collect_live_training_data as telemetry

KEY_FILE = Path("/var/run/kubeguard-hmac/key")
SIGNING_PREFIX = b"kubeguard-alert-v1\n"


def signed_headers(body, key, *, now=None):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Invalid notification signing key")
    stamp = str(int(time.time() if now is None else now))
    digest = hmac.new(
        key, SIGNING_PREFIX + stamp.encode() + b"\n" + body, hashlib.sha256
    ).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-KubeGuard-Timestamp": stamp,
        "X-KubeGuard-Signature": "sha256=" + digest,
    }


def secure_send(payload):
    # Receiver URL is compiled into the validated agent and cannot be overridden
    # by incident content or an untrusted environment variable.
    key = KEY_FILE.read_bytes()
    body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()
    if len(body) > 8192:
        raise ValueError("Notification exceeds receiver size limit")
    req = Request(core.RECEIVER, body, headers=signed_headers(body, key), method="POST")
    opener = build_opener(ProxyHandler({}), telemetry.DenyRedirects())
    with opener.open(req, timeout=8) as response:
        if response.status != 200:
            raise RuntimeError("Receiver did not acknowledge event")
        response.read(512)


def main():
    # The existing state machine calls the module-global tick(). Redirect it to
    # the exact same implementation with only the transport overridden.
    original_tick = core.tick
    def secured_tick(epoch, state, state_file, send):
        return original_tick(epoch, state, state_file, send, publisher=secure_send)
    core.tick = secured_tick
    return core.main()


if __name__ == "__main__":
    raise SystemExit(main())
