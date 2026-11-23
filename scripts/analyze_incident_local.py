
import json
from urllib.request import Request, build_opener, ProxyHandler

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
MODEL = "qwen3:4b-instruct"

# Synthetic evidence only — no Kubernetes access.
evidence = {
    "incident": "High application latency",
    "available_replicas": 1,
    "running_pods": 1,
    "avg_latency_seconds": 1.2,
    "container_restarts_total": 2,
    "error_rate_pct": None,
}

system_prompt = """
You are KubeGuard AI, a read-only SRE investigation assistant.

Rules:
- Use only the supplied evidence.
- Never invent metrics or claim a confirmed root cause.
- Missing metrics mean unknown, not zero.
- Container restart totals are cumulative.
- Available replicas do not prove external reachability.
- Suggest read-only investigation steps only.
- Do not propose automatic remediation.

Return a JSON object with these fields:
observations, possible_causes, unknowns, read_only_checks.
Each field must contain a list of strings.
"""

payload = {
    "model": MODEL,
    "stream": False,
    "format": "json",
    "options": {"temperature": 0.1},
    "messages": [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": json.dumps(evidence)
        }
    ]
}

request = Request(
    OLLAMA_URL,
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)

# Disable environment proxy settings.
opener = build_opener(ProxyHandler({}))

print("Running local KubeGuard AI investigation...")

with opener.open(request, timeout=120) as response:
    result = json.load(response)

analysis = json.loads(result["message"]["content"])

required = {
    "observations",
    "possible_causes",
    "unknowns",
    "read_only_checks",
}

if not required.issubset(analysis):
    raise ValueError("AI response missing required fields")

for key in required:
    if not isinstance(analysis[key], list) or not all(
        isinstance(item, str) for item in analysis[key]
    ):
        raise ValueError(f"Invalid AI response field: {key}")

print(json.dumps(analysis, indent=2))
print("\nSynthetic test completed. No cluster actions performed.")
