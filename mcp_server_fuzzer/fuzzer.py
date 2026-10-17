"""Verdict classification and the fuzz-run orchestrator.

Verdicts:
  CRASH     - target died / refused connection / HTTP 5xx with no usable reply
  HANG      - no response within the timeout
  INFO-LEAK - response arrived but contains stack traces, paths, or secret-ish markers
  OK        - well-formed JSON-RPC response (including proper error objects)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .cases import FuzzCase, get_cases
from .transports import HttpTransport, SendResult, StdioTransport

LEAK_MARKERS = [
    "Traceback (most recent call last)",
    'File "',
    "os.environ",
    "/etc/passwd",
    "/home/",
    "/root/",
    "password",
    "secret",
    "api_key",
    "BEGIN PRIVATE KEY",
]


def classify(result: SendResult) -> tuple[str, str]:
    """Map a transport result to (verdict, deterministic detail string)."""
    if result.timed_out:
        return "HANG", result.detail
    if result.crashed or result.raw is None:
        return "CRASH", result.detail
    raw = result.raw
    lowered = raw.lower()
    hits = [m for m in LEAK_MARKERS if m.lower() in lowered]
    if hits:
        return "INFO-LEAK", f"leak markers in response: {', '.join(hits)}"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return "CRASH", "response was not valid JSON"
    if isinstance(parsed, dict) and "error" in parsed:
        return "OK", "valid JSON-RPC error response"
    if isinstance(parsed, (dict, list)):
        return "OK", "valid JSON-RPC response"
    return "CRASH", "response was not a JSON-RPC object"


@dataclass
class CaseOutcome:
    case: str
    verdict: str
    detail: str


@dataclass
class FuzzReport:
    target: str
    outcomes: list[CaseOutcome] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        counts = {"OK": 0, "CRASH": 0, "HANG": 0, "INFO-LEAK": 0}
        for o in self.outcomes:
            counts[o.verdict] += 1
        return counts

    def table(self) -> str:
        lines = [
            "mcp-server-fuzzer report",
            f"target: {self.target}",
            "=" * 70,
            f"{'CASE':<18}{'VERDICT':<10}DETAIL",
            "-" * 70,
        ]
        for o in self.outcomes:
            lines.append(f"{o.case:<18}{o.verdict:<10}{o.detail}")
        lines.append("=" * 70)
        c = self.counts()
        lines.append(
            f"OK={c['OK']} CRASH={c['CRASH']} HANG={c['HANG']} "
            f"INFO-LEAK={c['INFO-LEAK']} total={len(self.outcomes)}"
        )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "counts": self.counts(),
            "outcomes": [
                {"case": o.case, "verdict": o.verdict, "detail": o.detail}
                for o in self.outcomes
            ],
        }


def run_fuzz(
    transport: StdioTransport | HttpTransport,
    target_label: str,
    cases: list[FuzzCase] | None = None,
) -> FuzzReport:
    report = FuzzReport(target=target_label)
    for case in cases or get_cases():
        payload = case.build()
        result = transport.send(payload)
        verdict, detail = classify(result)
        report.outcomes.append(CaseOutcome(case.name, verdict, detail))
    return report


def make_transport(spec: str, timeout: float):
    """spec: 'stdio:<command>' or 'http:<url>'"""
    if spec.startswith("stdio:"):
        return StdioTransport(spec[len("stdio:"):], timeout), f"stdio: {spec[len('stdio:'):]}"
    if spec.startswith("http:"):
        url = spec[len("http:"):]
        return HttpTransport(url, timeout), f"http: {url}"
    raise ValueError("target spec must start with 'stdio:' or 'http:'")
