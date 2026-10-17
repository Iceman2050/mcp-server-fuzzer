"""Malformed JSON-RPC payload generators for MCP server fuzzing.

Each case is a (name, description, payload_builder) triple. Payload builders
return the exact string to send; nothing is mocked -- these bytes go to the
real target over stdio or HTTP.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class FuzzCase:
    name: str
    description: str
    build: Callable[[], str]


def _nested(depth: int) -> list:
    node: list = []
    cur = node
    for _ in range(depth):
        child: list = []
        cur.append(child)
        cur = child
    cur.append("bottom")
    return node


CASES: list[FuzzCase] = [
    FuzzCase(
        "truncated-json",
        "JSON cut off mid-object (dropped connection / partial write)",
        lambda: '{"jsonrpc": "2.0", "method": "tools/list", "id": 1',
    ),
    FuzzCase(
        "not-json",
        "Plain text that is not JSON at all",
        lambda: "this is not json at all",
    ),
    FuzzCase(
        "empty-line",
        "Empty request line",
        lambda: "",
    ),
    FuzzCase(
        "wrong-id-type",
        "Request id is an object instead of string/number/null",
        lambda: json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": {"a": 1}}),
    ),
    FuzzCase(
        "unknown-method",
        "Method the server never implemented",
        lambda: json.dumps({"jsonrpc": "2.0", "method": "system/exfiltrate", "id": 7}),
    ),
    FuzzCase(
        "missing-method",
        "No 'method' member at all",
        lambda: json.dumps({"jsonrpc": "2.0", "id": 8, "params": {}}),
    ),
    FuzzCase(
        "missing-jsonrpc",
        "No 'jsonrpc' version member",
        lambda: json.dumps({"method": "tools/list", "id": 9}),
    ),
    FuzzCase(
        "wrong-version",
        "jsonrpc version is '1.0' instead of '2.0'",
        lambda: json.dumps({"jsonrpc": "1.0", "method": "tools/list", "id": 10}),
    ),
    FuzzCase(
        "params-wrong-type",
        "tools/call with params as a string instead of an object",
        lambda: json.dumps({
            "jsonrpc": "2.0", "method": "tools/call", "id": 11,
            "params": "this should have been an object",
        }),
    ),
    FuzzCase(
        "oversized-params",
        "tools/call with a 200KB string param (unbounded allocation probe)",
        lambda: json.dumps({
            "jsonrpc": "2.0", "method": "tools/call", "id": 12,
            "params": {"name": "expand", "arguments": {"data": "X" * 200_000}},
        }),
    ),
    FuzzCase(
        "nested-bomb",
        "tools/call with 500-deep nested arrays (recursion/timeout probe)",
        lambda: json.dumps({
            "jsonrpc": "2.0", "method": "tools/call", "id": 13,
            "params": {"name": "expand", "arguments": {"data": _nested(500)}},
        }),
    ),
    FuzzCase(
        "sleep-param",
        "tools/call asking the server to sleep 30s (missing timeout probe)",
        lambda: json.dumps({
            "jsonrpc": "2.0", "method": "tools/call", "id": 14,
            "params": {"name": "expand", "arguments": {"sleep_seconds": 30}},
        }),
    ),
    FuzzCase(
        "huge-array",
        "tools/call with a 50,000-element array param",
        lambda: json.dumps({
            "jsonrpc": "2.0", "method": "tools/call", "id": 15,
            "params": {"name": "expand", "arguments": {"data": list(range(50_000))}},
        }),
    ),
    FuzzCase(
        "batch-mixed",
        "JSON-RPC batch: one valid call plus one truncated entry",
        lambda: '[{"jsonrpc": "2.0", "method": "tools/list", "id": 16}, {"jsonrpc": "2.0", "meth',
    ),
]


def get_cases(names: list[str] | None = None) -> list[FuzzCase]:
    if names is None:
        return list(CASES)
    wanted = set(names)
    unknown = wanted - {c.name for c in CASES}
    if unknown:
        raise ValueError(f"unknown cases: {sorted(unknown)}")
    return [c for c in CASES if c.name in wanted]
