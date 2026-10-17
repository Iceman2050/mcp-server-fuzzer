"""INTENTIONALLY VULNERABLE dummy MCP server -- FOR TESTS ONLY.

It exists so the fuzzer has a real target with real bugs. Do NOT copy these
patterns into production code. Vulnerabilities baked in on purpose:
  1. Unknown/missing methods -> unhandled KeyError -> process CRASHES.
  2. Bad tool params -> error message embeds a fake stack trace AND an env var.
  3. Oversized string params -> unbounded multiplication -> MemoryError -> CRASH.
  4. Deeply nested / sleep params -> unbounded sleep -> HANG.
"""
from __future__ import annotations

import json
import os
import sys
import time


def _depth(node):
    # iterative on purpose: the vuln under test is the unbounded sleep below,
    # not the depth computation itself.
    best = 0
    stack = [(node, 0)]
    while stack:
        cur, d = stack.pop()
        best = max(best, d)
        if isinstance(cur, list):
            stack.extend((x, d + 1) for x in cur)
        elif isinstance(cur, dict):
            stack.extend((v, d + 1) for v in cur.values())
    return best


def handle_call(params):
    # VULN 2: no type check -- string params blow up and the error leaks internals.
    if not isinstance(params, dict):
        canary = os.environ.get("MCP_FUZZ_CANARY", "")
        return {
            "error": {
                "code": -32602,
                "message": (
                    "Traceback (most recent call last):\n"
                    '  File "dummy_server.py", line 42, in handle_call\n'
                    "ValueError: params must be an object, got "
                    + type(params).__name__
                    + f" [debug env MCP_FUZZ_CANARY={canary}]"
                ),
            }
        }
    args = params.get("arguments", {})
    if isinstance(args, dict):
        data = args.get("data")
        # VULN 3: unbounded allocation on attacker-controlled size.
        if isinstance(data, str) and len(data) > 100_000:
            _huge = data * 50_000_000  # noqa: F841 -> MemoryError, process dies
            return {"result": {"ok": True}}
        # VULN 4: no recursion or time budget on attacker-controlled input.
        if _depth(data) > 100:
            time.sleep(30)
            return {"result": {"ok": True}}
        if isinstance(args.get("sleep_seconds"), (int, float)):
            time.sleep(args["sleep_seconds"])
            return {"result": {"ok": True}}
        if isinstance(data, list):
            return {"result": {"count": len(data)}}
    return {"result": {"ok": True}}


def handle(msg):
    # VULN 1: direct dict access, no dispatch guard -- unknown/missing methods
    # raise KeyError and kill the process.
    method = msg["method"]
    if method == "initialize":
        return {"result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": "dummy"}}}
    if method == "tools/list":
        return {"result": {"tools": [{"name": "expand"}]}}
    if method == "tools/call":
        out = handle_call(msg.get("params"))
        return out
    return HANDLERS[method](msg)  # KeyError -> traceback -> exit(1)


HANDLERS = {}


def _respond(obj, req_id):
    if isinstance(obj, dict) and "id" not in obj:
        obj["id"] = req_id
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            _respond({"error": {"code": -32700, "message": "Parse error"}}, None)
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            _respond({"error": {"code": -32700, "message": "Parse error"}}, None)
            continue
        if isinstance(msg, list):
            # batch: answer each entry; a non-dict entry gets a parse error
            out = []
            for entry in msg:
                if not isinstance(entry, dict):
                    out.append({"error": {"code": -32700, "message": "Parse error"}, "id": None})
                    continue
                try:
                    out.append(handle(entry))
                except Exception:
                    raise  # VULN 1 also applies inside batches
            sys.stdout.write(json.dumps(out) + "\n")
            sys.stdout.flush()
            continue
        req_id = msg.get("id")
        try:
            _respond(handle(msg), req_id)
        except KeyError:
            raise  # VULN 1: unknown method kills the server


if __name__ == "__main__":
    main()
