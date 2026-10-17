# mcp-server-fuzzer

**You ship an MCP server. One malformed JSON-RPC message crashes it, hangs it, or makes it print a stack trace with your internals.**

MCP servers sit on an open protocol boundary and parse attacker-shaped input all day. This tool fires 14 malformed JSON-RPC payloads — truncated JSON, wrong types, oversized params, unknown methods, nested bombs — at any MCP server over stdio or HTTP, and catalogs every case as **CRASH**, **HANG**, **INFO-LEAK**, or **OK** with a summary table. Thirty seconds, zero dependencies.

## Quickstart

```bash
# zero dependencies, Python 3.9+
git clone https://github.com/Iceman2050/mcp-server-fuzzer
cd mcp-server-fuzzer

# fuzz a server over stdio (spawns: python my_server.py)
python -m mcp_server_fuzzer --target "stdio:python3 my_server.py"

# fuzz a server over HTTP (MCP SSE/HTTP endpoint)
python -m mcp_server_fuzzer --target "http:http://localhost:8000/messages"

# options
python -m mcp_server_fuzzer --target "stdio:python3 my_server.py" --timeout 5.0 --format json
python -m mcp_server_fuzzer --target "stdio:python3 my_server.py" --case nested-bomb --case unknown-method
python -m mcp_server_fuzzer --list-cases

# run the test suite (spins up the bundled vulnerable dummy server)
python -m unittest discover -s tests
```

Try it instantly against the bundled intentionally-vulnerable dummy server:

```bash
python -m mcp_server_fuzzer --target "stdio:python3 tests/dummy_server.py" --timeout 2.0
```

## Example output

Machine-verified byte-for-byte against a fresh run of the command above (exit code 2 = crashes/hangs found):

```
mcp-server-fuzzer report
target: stdio: python3 tests/dummy_server.py
======================================================================
CASE              VERDICT   DETAIL
----------------------------------------------------------------------
truncated-json    OK        valid JSON-RPC error response
not-json          OK        valid JSON-RPC error response
empty-line        OK        valid JSON-RPC error response
wrong-id-type     OK        valid JSON-RPC response
unknown-method    CRASH     no response; process exited (code 1)
missing-method    CRASH     no response; process exited (code 1)
missing-jsonrpc   OK        valid JSON-RPC response
wrong-version     OK        valid JSON-RPC response
params-wrong-type INFO-LEAK leak markers in response: Traceback (most recent call last)
oversized-params  CRASH     no response; process exited (code 1)
nested-bomb       HANG      no response within 2.0s; process killed
sleep-param       HANG      no response within 2.0s; process killed
huge-array        OK        valid JSON-RPC response
batch-mixed       OK        valid JSON-RPC error response
======================================================================
OK=8 CRASH=3 HANG=2 INFO-LEAK=1 total=14
```

## How it works

1. **Fuzz cases** (`cases.py`) — 14 payload builders covering the classic malformed-input classes: truncated/non-JSON input, wrong id/method/param types, missing members, oversized params, deeply nested structures, batch mixtures.
2. **Transports** (`transports.py`) — real I/O only. Stdio spawns a fresh target process per case (so a crash is attributable to exactly one payload); HTTP POSTs to an SSE/HTTP endpoint. Per-case timeouts; hung targets are killed.
3. **Verdict classification** (`fuzzer.py`) — `CRASH` (died / refused / 5xx), `HANG` (timeout), `INFO-LEAK` (response contains stack traces, file paths, or secret-ish markers), `OK` (well-formed JSON-RPC response, including proper error objects). Table or JSON output.
4. **Dummy target** (`tests/dummy_server.py`) — an intentionally vulnerable MCP server with four baked-in bugs (unguarded method dispatch, traceback-leaking error path, unbounded allocation, unbounded sleep) so the demo and test suite run against a real target.

## Ethical use

This is a defensive testing tool. Fuzz only **your own servers** or targets you have explicit permission to test. Do not point it at third-party services.

## What it does NOT do

- It does **not** test MCP transports beyond stdio and plain HTTP POST (no WebSocket, no full SSE session handshake).
- It does **not** do protocol-aware attacks (it won't complete `initialize` handshakes, negotiate capabilities, or chain tool calls) — it's a malformed-input fuzzer, not a logic fuzzer.
- It does **not** prove a server is secure — 14/14 OK means it survived these 14 payloads, nothing more.
- INFO-LEAK detection is marker-based (stack traces, paths, secret-ish words), not semantic — a clever leak without markers won't be flagged.

## Built by Ingenious AI
- DisclosureGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DisclosureGuard.
- ModelMinder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ModelMinder.
- TermsWatch — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20TermsWatch.
- Vibe-Code Audit — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.
- Rogue-Agent Defense — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.
- BreachHunter — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20BreachHunter.
- ChatBreaker — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ChatBreaker.
- Agent Flight Recorder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.
- Agent Auth Gateway — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.
- DomainGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DomainGuard.
- ContentCraft AI — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ContentCraft%20AI.
Built with Muse — try it free: invite code 2HCQH1

## License

MIT — see [LICENSE](LICENSE).
