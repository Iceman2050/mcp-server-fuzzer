"""Tests for mcp-server-fuzzer. Run: python -m unittest discover -s tests -v

Spawns the intentionally-vulnerable dummy MCP server as a real subprocess --
no mocks of the transport or the target.
"""
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_server_fuzzer import (
    CASES,
    HttpTransport,
    StdioTransport,
    classify,
    get_cases,
    make_transport,
    run_fuzz,
)
from mcp_server_fuzzer.transports import SendResult

DUMMY = str(Path(__file__).resolve().parent / "dummy_server.py")
STDIO_CMD = f"{sys.executable} {DUMMY}"


class TestCases(unittest.TestCase):
    def test_all_cases_build_strings(self):
        self.assertGreaterEqual(len(CASES), 10)
        for case in CASES:
            payload = case.build()
            self.assertIsInstance(payload, str, case.name)

    def test_case_names_unique(self):
        names = [c.name for c in CASES]
        self.assertEqual(len(names), len(set(names)))

    def test_get_cases_subset(self):
        subset = get_cases(["not-json", "unknown-method"])
        self.assertEqual([c.name for c in subset], ["not-json", "unknown-method"])

    def test_get_cases_unknown_raises(self):
        with self.assertRaises(ValueError):
            get_cases(["nope"])


class TestClassify(unittest.TestCase):
    def test_hang(self):
        v, d = classify(SendResult(None, timed_out=True, detail="no response within 3.0s"))
        self.assertEqual(v, "HANG")

    def test_crash_no_response(self):
        v, _ = classify(SendResult(None, crashed=True, detail="no response; process exited (code 1)"))
        self.assertEqual(v, "CRASH")

    def test_info_leak_traceback(self):
        raw = json.dumps({"error": {"message": "Traceback (most recent call last): boom"}})
        v, d = classify(SendResult(raw))
        self.assertEqual(v, "INFO-LEAK")
        self.assertIn("Traceback (most recent call last)", d)

    def test_ok_result(self):
        v, _ = classify(SendResult(json.dumps({"result": {}, "id": 1})))
        self.assertEqual(v, "OK")

    def test_ok_error_object(self):
        v, d = classify(SendResult(json.dumps({"error": {"code": -32700, "message": "Parse error"}})))
        self.assertEqual(v, "OK")
        self.assertIn("error", d)

    def test_non_json_response_is_crash(self):
        v, _ = classify(SendResult("definitely not json {{{"))
        self.assertEqual(v, "CRASH")


class TestStdioAgainstDummy(unittest.TestCase):
    def setUp(self):
        self.env = dict(os.environ)
        self.env["MCP_FUZZ_CANARY"] = "canary-" + os.urandom(4).hex()

    def _send(self, payload, timeout=3.0):
        env = dict(os.environ)
        env["MCP_FUZZ_CANARY"] = self.env["MCP_FUZZ_CANARY"]
        t = StdioTransport(f"{sys.executable} {DUMMY}", timeout=timeout, env=env)
        return t.send(payload)

    def test_unknown_method_crashes_dummy(self):
        payload = json.dumps({"jsonrpc": "2.0", "method": "system/exfiltrate", "id": 7})
        result = self._send(payload)
        verdict, _ = classify(result)
        self.assertEqual(verdict, "CRASH")

    def test_bad_params_leak_traceback_and_canary(self):
        payload = json.dumps({
            "jsonrpc": "2.0", "method": "tools/call", "id": 11,
            "params": "should have been an object",
        })
        result = self._send(payload)
        verdict, _ = classify(result)
        self.assertEqual(verdict, "INFO-LEAK")
        self.assertIn(self.env["MCP_FUZZ_CANARY"], result.raw or "")

    def test_valid_call_is_ok(self):
        payload = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1})
        result = self._send(payload)
        verdict, _ = classify(result)
        self.assertEqual(verdict, "OK")

    def test_sleep_param_hangs(self):
        payload = json.dumps({
            "jsonrpc": "2.0", "method": "tools/call", "id": 14,
            "params": {"name": "expand", "arguments": {"sleep_seconds": 30}},
        })
        result = self._send(payload, timeout=1.0)
        verdict, _ = classify(result)
        self.assertEqual(verdict, "HANG")


class TestHttpTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                if self.path == "/boom":
                    self.send_response(500)
                    self.end_headers()
                elif self.path == "/leak":
                    body = b'{"error": {"message": "Traceback (most recent call last)"}}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    body = b'{"result": {}, "id": 1}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *a):
                pass

        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_http_ok(self):
        t = HttpTransport(f"http://127.0.0.1:{self.port}/rpc", timeout=3.0)
        verdict, _ = classify(t.send('{"jsonrpc":"2.0","method":"tools/list","id":1}'))
        self.assertEqual(verdict, "OK")

    def test_http_500_is_crash(self):
        t = HttpTransport(f"http://127.0.0.1:{self.port}/boom", timeout=3.0)
        verdict, _ = classify(t.send('{"jsonrpc":"2.0","method":"tools/list","id":1}'))
        self.assertEqual(verdict, "CRASH")

    def test_http_leak_body_is_info_leak(self):
        t = HttpTransport(f"http://127.0.0.1:{self.port}/leak", timeout=3.0)
        verdict, _ = classify(t.send('{"jsonrpc":"2.0","method":"tools/list","id":1}'))
        self.assertEqual(verdict, "INFO-LEAK")

    def test_connection_refused_is_crash(self):
        t = HttpTransport("http://127.0.0.1:1/rpc", timeout=2.0)
        verdict, detail = classify(t.send('{}'))
        self.assertEqual(verdict, "CRASH")


class TestMakeTransport(unittest.TestCase):
    def test_stdio_spec(self):
        t, label = make_transport("stdio:echo hi", 1.0)
        self.assertIsInstance(t, StdioTransport)
        self.assertTrue(label.startswith("stdio:"))

    def test_http_spec(self):
        t, label = make_transport("http:http://x/y", 1.0)
        self.assertIsInstance(t, HttpTransport)

    def test_bad_spec_raises(self):
        with self.assertRaises(ValueError):
            make_transport("grpc://x", 1.0)


class TestFullRun(unittest.TestCase):
    def test_report_covers_all_cases_and_counts(self):
        env = dict(os.environ)
        env["MCP_FUZZ_CANARY"] = "fullrun-canary"
        transport = StdioTransport(f"{sys.executable} {DUMMY}", timeout=2.0, env=env)
        label = f"stdio: {sys.executable} {DUMMY}"
        report = run_fuzz(transport, label)
        self.assertEqual(len(report.outcomes), len(CASES))
        counts = report.counts()
        self.assertGreaterEqual(counts["CRASH"], 1)
        self.assertGreaterEqual(counts["HANG"], 1)
        self.assertGreaterEqual(counts["INFO-LEAK"], 1)
        self.assertGreaterEqual(counts["OK"], 1)
        table = report.table()
        self.assertIn("mcp-server-fuzzer report", table)
        self.assertIn("total=", table)


if __name__ == "__main__":
    unittest.main()
