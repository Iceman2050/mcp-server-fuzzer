"""Transports: send one JSON-RPC payload string, get back one raw response string.

StdioTransport spawns the target as a subprocess per payload (so a crash is
attributable to exactly one case). HttpTransport POSTs to an HTTP endpoint
(for MCP servers exposing SSE/HTTP). Both are real I/O -- no mocks.
"""
from __future__ import annotations

import shlex
import subprocess
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass


@dataclass
class SendResult:
    raw: str | None          # response text, None if no response arrived
    crashed: bool = False   # process died / connection refused / HTTP 5xx
    timed_out: bool = False # no response within timeout
    detail: str = ""        # human-readable, deterministic


class StdioTransport:
    """Newline-delimited JSON-RPC over a subprocess's stdin/stdout."""

    def __init__(self, command: str, timeout: float = 3.0, env: dict | None = None) -> None:
        self.argv = shlex.split(command)
        self.timeout = timeout
        self.env = env

    def send(self, payload: str) -> SendResult:
        try:
            proc = subprocess.Popen(
                self.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                env=self.env,
            )
        except (OSError, FileNotFoundError) as exc:
            return SendResult(None, crashed=True, detail=f"could not spawn target: {exc}")

        try:
            assert proc.stdin is not None and proc.stdout is not None
            proc.stdin.write(payload + "\n")
            proc.stdin.flush()
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(proc.stdout.readline)
                try:
                    line = future.result(timeout=self.timeout)
                except FuturesTimeout:
                    proc.kill()
                    proc.wait()
                    return SendResult(
                        None, timed_out=True,
                        detail=f"no response within {self.timeout:.1f}s; process killed",
                    )
            proc.terminate()
            try:
                rc = proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                rc = proc.wait()
            if not line:
                return SendResult(
                    None, crashed=True,
                    detail=f"no response; process exited (code {rc})",
                )
            return SendResult(line.strip(), detail="response received")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


class HttpTransport:
    """POST the payload to an HTTP JSON-RPC endpoint (MCP SSE/HTTP servers)."""

    def __init__(self, url: str, timeout: float = 3.0) -> None:
        self.url = url
        self.timeout = timeout

    def send(self, payload: str) -> SendResult:
        req = urllib.request.Request(
            self.url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                if resp.status >= 500:
                    return SendResult(
                        body or None, crashed=True,
                        detail=f"HTTP {resp.status} from target",
                    )
                return SendResult(body, detail=f"HTTP {resp.status}")
        except urllib.error.HTTPError as exc:
            code = exc.code or 0
            crashed = code >= 500
            return SendResult(
                None, crashed=crashed,
                detail=f"HTTP {code} from target",
            )
        except urllib.error.URLError as exc:
            return SendResult(None, crashed=True, detail=f"connection failed: {exc.reason}")
        except TimeoutError:
            return SendResult(
                None, timed_out=True,
                detail=f"no response within {self.timeout:.1f}s",
            )
        except OSError as exc:
            return SendResult(None, crashed=True, detail=f"connection failed: {exc}")
