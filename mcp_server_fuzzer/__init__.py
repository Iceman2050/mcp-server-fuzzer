"""mcp-server-fuzzer: hammer MCP servers with malformed JSON-RPC and catalog the damage."""
from .fuzzer import run_fuzz, make_transport, classify, FuzzReport, LEAK_MARKERS
from .cases import CASES, get_cases
from .transports import StdioTransport, HttpTransport

__all__ = [
    "run_fuzz", "make_transport", "classify", "FuzzReport", "LEAK_MARKERS",
    "CASES", "get_cases", "StdioTransport", "HttpTransport",
]

__version__ = "1.0.0"
