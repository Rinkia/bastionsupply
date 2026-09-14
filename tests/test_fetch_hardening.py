"""C4: fetch_stdio must not hang or OOM on a hostile/broken server."""

import time

import pytest

from bastionsupply import fetch


class _BlockingStdout:
    def readline(self, size=-1):
        time.sleep(30)  # never returns within the test's timeout
        return ""


class _HugeStdout:
    def __init__(self, chunk):
        self.chunk = chunk

    def readline(self, size=-1):
        return self.chunk  # a giant line with no newline, forever


class _FakeProc:
    def __init__(self, stdout):
        self.stdout = stdout


def test_read_result_times_out_on_silent_server():
    start = time.time()
    with pytest.raises(TimeoutError):
        fetch._read_result(_FakeProc(_BlockingStdout()), 1, timeout=0.2)
    assert time.time() - start < 5  # returned promptly, did not hang


def test_read_loop_rejects_oversized_line(monkeypatch):
    monkeypatch.setattr(fetch, "MAX_LINE", 100)
    proc = _FakeProc(_HugeStdout("x" * 100))  # len >= MAX_LINE, no newline
    with pytest.raises(RuntimeError, match="oversized"):
        fetch._read_loop(proc, 1, timeout=5)


def test_read_loop_closed_connection():
    proc = _FakeProc(type("S", (), {"readline": lambda self, size=-1: ""})())
    with pytest.raises(RuntimeError, match="closed the connection"):
        fetch._read_loop(proc, 1, timeout=5)


def test_read_loop_returns_matching_result():
    lines = iter(['{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n'])
    proc = _FakeProc(type("S", (), {"readline": lambda self, size=-1: next(lines, "")})())
    assert fetch._read_loop(proc, 1, timeout=5) == {"tools": []}
