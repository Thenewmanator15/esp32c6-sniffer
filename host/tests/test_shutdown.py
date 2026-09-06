"""The plugin must exit when the host goes away, even on a silent channel.

Wireshark stops a capture by closing the pipe, and the plugin learns of it by
failing to write. Everything in the capture loop was driven by packets
arriving, so on a busy channel it exited within milliseconds and on a quiet
one it never exited at all: no packet, no write, no failure, no exit --
and Wireshark hung on shutdown waiting for a child that was waiting for a
frame.

Reported against the 802.15.4 interface, which is where it shows, because its
default channel 11 carries a couple of frames a minute here while Wi-Fi and
BLE carry hundreds a second.

Measured on 802.15.4 channel 13, closing the read end exactly as Wireshark
does:

    before   still running 25 s later, 228 bytes written in 12 s
    after    exited 0.4 s later,      1064 bytes written in 12 s

The byte counts are the second half of the same fault: the statistics block
was written from inside the packet loop, so a quiet capture recorded no drop
counters at all.

These tests hold the shape of the fix. They cannot reproduce the hang, which
needs a board and a real pipe; the numbers above are that record.
"""

import ast
import pathlib

import pytest

PLUGIN = pathlib.Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


@pytest.fixture(scope="module")
def do_capture() -> ast.FunctionDef:
    tree = ast.parse(PLUGIN.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "do_capture":
            return node
    pytest.fail("do_capture not found")


def function_in(parent: ast.AST, name: str) -> ast.FunctionDef | None:
    for node in ast.walk(parent):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def calls(node: ast.AST, name: str) -> bool:
    for inner in ast.walk(node):
        if isinstance(inner, ast.Call):
            func = inner.func
            if isinstance(func, ast.Attribute) and func.attr == name:
                return True
            if isinstance(func, ast.Name) and func.id == name:
                return True
    return False


def test_there_is_a_heartbeat(do_capture):
    """The only thing that writes when no packets arrive, and therefore the
    only thing that can notice the pipe has closed."""
    heartbeat = function_in(do_capture, "heartbeat")
    assert heartbeat is not None, (
        "no heartbeat: on a silent channel nothing writes, so nothing "
        "discovers that Wireshark has gone")
    assert calls(heartbeat, "write_statistics")
    assert calls(heartbeat, "request_stop"), (
        "the heartbeat notices the closed pipe but does not wake the capture "
        "loop, which is blocked waiting for a frame")


def test_the_heartbeat_asks_to_see_the_write_failure(do_capture):
    """write_statistics swallows errors for its other callers. The heartbeat
    uses the failure as its liveness signal, so it must opt in -- otherwise it
    beats forever against a pipe nobody is reading."""
    heartbeat = function_in(do_capture, "heartbeat")
    source = ast.unparse(heartbeat)
    assert "reraise=True" in source


def test_the_toolbar_reader_also_wakes_the_capture(do_capture):
    """The second route to the same hang. Wireshark sends a quit on the
    control pipe, and setting a flag the capture loop only reads after a
    packet is not enough."""
    reader = function_in(do_capture, "reader")
    assert reader is not None
    assert calls(reader, "request_stop")


def test_writes_from_both_threads_are_serialised(do_capture):
    """Two threads writing pcapng blocks into one pipe interleave, and a file
    is unreadable from the point two blocks collide."""
    source = ast.unparse(do_capture)
    assert "write_lock" in source, "no lock guarding the shared pipe"
    heartbeat = function_in(do_capture, "heartbeat")
    assert "write_lock" in ast.unparse(heartbeat)


def test_statistics_are_not_written_only_from_the_packet_loop(do_capture):
    """Which is what left a quiet capture with no drop counters, so it could
    not be told apart later from a capture that dropped nothing."""
    heartbeat = function_in(do_capture, "heartbeat")
    assert calls(heartbeat, "write_statistics")
