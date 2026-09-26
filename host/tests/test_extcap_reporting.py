"""What the plugin tells the person watching, and how often."""

import ast
import importlib.util
import pathlib

import pytest

from esp32c6_sniffer.capture import CaptureStats

PLUGIN = pathlib.Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


@pytest.fixture(scope="module")
def plugin():
    spec = importlib.util.spec_from_file_location("extcap_plugin_reporting", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_no_warning_while_nothing_is_lost(plugin):
    warning = plugin.LossWarning()
    assert warning.due(0, now=0.0) == 0


def test_one_loss_is_warned_about_once(plugin):
    """The warning was raised every second once anything had been lost -- a
    Wireshark dialog a second, for a loss long over."""
    warning = plugin.LossWarning()
    assert warning.due(3, now=0.0) == 3
    assert [warning.due(3, now=t) for t in range(1, 300)] == [0] * 299


def test_new_loss_is_warned_about_with_how_much(plugin):
    warning = plugin.LossWarning()
    warning.due(3, now=0.0)
    assert warning.due(10, now=120.0) == 7


def test_loss_that_keeps_coming_is_warned_about_once_a_minute(plugin):
    warning = plugin.LossWarning()
    due = [warning.due(n, now=float(n)) for n in range(1, 122)]
    assert [n for n in due if n] == [1, 60, 60]


def test_commands_the_board_missed_are_reported(plugin):
    """A retune or antenna switch with no answer leaves the capture where it
    was. The log line's channel says so; this says why."""
    assert plugin.command_note(CaptureStats()) == ""
    assert plugin.command_note(CaptureStats(commands_unanswered=1)) == (
        ", 1 command unanswered")
    assert plugin.command_note(CaptureStats(commands_unanswered=2,
                                            commands_refused=1)) == (
        ", 2 commands unanswered, 1 refused")
    assert plugin.command_note(CaptureStats(commands_refused=1)) == (
        ", 1 command refused")


def test_check_keys_says_when_it_could_not_finish():
    """Otherwise a check the board did not follow ends with no result and no
    word about why."""
    tree = ast.parse(PLUGIN.read_text(encoding="utf-8"))
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute)
             and node.func.attr == "request_key_check"]
    assert calls
    assert all(any(k.arg == "on_failed" for k in call.keywords) for call in calls)


def test_the_log_says_no_loss_when_there_was_none(plugin):
    assert plugin.loss_summary(CaptureStats()) == "no loss"


def test_the_log_counts_lost_packets_once_with_the_counters_beside(plugin):
    s = CaptureStats(sequence_gaps=1, fw_link_rejected=1,
                     fw_frames_dropped_ringfull=1)
    assert plugin.loss_summary(s) == (
        "LOSS 1 packet (gaps=1 isr=0 link=1 ring=1)")


def test_a_refused_report_is_not_called_packet_loss(plugin):
    """A STATS or LOG frame the board's ring refused: the line read "LOSS 0
    packets", which says loss and then says none."""
    s = CaptureStats(sequence_gaps=1, fw_frames_dropped_ringfull=1)
    assert plugin.loss_summary(s) == (
        "no packets lost; 1 of the board's own frames not sent "
        "(gaps=1 isr=0 link=0 ring=1)")
