"""Asking for control frames must actually deliver control frames.

The Wi-Fi frame-type option offers "Everything, including control". It
delivered no control frames at all. The board's control-subtype filter was
left at the driver's default, which passes none of them, and the only thing
that ever set it was the *Drop acknowledgements* option.

So the option meant to ADD frames worked only in combination with the option
meant to REMOVE some, and on its own did nothing. Measured through the plugin,
exactly as Wireshark runs it:

    --filter 15                  0 control frames   (before)
    --filter 15 --drop-acks     15 control frames   (before)

    --filter 15                 81 control, 36 ACK  (after)
    --filter 15 --drop-acks     36 control,  0 ACK  (after)
    --filter 5                   0 control          (after)
"""

from esp32c6_sniffer.capture import CaptureSession
from esp32c6_sniffer.control import Command, CtrlFilter, FrameFilter, Radio


def configured(**kwargs):
    """Records the commands _configure would send, without a board.

    _configure is called directly, so nothing opens a port. Everything it
    needs is set in the constructor.
    """
    session = CaptureSession("COM_UNUSED", channel=6, radio=Radio.WIFI,
                             **kwargs)
    sent = []

    def fake_command(command, value=0, **_kw):
        sent.append((command, value))
        return {"command": command, "ok": True, "status": 0, "value": 0}

    session._command = fake_command
    session._configure()
    return dict(sent)


def test_asking_for_control_frames_enables_every_subtype():
    sent = configured(frame_filter=FrameFilter.ALL)
    assert Command.SET_CTRL_FILTER in sent, (
        "no control-subtype filter was sent, so the driver default applies "
        "and it passes none of them"
    )
    assert sent[Command.SET_CTRL_FILTER] == int(CtrlFilter.ALL)


def test_an_explicit_choice_is_not_overridden():
    """Dropping acknowledgements must still drop them."""
    sent = configured(frame_filter=FrameFilter.ALL,
                      ctrl_filter=CtrlFilter.NO_ACK)
    assert sent[Command.SET_CTRL_FILTER] == int(CtrlFilter.NO_ACK)
    assert not int(CtrlFilter.NO_ACK) & int(CtrlFilter.ACK)


def test_not_asking_for_control_frames_sends_no_subtype_filter():
    """The default is management and data, where the subtype filter is
    irrelevant and setting it would be a command sent for nothing."""
    sent = configured(frame_filter=FrameFilter.NO_CTRL)
    assert Command.SET_CTRL_FILTER not in sent


def test_no_frame_filter_at_all_sends_no_subtype_filter():
    sent = configured()
    assert Command.SET_CTRL_FILTER not in sent


def test_the_frame_filter_is_a_pass_mask_not_a_block_mask():
    """Named 'filter' but a set bit means deliver. Reading it the other way
    round would make every one of these tests assert the opposite."""
    assert FrameFilter.NO_CTRL & FrameFilter.MGMT
    assert FrameFilter.NO_CTRL & FrameFilter.DATA
    assert not FrameFilter.NO_CTRL & FrameFilter.CTRL
    assert FrameFilter.ALL & FrameFilter.CTRL
