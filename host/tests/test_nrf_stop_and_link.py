"""Two things the nRF54L15 told the host that were not quite so.

The second-pass review found both. The nRF54L15 is a separate repository, a
sibling of this one by convention; NRF54L15_SNIFFER names another checkout.
"""

import os
import pathlib

import pytest

from test_firmware_keys import body_of

ROOT = pathlib.Path(__file__).resolve().parents[2]
NRF = pathlib.Path(os.environ.get("NRF54L15_SNIFFER",
                                  ROOT.parent / "nrf54l15-sniffer"))
NRF_154 = NRF / "src" / "radio154.c"
NRF_LINK = NRF / "src" / "link.c"

needs_nrf = pytest.mark.skipif(not NRF_154.exists(),
                               reason="nrf54l15-sniffer not beside this repository")


@needs_nrf
def test_frames_heard_after_stop_are_not_sent():
    """net_recv_data did not look at `running`. Frames the driver had queued
    as it stopped went into a new batch after the flush, and reached the
    host about 20 ms after the STOP or GET_INFO reply -- packets from a
    capture that had ended."""
    body = body_of(NRF_154, "int net_recv_data(struct net_if *iface, struct net_pkt *pkt)\n{")
    check = body.find("!running")
    assert check != -1
    assert check < body.index("sn_batch_add(")
    between = body[check:body.index("sn_batch_add(")]
    assert "net_pkt_unref(pkt)" in between and "return" in between


@needs_nrf
def test_link_reports_the_space_data_can_use():
    """The ring is 8192 bytes, but 512 are kept for replies, STATS and LINK,
    so capture data can fill only 7680: a saturated ring read as 94% full."""
    body = body_of(NRF_LINK, "uint32_t sn_link_capacity(void)\n{")
    assert "TX_RING_SIZE - TX_CONTROL_RESERVE" in body
