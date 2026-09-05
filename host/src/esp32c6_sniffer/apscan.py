"""Access-point records from a Wi-Fi scan.

The board emits one SN_FRAME_AP_RECORD per access point before the command
reply carrying the count. They travel as their own frame type rather than
inside the reply because the list is variable length and a reply carries a
single 32-bit value.

Wire layout, little-endian, matching sn_radio80211_scan() in
firmware/main/radio80211.c::

    int8   rssi_dbm
    uint8  channel
    uint8  authmode        wifi_auth_mode_t
    uint8  ssid_len
    uint8  bssid[6]
    char   ssid[ssid_len]  not NUL terminated
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_HEADER = struct.Struct("<bBBB6s")
HEADER_LEN = _HEADER.size  # 10

#: wifi_auth_mode_t, from esp_wifi_types_generic.h.
AUTH_MODES = {
    0: "Open",
    1: "WEP",
    2: "WPA-PSK",
    3: "WPA2-PSK",
    4: "WPA/WPA2-PSK",
    5: "Enterprise",
    6: "WPA3-PSK",
    7: "WPA2/WPA3-PSK",
    8: "WAPI-PSK",
    9: "OWE",
    10: "WPA3 Enterprise 192-bit",
    11: "WPA3-PSK-Ext",
    12: "WPA3 Enterprise",
    13: "WPA3 Enterprise Transition",
}


@dataclass(frozen=True)
class AccessPoint:
    bssid: str
    ssid: str
    channel: int
    rssi_dbm: int
    authmode: int

    @property
    def auth_name(self) -> str:
        return AUTH_MODES.get(self.authmode, f"mode {self.authmode}")

    @property
    def hidden(self) -> bool:
        """A hidden network beacons with an empty SSID rather than none."""
        return self.ssid == ""


def parse_ap_record(payload: bytes) -> AccessPoint:
    """Decodes one AP_RECORD payload.

    Raises ValueError on a payload too short to hold what it claims, rather
    than returning a record with a silently truncated SSID.
    """
    if len(payload) < HEADER_LEN:
        raise ValueError(f"AP record is {len(payload)} bytes, need {HEADER_LEN}")
    rssi, channel, authmode, ssid_len, bssid = _HEADER.unpack_from(payload)
    ssid_bytes = payload[HEADER_LEN:HEADER_LEN + ssid_len]
    if len(ssid_bytes) != ssid_len:
        raise ValueError(
            f"AP record claims a {ssid_len}-byte SSID but carries "
            f"{len(ssid_bytes)}"
        )
    return AccessPoint(
        bssid=":".join(f"{b:02x}" for b in bssid),
        # Access points are free to put anything in an SSID, so a decode error
        # must not abort a survey.
        ssid=ssid_bytes.decode("utf-8", "replace"),
        channel=channel,
        rssi_dbm=rssi,
        authmode=authmode,
    )
