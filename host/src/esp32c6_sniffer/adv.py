"""Decoding BLE advertising reports and the data they carry.

Wireshark dissects all of this already, and for reading a capture it should be
left to. This exists for the survey tool, which has to summarise a room without
a full HCI dissector -- who is advertising, how often, how loudly, and whether
they are trying to be anonymous about it.

That is the whole boundary, and it is worth stating because the temptation to
cross it is constant: anything that ends up in a capture file is Wireshark's
job, and Wireshark 4.6 dissects more than one might assume -- Matter
advertising data, the Matter message layer and its TLV encoding all have
dissectors. Nothing here is for reading captures. It exists because the survey
never produces one.

Two report layouts, and they are not interchangeable:

* Legacy, LE Meta subevent 0x02: event type, address type, address, data
  length, data, then RSSI *after* the data.
* Extended, subevent 0x0D: a two-byte event type, then address, PHYs, SID, TX
  power and RSSI *before* the data.

Reading one with the other's offsets yields a plausible address belonging to
nobody, so the subevent decides and an unrecognised one returns nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

META_LEN = 12          # sn_ble_meta_t, ahead of the HCI packet

H4_EVENT = 0x04
EVENT_LE_META = 0x3E
SUBEVENT_ADV_REPORT = 0x02
SUBEVENT_EXT_ADV_REPORT = 0x0D

# Advertising data types, from the Bluetooth assigned numbers. Only the ones
# worth summarising are named; the rest are reported by number.
AD_FLAGS = 0x01
AD_UUID16_PARTIAL = 0x02
AD_UUID16_COMPLETE = 0x03
AD_UUID128_PARTIAL = 0x06
AD_UUID128_COMPLETE = 0x07
AD_NAME_SHORT = 0x08
AD_NAME_COMPLETE = 0x09
AD_TX_POWER = 0x0A
AD_SERVICE_DATA_16 = 0x16
AD_APPEARANCE = 0x19
AD_MANUFACTURER = 0xFF

#: Matter's commissioning service. A device advertises under this only while
#: it is waiting to be commissioned -- out of the box, or after a factory
#: reset, or when put into pairing mode. A configured Matter device does not
#: appear here at all, which makes the presence of one a fact worth reporting
#: rather than background noise.
MATTER_SERVICE_UUID = 0xFFF6

#: The only opcode defined for that service data.
MATTER_OPCODE_COMMISSIONABLE = 0x00

#: A deliberately small subset of the Bluetooth company identifiers: the
#: vendors that dominate a typical room. The full list runs to thousands and
#: shipping a stale copy of it would be worse than admitting the gap, so an
#: unknown identifier is reported as a number.
COMPANY_NAMES = {
    0x0006: "Microsoft",
    0x004C: "Apple",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x0087: "Garmin",
    0x00D2: "Dialog",
    0x0157: "Huawei",
    0x0171: "Amazon",
    0x0499: "Ruuvi",
    0x02E5: "Espressif",
    0x0059: "Nordic Semiconductor",
    0x000F: "Broadcom",
    0x001D: "Qualcomm",
    0x0131: "Cypress",
    0x038F: "Xiaomi",
}


class AddressType:
    """How an advertiser's address should be read.

    The distinction is the whole of BLE privacy. A resolvable private address
    is rotated every fifteen minutes or so and cannot be tracked without the
    identity resolving key, so counting it as a device would count one phone
    many times over. A public or random static address does identify a device.
    """

    PUBLIC = "public"
    RANDOM_STATIC = "random static"
    RANDOM_RESOLVABLE = "resolvable private"
    RANDOM_NON_RESOLVABLE = "non-resolvable private"

    @staticmethod
    def classify(address_type: int, address: bytes) -> str:
        if address_type == 0x00:
            return AddressType.PUBLIC
        if not address:
            return "unknown"
        # The top two bits of the most significant byte say which kind of
        # random address it is.
        top = address[-1] >> 6
        if top == 0b11:
            return AddressType.RANDOM_STATIC
        if top == 0b01:
            return AddressType.RANDOM_RESOLVABLE
        if top == 0b00:
            return AddressType.RANDOM_NON_RESOLVABLE
        return "random, reserved"


#: In an extended advertising report, this event-type bit means the PDU that
#: carried it was a LEGACY one. Extended scanning reports legacy
#: advertisements too, so the report format says nothing about the
#: advertisement -- only this bit does.
EVENT_TYPE_LEGACY_PDU = 0x0010


@dataclass(frozen=True)
class MatterCommissioning:
    """What a Matter device says while it waits to be commissioned.

    The discriminator is how a commissioner tells one waiting device from
    another when several are in pairing mode; it is the number the setup code
    encodes. Vendor and product identify the model.
    """
    discriminator: int
    vendor_id: int
    product_id: int
    version: int
    extended_announcement: bool


def parse_matter_service_data(value: bytes) -> MatterCommissioning | None:
    """Decodes Matter commissioning service data, or None if it is not that.

    Layout, after the two UUID bytes: one opcode byte, then a 16-bit field
    holding the 12-bit discriminator and a 4-bit version, then vendor and
    product identifiers, then flags. Everything little-endian.
    """
    if len(value) < 8:
        return None
    if value[0] != MATTER_OPCODE_COMMISSIONABLE:
        return None
    combined = value[1] | (value[2] << 8)
    flags = value[7]
    return MatterCommissioning(
        discriminator=combined & 0x0FFF,
        version=(combined >> 12) & 0x0F,
        vendor_id=value[3] | (value[4] << 8),
        product_id=value[5] | (value[6] << 8),
        extended_announcement=bool(flags & 0x02),
    )


@dataclass
class AdvertisingReport:
    address: str
    address_type: str
    rssi_dbm: int
    #: The report arrived through the extended HCI path. This is a property of
    #: the scan, not of the advertisement: under extended scanning everything
    #: arrives this way, legacy advertisements included.
    via_extended_report: bool
    #: The advertisement itself used an extended PDU, which is the thing
    #: legacy scanning cannot see at all. Conflating the two made a survey
    #: report every device as "extended" and mean nothing by it.
    extended_pdu: bool
    data: bytes
    name: str | None = None
    company_id: int | None = None
    services: list[str] = field(default_factory=list)
    tx_power_dbm: int | None = None
    #: Set when the device is advertising itself as ready to be
    #: commissioned into a Matter fabric.
    matter: object | None = None

    @property
    def company(self) -> str | None:
        if self.company_id is None:
            return None
        return COMPANY_NAMES.get(self.company_id, f"0x{self.company_id:04x}")

    @property
    def trackable(self) -> bool:
        """False when the address is rotated for privacy, so counting it as a
        device would count one phone many times over."""
        return self.address_type in (AddressType.PUBLIC,
                                     AddressType.RANDOM_STATIC)


def parse_ad_structures(data: bytes) -> list[tuple[int, bytes]]:
    """Splits advertising data into (type, value) pairs.

    Stops at the first structure that runs past the end rather than raising:
    advertising data is padded with zeros to a fixed length, so a run of them
    is normal termination, not corruption.
    """
    out: list[tuple[int, bytes]] = []
    pos = 0
    while pos < len(data):
        length = data[pos]
        if length == 0:
            break                      # zero padding: the data has ended
        if pos + 1 + length > len(data):
            break                      # truncated, keep what parsed cleanly
        out.append((data[pos + 1], bytes(data[pos + 2:pos + 1 + length])))
        pos += 1 + length
    return out


def _enrich(report: AdvertisingReport) -> AdvertisingReport:
    for ad_type, value in parse_ad_structures(report.data):
        if ad_type in (AD_NAME_COMPLETE, AD_NAME_SHORT) and report.name is None:
            # Names are attacker-controlled bytes, so decoding must not raise.
            report.name = value.decode("utf-8", "replace").strip("\x00")
        elif ad_type == AD_MANUFACTURER and len(value) >= 2:
            report.company_id = value[0] | (value[1] << 8)
        elif ad_type in (AD_UUID16_COMPLETE, AD_UUID16_PARTIAL):
            for i in range(0, len(value) - 1, 2):
                report.services.append(f"{value[i + 1]:02x}{value[i]:02x}")
        elif ad_type == AD_TX_POWER and value:
            report.tx_power_dbm = value[0] - 256 if value[0] > 127 else value[0]
        elif ad_type == AD_SERVICE_DATA_16 and len(value) >= 2:
            uuid = value[0] | (value[1] << 8)
            if uuid == MATTER_SERVICE_UUID:
                report.matter = parse_matter_service_data(value[2:])
    return report


def _address_text(raw: bytes) -> str:
    # HCI carries addresses least significant byte first.
    return ":".join(f"{b:02x}" for b in reversed(raw))


def parse_advertising_reports(payload: bytes) -> list[AdvertisingReport]:
    """Decodes every report in one frame payload. Empty if it is not one."""
    if len(payload) <= META_LEN:
        return []
    hci = payload[META_LEN:]
    if len(hci) < 5 or hci[0] != H4_EVENT or hci[1] != EVENT_LE_META:
        return []

    subevent = hci[3]
    count = hci[4]
    pos = 5
    reports: list[AdvertisingReport] = []

    for _ in range(count):
        if subevent == SUBEVENT_ADV_REPORT:
            # event type, address type, address, data length, data, RSSI
            if pos + 9 > len(hci):
                break
            address_type = hci[pos + 1]
            address = hci[pos + 2:pos + 8]
            data_len = hci[pos + 8]
            start = pos + 9
            if start + data_len + 1 > len(hci):
                break
            data = hci[start:start + data_len]
            rssi = hci[start + data_len]
            pos = start + data_len + 1
            via_extended_report = False
            extended_pdu = False        # this subevent only carries legacy
        elif subevent == SUBEVENT_EXT_ADV_REPORT:
            # two-byte event type, then address, PHYs, SID, TX power, RSSI,
            # periodic interval, direct address, and only then the data.
            if pos + 24 > len(hci):
                break
            event_type = hci[pos] | (hci[pos + 1] << 8)
            address_type = hci[pos + 2]
            address = hci[pos + 3:pos + 9]
            rssi = hci[pos + 13]
            data_len = hci[pos + 23]
            start = pos + 24
            if start + data_len > len(hci):
                break
            data = hci[start:start + data_len]
            pos = start + data_len
            via_extended_report = True
            extended_pdu = not (event_type & EVENT_TYPE_LEGACY_PDU)
        else:
            return []

        reports.append(_enrich(AdvertisingReport(
            address=_address_text(address),
            address_type=AddressType.classify(address_type, address),
            rssi_dbm=rssi - 256 if rssi > 127 else rssi,
            via_extended_report=via_extended_report,
            extended_pdu=extended_pdu,
            data=bytes(data),
        )))

    return reports
