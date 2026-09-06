import pytest
import serial


def pytest_addoption(parser):
    parser.addoption("--port", default="COM3", help="serial port of the board")


def pytest_configure(config):
    config.addinivalue_line("markers", "hardware: requires the board attached")


@pytest.fixture
def sniffer_port(request):
    """The board's serial port, or a skip explaining why there isn't one.

    A port that is absent or busy is an environment condition, not a test
    failure. Running the suite while a capture was open in Wireshark produced
    three red ERRORs whose message was a pyserial traceback about access being
    denied -- which reads as "the tests are broken" rather than "something else
    is using the board, as only one thing can".
    """
    port = request.config.getoption("--port")
    try:
        ser = serial.Serial(port, 115200, timeout=0.2)
    except serial.SerialException as exc:
        text = str(exc)
        if "Access is denied" in text or "PermissionError" in text:
            pytest.skip(
                f"{port} is busy. Something else is using the board -- a "
                f"capture open in Wireshark, a serial monitor, or a previous "
                f"run that has not exited. Only one can hold it."
            )
        pytest.skip(f"no board on {port}: {exc}")
    try:
        # pyserial opens Windows ports with only a 4 KB receive buffer. The
        # firmware discards data when the host stops reading, so a larger
        # cushion is a correctness measure, not a performance one.
        ser.set_buffer_size(rx_size=1 << 20)
    except (AttributeError, OSError):
        pass
    ser.reset_input_buffer()
    yield ser
    ser.close()
