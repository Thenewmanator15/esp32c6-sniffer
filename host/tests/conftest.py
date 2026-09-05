import pytest
import serial


def pytest_addoption(parser):
    parser.addoption("--port", default="COM3", help="serial port of the board")


def pytest_configure(config):
    config.addinivalue_line("markers", "hardware: requires the board attached")


@pytest.fixture
def sniffer_port(request):
    port = request.config.getoption("--port")
    ser = serial.Serial(port, 115200, timeout=0.2)
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
