"""The README.txt inside a release zip must describe that zip.

It said both firmwares were in the release, but release.yml publishes only
the ESP32-C6's: the nRF54L15 firmware has its own repository and its own
release, so the file it named was not there to flash.
"""

import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def readme_text() -> str:
    module = load("package_release_readme", ROOT / "extcap" / "package-release.py")
    return next(v for k, v in vars(module).items()
                if isinstance(v, str) and "Flash a board first" in v)


def test_the_release_readme_promises_only_what_the_release_holds():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8")
    assert ".hex" not in workflow           # nothing of the nRF54L15 is built here
    text = readme_text()
    assert "Both firmwares are in the same release" not in text
    assert "esp32c6-<ver>.bin" in text


def test_it_says_where_the_nrf54l15_firmware_is():
    text = readme_text()
    assert "nrf54l15-sniffer" in text
