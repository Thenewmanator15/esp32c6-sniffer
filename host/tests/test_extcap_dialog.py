"""The capture dialog must open on the defaults it claims, and pick files the
way each option uses them.

Checked against Wireshark's own source, not assumed:

- A selector's `{default=...}` on the arg line is ignored by the Qt dialog.
  ExtArgSelector::setDefaultValue preselects only a value line marked
  `{default=true}`, and falls back to the first value. The Wi-Fi Channel
  said 6 and the dialog opened on 1, so a capture started from it ran on 1.
- A fileselect without `{mustexist=true}` opens a Save dialog: it warns
  about overwriting the very key file the user is choosing, and does not
  check that the file exists.
"""

import importlib.util
import re
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"

INTERFACES = ["esp32c6-802154", "esp32c6-wifi", "esp32c6-ble",
              "nrf54l15-802154", "nrf54l15-ble"]

#: Files the capture reads. The CSI sidecar is written, so a Save dialog is
#: right for it.
READS = {"--keys", "--thread", "--ble-keys"}
WRITES = {"--csi"}


def load_plugin():
    spec = importlib.util.spec_from_file_location("extcap_plugin_dialog", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = load_plugin()


@pytest.fixture
def config(monkeypatch, capsys):
    monkeypatch.setattr(plugin, "find_board_ports", lambda: [])

    def run(interface):
        plugin.print_config(interface)
        return capsys.readouterr().out.splitlines()
    return run


def fields(line):
    return dict(re.findall(r"\{(\w+)=([^}]*)\}", line))


def args_of(lines, kind):
    return {fields(l)["number"]: fields(l) for l in lines
            if l.startswith("arg ") and fields(l).get("type") == kind}


@pytest.mark.parametrize("interface", INTERFACES)
def test_every_selector_marks_its_default_value(config, interface):
    lines = config(interface)
    for number, arg in args_of(lines, "selector").items():
        values = [fields(l) for l in lines
                  if l.startswith("value ") and fields(l)["arg"] == number]
        marked = [v["value"] for v in values if v.get("default") == "true"]
        assert marked == [arg["default"]], (interface, arg["call"], marked)


def test_the_wifi_dialog_opens_on_channel_6(config):
    lines = config("esp32c6-wifi")
    channel = next(a for a in args_of(lines, "selector").values()
                   if a["call"] == "--channel")
    marked = [fields(l)["value"] for l in lines
              if l.startswith("value ") and fields(l)["arg"] == channel["number"]
              and fields(l).get("default") == "true"]
    assert marked == ["6"]


@pytest.mark.parametrize("interface", INTERFACES)
def test_files_the_capture_reads_must_exist(config, interface):
    for arg in args_of(config(interface), "fileselect").values():
        if arg["call"] in READS:
            assert arg.get("mustexist") == "true", (interface, arg["call"])
        else:
            assert arg["call"] in WRITES, f"new file option {arg['call']}: reads or writes?"
            assert "mustexist" not in arg, (interface, arg["call"])


def test_every_file_option_is_seen_somewhere(config):
    """So the two tests above are not passing over options they never met."""
    seen = set()
    for interface in INTERFACES:
        seen |= {a["call"] for a in args_of(config(interface), "fileselect").values()}
    assert seen == READS | WRITES
