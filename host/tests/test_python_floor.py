"""The oldest Python the plugin supports is one fact, stated in several places.

host/pyproject.toml declares it, and pip enforces it on a release wheel. The
CI matrix has to test it, or the floor rots: this one did. It said 3.10 for
two weeks while a nested f-string that only 3.12 can parse sat in the extcap
script, so a user on 3.10 or 3.11 got a plugin that failed to load inside
Wireshark, and the 3.10 job that would have said so was red from its first
run with nobody reading it.

The installers and the README repeat the floor to a user who has not got it
yet, and the installers check it, so that an old Python is refused with a
sentence rather than with pip's resolver output. Every copy is held to the
declared value here.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]


def _floor():
    text = (REPO / "host" / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^requires-python\s*=\s*">=\s*(\d+)\.(\d+)"', text, re.M)
    assert m, "host/pyproject.toml declares no requires-python floor"
    return int(m.group(1)), int(m.group(2))


def test_ci_tests_the_declared_floor():
    text = (REPO / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    m = re.search(r"^\s*python:\s*\[([^\]]*)\]", text, re.M)
    assert m, "tests.yml has no python matrix"
    # "3.14t" is 3.14's free-threaded build: the same version for the floor.
    versions = [tuple(int(p) for p in v.strip().strip("\"'").rstrip("t").split("."))
                for v in m.group(1).split(",")]
    assert min(versions) == _floor(), (
        f"tests.yml tests {versions}, but the declared floor is {_floor()}")


def test_every_stated_floor_is_the_declared_one():
    """'Python 3.x or newer' and 'Python 3.x+' wherever a user reads them."""
    stated = re.compile(r"Python (\d+)\.(\d+)(?: or newer|\+)")
    wrong = []
    for name in ("README.md", "extcap/install.ps1", "extcap/install.sh",
                 "extcap/package-release.py", ".github/workflows/release.yml"):
        text = (REPO / name).read_text(encoding="utf-8")
        found = stated.findall(text)
        assert found, f"{name} no longer states the Python floor"
        wrong += [f"{name}: Python {a}.{b}" for a, b in found
                  if (int(a), int(b)) != _floor()]
    assert not wrong, f"the declared floor is {_floor()}; these disagree: {wrong}"


def test_the_installers_refuse_an_older_python():
    """Checked before the environment is built, not left to pip's resolver."""
    for name in ("extcap/install.ps1", "extcap/install.sh"):
        text = (REPO / name).read_text(encoding="utf-8")
        m = re.search(r"version_info\s*<\s*\((\d+),\s*(\d+)\)", text)
        assert m, f"{name} does not check the Python version it builds with"
        assert (int(m.group(1)), int(m.group(2))) == _floor(), (
            f"{name} checks for {m.group(1)}.{m.group(2)}, "
            f"but the declared floor is {_floor()}")
