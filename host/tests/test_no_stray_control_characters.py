"""No file carries a control character it was never meant to.

An escape sequence that a shell or a Python string interpreted on its way into
a file leaves one invisible byte where two characters should be. README.md
carried one for two weeks: `tools\\ble_survey.py` had lost its `\\b` to a
backspace, so the command it showed did not exist, and nothing looked wrong in
an editor.

Tab, newline and carriage return are the only control characters text here has
a use for, and a carriage return only as half of a line ending. Anything else
below 0x20, DEL, and a carriage return in mid-line are reported with their
place. The mid-line case is real: repairing the lines above, where an
interpreted \\n had split one line in two, left the CR of that false line
ending stranded inside the rejoined line.
"""

import re

from test_no_private_data import tracked_text_files

STRAY = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def test_no_stray_control_characters():
    found = []
    # raw: universal newlines would turn every CR into a line break unseen.
    for name, text in tracked_text_files(raw=True):
        # split("\n"), not splitlines(): the latter treats \x0b, \x0c and
        # \x1c-\x1e as line breaks, and would swallow exactly what is sought.
        for lineno, line in enumerate(text.split("\n"), 1):
            for m in STRAY.finditer(line):
                found.append(f"{name}:{lineno}: byte 0x{ord(m.group()):02x} "
                             f"at column {m.start() + 1}")
            # A CR ends a CRLF line; anywhere before the end, it is stray.
            column = line.find("\r")
            if -1 < column < len(line) - 1:
                found.append(f"{name}:{lineno}: carriage return at column "
                             f"{column + 1}, not at the end of the line")
    assert not found, "stray control characters:\n  " + "\n  ".join(found)
