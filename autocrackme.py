#!/usr/bin/env python3
"""autocrackme — generated IDA crackmes that follow how you solve them.

    python autocrackme.py next                  # build the next challenge
    (solve it in IDA, annotate as you go)
    python autocrackme.py export                # pull your IDA comments out
    python autocrackme.py submit --password <what you found>
    python autocrackme.py status                # what has been observed

Run `python autocrackme.py --help` for every command.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running the script directly from a checkout, without installing anything.
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Challenge output uses a couple of non-ASCII characters (.→ etc). On a
# cp1252 console or pipe that can otherwise fail to encode.
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

from acm.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
