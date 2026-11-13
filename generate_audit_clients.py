#!/usr/bin/env python3
"""Create private, unique audit client credentials without displaying them."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, default=Path("audit-clients.json"))
parser.add_argument("--client", action="append", help="Repeat to override the default client labels")
args = parser.parse_args()
labels = args.client or ["agent-a", "agent-b", "agent-c"]
if len(set(labels)) != len(labels) or any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", label) for label in labels):
    parser.error("Client labels must be unique safe identifiers")
os.umask(0o077)
fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w") as handle:
    json.dump({"version": 1, "clients": {label: secrets.token_hex(32) for label in labels}}, handle, indent=2)
    handle.write("\n")
print(f"Created private credential file: {args.output}")
print("Client labels: " + ", ".join(labels))
