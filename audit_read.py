#!/usr/bin/env python3
"""Read retained JSONL audit files without displaying request/response bodies."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("log", type=Path, help="Active events.jsonl path; rotated siblings are included")
parser.add_argument("--client", help="Filter by credential label")
parser.add_argument("--json", action="store_true", help="Print structured events")
args = parser.parse_args()
files = sorted(args.log.parent.glob(args.log.name + ".[0-9]*"),
               key=lambda path: int(path.name.rsplit(".", 1)[1]), reverse=True) + [args.log]
for path in files:
    if not path.exists():
        continue
    for number, line in enumerate(path.open(), 1):
        try:
            event = json.loads(line)
        except ValueError:
            print(f"Unparseable record: {path.name}:{number}")
            continue
        if args.client and event.get("client") != args.client:
            continue
        if args.json:
            print(json.dumps(event))
        else:
            fields = [event.get("time", ""), event.get("client", "-"), event.get("event", ""),
                      event.get("tool", event.get("rpc_method", "")), event.get("requested_url", event.get("url", event.get("returned_url", ""))),
                      event.get("rpc_outcome", event.get("outcome", event.get("reason", "")))]
            print("  ".join(str(field) for field in fields if field))
