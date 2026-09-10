#!/bin/bash
# T019 - ground-truth reporting (HN-03).
#
# Reports which condition rules fired and how many packets each dropped, so a
# test can distinguish "the obfuscation worked" from "the rule never fired".
# Without this, HV-03 could pass for entirely the wrong reason.
set -euo pipefail

python3 - <<'PYEOF'
import json, re, subprocess

def iface():
    try:
        with open("/run/dnet-iface") as fh:
            return fh.read().strip() or "eth0"
    except OSError:
        return "eth1"

def counters():
    out = subprocess.run(
        ["iptables", "-L", "DNET_COND", "-v", "-n", "-x"],
        capture_output=True, text=True,
    ).stdout
    rules = []
    for line in out.splitlines()[2:]:
        parts = line.split(None, 5)
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        comment = ""
        m = re.search(r"/\* (.*?) \*/", line)
        if m:
            comment = m.group(1)
        rules.append({
            "packets": int(parts[0]),
            "bytes": int(parts[1]),
            "target": parts[2],
            "proto": parts[3],
            "label": comment,
        })
    return rules

def qdisc():
    out = subprocess.run(
        ["tc", "-s", "qdisc", "show", "dev", iface()],
        capture_output=True, text=True,
    ).stdout.strip()
    return out.splitlines()[0] if out else ""

print(json.dumps({"conditions": counters(), "qdisc": qdisc()}, indent=2))
PYEOF
