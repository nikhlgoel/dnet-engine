# BUG-004: Container interface name assumed, then detected from shared state

**Status**: Fixed
**Severity**: Medium — conditions applied to the wrong interface, or to the wrong container's
**Found**: 2026-09-10, when the transit interface appeared as `eth1` on one run and `eth0` on the next
**Area**: `testing/harness` — all condition scripts
**Fixed in**: `cb46844`

## Symptom

Two related failures, the second introduced while fixing the first.

**First**: condition scripts hardcoded `IFACE=eth1`. Docker does not guarantee that the second
attached network lands on `eth1`; the transit interface was observed as `eth1` on one run and `eth0`
on the next. Shaping was silently applied to the wrong interface.

**Second**: the initial fix had each container write its interface name into `/opt/state`, and had
`degrade.sh` infer which container it was running in by checking which marker files existed. But
**both containers mount the same `/opt/state` volume**, so each saw the other's marker. The detection
logic could never distinguish them.

## Root cause

**First**: interface naming in Docker is an ordering artefact, not a contract. Assuming it is stable
is assuming something the platform never promised.

**Second**: a shared volume is shared. Using it for per-container identity is self-contradictory —
the one thing a shared volume cannot express is which container is asking.

## Why it was dangerous

Applying `tc` to the wrong interface produces exactly the BUG-001 failure mode: the condition installs
cleanly, `tc qdisc show` reports it present, and the traffic under test is untouched. A test passes
and proves nothing.

The second bug is the more instructive one — it was introduced *while fixing the first*, and it
looked correct. A fix that is not verified is a hypothesis.

## Resolution

Each container resolves its own transit interface by **subnet**, not by name, and writes it to
`/run/dnet-iface` — deliberately **not** the shared volume:

```bash
TRANSIT_IFACE="$(ip -o -4 addr show | awk '$4 ~ /^172\.32\./ {print $2; exit}')"
echo "$TRANSIT_IFACE" > /run/dnet-iface   # container-local, NOT the shared volume
```

All condition scripts then read one line:

```bash
IFACE="$(cat /run/dnet-iface 2>/dev/null || echo eth0)"
```

The UTM fails fast at startup if the transit subnet is not found, rather than shaping something
arbitrary. Verified: `utm -> eth1`, `endpoint -> eth0`, each correct for its own container.

## Prevention

- Interfaces are identified by the property that actually matters — the subnet they carry — not by a
  name the platform assigns arbitrarily.
- Per-container state lives on container-local paths. `/opt/state` remains for genuinely shared
  values only.
- Recorded in `HARNESS-NOTES.md`, including the shared-volume trap, since the second bug was subtler
  than the first.
