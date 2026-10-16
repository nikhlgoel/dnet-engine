# Bug Reports

One file per significant bug: `bug-NNN-short-slug.md`.

A bug is "significant" and gets a file if it caused **wrong behaviour that a passing test did not
catch**, cost more than a few minutes to diagnose, or would plausibly recur. Typos and trivial
compile errors do not.

## Template

```markdown
# BUG-NNN: <one-line title>

**Status**: Fixed | Open | Won't fix
**Severity**: Critical | High | Medium | Low
**Found**: YYYY-MM-DD, <how it was found>
**Area**: <component>
**Fixed in**: <commit>

## Symptom
What was observed.

## Root cause
Why it happened. The mechanism, not the guess.

## Why it was dangerous
What it would have caused had it shipped or gone unnoticed.

## Resolution
The specific change.

## Prevention
What stops it recurring: a test, a check, a documented constraint.
```

## Index

| ID | Title | Severity | Status |
|---|---|---|---|
| [BUG-001](bug-001-harness-tc-egress-only.md) | Traffic shaping applied to only one direction | **Critical** | Fixed |
| [BUG-002](bug-002-harness-iptables-length-match.md) | iptables length match used the wrong packet size | **High** | Fixed |
| [BUG-003](bug-003-harness-missing-python3.md) | Test probe failed silently: no interpreter in the container | **High** | Fixed |
| [BUG-004](bug-004-harness-interface-naming.md) | Container interface name assumed, then detected from shared state | Medium | Fixed |
| [BUG-005](bug-005-powershell-argument-and-stderr.md) | Two PowerShell traps produced false failures | Medium | Fixed |
| [BUG-006](bug-006-spike-o6-instrument-verdict.md) | SPIKE-O6 instrument printed a verdict it could not support | **High** | Fixed (instrument v2) |
| [BUG-007](bug-007-spike-r4-uapi-pipe-owner.md) | SPIKE-R4 cannot start the AmneziaWG core from an Administrator shell | **High** | Open |
| [BUG-008](bug-008-probe-core-network-changed.md) | A healthy profile was reported blocked half the time, right after its probe core started | **High** | Fixed (bounded retry; mechanism inferred) |

## Pattern

**Four of the first five bugs produced a *passing* result that proved nothing.** None would have been
caught by running the test suite, because the suite was green throughout. All five were found by
*measuring what the test actually did* rather than trusting that it did it.

**BUG-006 is the inverse:** a *failing* result that proved nothing. The gate could only
answer PASS or FAIL, so an instrument defect came out as a verdict that nearly cut FR-023.
Gates must be able to return INVALID.

**BUG-007 is a third kind:** the gate failed loudly and honestly, but its cause stayed in a
gitignored log, so the written reasons for deferring it pointed elsewhere. When a gate fails, put the
cause where the next reader will look.

That is the reasoning behind Constitution Principle III's exit gate — a harness that passes
everything proves nothing — and behind the negative test on `lint-branding`. Where a check exists to
detect something, prove it detects that thing before trusting a negative result.
