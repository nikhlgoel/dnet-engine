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

## Pattern

**Four of the first five bugs produced a *passing* result that proved nothing.** None would have been
caught by running the test suite, because the suite was green throughout. All five were found by
*measuring what the test actually did* rather than trusting that it did it.

That is the reasoning behind Constitution Principle III's exit gate — a harness that passes
everything proves nothing — and behind the negative test on `lint-branding`. Where a check exists to
detect something, prove it detects that thing before trusting a negative result.
