# DNet Engine Documentation

## Authority

When documents disagree, this is the order of precedence:

1. [`.specify/memory/constitution.md`](../.specify/memory/constitution.md) — governing principles and binding obligations
2. [`specs/001-network-resilience-client/`](../specs/001-network-resilience-client/) — spec, plan, contracts, tasks
3. [`adr/`](adr/) — decisions that amend the above
4. Everything else in this directory — explanatory, not normative

## Structure

| Path | Contains |
|---|---|
| [`architecture/`](architecture/) | [Tech stack](architecture/tech-stack.md) · [System architecture](architecture/system-architecture.md) · [Module blueprints](architecture/module-blueprints.md) |
| [`design/`](design/) | [Design system](design/design-system.md) · [Tokens](design/tokens.css) · [Live preview](design/preview.html) (serve over HTTP) · [Interaction flows](design/interaction-flows.md) |
| [`security/`](security/) | [Security design](security/security-design.md) · [Threat model](security/threat-model.md) · [Credential handling](security/credential-handling.md) · [The server's firewall and ports: what is open, why, what protects it, what was tested](security/server-firewall.md) · [Dependencies and advisories: what was checked, found and accepted](security/dependencies-and-advisories.md) |
| [`bugs/`](bugs/) | One file per significant bug — see the [index](bugs/README.md) |
| [`adr/`](adr/) | Architecture decision records |
| [`research/`](research/) | Dated research records: evidence behind a proposal, with sources and confidence. Start with [the framework research and status audit](research/2026-10-31-framework-research.md), then [the deep audit of our own code and the upgrades it leads to](research/2026-10-31-framework-deep-audit.md), then [the solutions, with the evidence that they work](research/2026-10-31-solutions.md), then [why not assembly, and adapting to each kind of network](research/2026-10-31-language-and-adaptive-paths.md) |
| [`feed-publishing.md`](feed-publishing.md) | Runbook for the key ceremony and for signing the profile feed (ADR-0002) |

## Source records

| Document | Status |
|---|---|
| [`archive/DNet-Engine-Research.md`](archive/DNet-Engine-Research.md) | Original blueprint. **Unverified** — its citation list does not support its claims. Context, not truth |
| [`DNet-engine-research-v2.md`](DNet-engine-research-v2.md) | Updated record of the architectural pivots. Consistent with the Constitution, except its Tier 1 wording, which is corrected inline |
| [`Research-Critique.md`](Research-Critique.md) | The critique that produced decisions D1–D10 and findings C1–C14. **Supersedes both** where they disagree |
| `Steps.docx` | Original Spec Kit and harness workflow guide |

## Conventions

- Prose is markdown so it diffs. Binary office formats are gitignored.
- Every protocol-level claim cites a primary source (Constitution Principle II).
- Capabilities are described as measured, never as intended (Principle VI).
