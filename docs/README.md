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
| [`design/`](design/) | [Design system](design/design-system.md) · [Interaction flows](design/interaction-flows.md) |
| [`security/`](security/) | [Security design](security/security-design.md) · [Threat model](security/threat-model.md) · [Credential handling](security/credential-handling.md) |
| [`bugs/`](bugs/) | One file per significant bug — see the [index](bugs/README.md) |
| [`adr/`](adr/) | Architecture decision records |

## Source records

| Document | Status |
|---|---|
| [`DNet-Engine-Research.md`](DNet-Engine-Research.md) | Original blueprint. **Unverified** — its citation list does not support its claims. Context, not truth |
| [`DNet-engine-research-v2.md`](DNet-engine-research-v2.md) | Updated record of the architectural pivots. Reviewed and consistent with the Constitution |
| [`Research-Critique.md`](Research-Critique.md) | The critique that produced decisions D1–D10 and findings C1–C14. **Supersedes both** where they disagree |
| `Steps.docx` | Original Spec Kit and harness workflow guide |

## Conventions

- Prose is markdown so it diffs. Binary office formats are gitignored.
- Every protocol-level claim cites a primary source (Constitution Principle II).
- Capabilities are described as measured, never as intended (Principle VI).
