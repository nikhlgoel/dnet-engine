# ADR-0003: Hysteria 2 obfuscation layer: Salamander, Gecko, and which is the default

**Status**: **Accepted** — option C, by the owner, 2026-10-24. Questions 2 and 3 under "Decision needed" are
not decided and stay open (see "Open after acceptance").
**Date**: 2026-10-24
**Task**: T067 (open item O7)
**Relates to**: ADR-0002 (the profile feed may *propose* a layer, but never applies one alone),
`docs/Research-Critique.md` §6.2 and O7

## Context

Hysteria 2 (profile B) hides its QUIC traffic behind an obfuscation layer. Two exist:

- **Salamander.** BLAKE2b-256 over a random 8-byte salt followed by a shared secret; the packet is XORed
  against that hash. It makes the payload look random. It does not change packet sizes or the shape of
  the handshake.
- **Gecko.** Wraps Salamander, and additionally splits the long-header QUIC packets (the handshake
  ones) into 2 to 8 randomly sized, randomly padded segments, so the handshake's size pattern is no
  longer a recognisable QUIC one.

Open item O7 asked whether the pinned core implements Gecko at all, because Gecko is the newer of the two
and a core can lag its specification.

### What is established

| Fact | How known |
|---|---|
| The pinned primary core (v1.14.0) accepts `obfs.type = "gecko"` with `min_packet_size` and `max_packet_size`, and its own `check` command accepts a generated Gecko configuration | T056, 2026-09-12, against `option/hysteria2.go` and `constant/hysteria2.go` at the pinned commit; `crates/dnet-config/tests/pinned_core_check.rs` runs the real core's `check` on a Gecko configuration |
| The client generator, the stored credentials, the profile-feed schema and its bounds all support both layers | `dnet-config::hysteria2`, `credentials`, `dnet-core::feed::document`; each layer round-trips and is refused when malformed (Gecko without sizes, Salamander with sizes, sizes outside 256 to 1400 or `min > max`) |
| **Both ends must use the same layer.** The layer is an *endpoint* parameter in ADR-0002's terms, so a feed can propose it but the client never switches to it alone; the person approves a change to their own server | ADR-0002 §6 |
| **Provisioned servers are bootstrapped with Salamander only.** The server-side configuration the bootstrap writes names `salamander` and nothing else | `crates/dnet-provision/src/bootstrap.rs` |

### What is not established

- **Whether Gecko is harder to block than Salamander on any real network.** No measurement compares them.
  The claim that fragmenting the handshake defeats size-pattern matching is the specification's, and
  nothing in this project has tested it against a network that blocks QUIC by pattern.
- **What Gecko costs.** Splitting and padding the handshake adds packets and bytes to every new
  connection and every migration. The size is unmeasured; it is expected to be small against a long-lived
  tunnel and noticeable against many short ones.
- **Good values for `min_packet_size` and `max_packet_size`.** The feed's bounds (256 to 1400) are what
  the core accepts, narrowed; the example in ADR-0002 uses 512 and 1200. No tuning has been done.

HV-03 (the obfuscated profile connects and the unobfuscated control does not) is the test that would
start to answer the first, and it runs on a real hostile network, which the project does not have access
to and may not test against (Constitution, Principle III: the simulated harness is the only target).
The harness can show that a layer *works*; it cannot show that it *evades* a particular real filter.

## Options

**A. Salamander always.** Simplest; the layer every provisioned server already uses; no tuning. Leaves
the handshake's size pattern as it is.

**B. Gecko by default.** Stronger on paper. Not supported by provisioning, costs bytes, and is not
measured to help, so it would be a default chosen on the specification's word alone, in a project whose
principles say capabilities are described as measured, never as intended (Principle VI).

**C. Salamander by default; Gecko an endpoint option that is offered, not assumed.** A person who runs
their own server (or whose server a feed proposes to reconfigure, with their consent) can use Gecko; the
product makes no claim that it is better until something measures it.

## Recommendation

**C.** It is the only option that matches what is known. It changes nothing that works today, it keeps
the decision with the person whose server it is, and it leaves the door open: if a measurement ever shows
Gecko helps, a feed can propose it (endpoint section, with consent) without a release.

## Decision (owner, 2026-10-24)

**Option C is accepted:** Salamander is the default; Gecko is an endpoint option that is offered, not
assumed, and the product makes no claim that it is better until something measures it.

## Open after acceptance

The two remaining questions were not part of the decision:

2. Whether provisioning should be able to bootstrap a Gecko server (a bootstrap option; the server core
   it installs is the same one and already supports it), or whether that stays a manual choice.
3. Whether the feed's example sizes (512 and 1200) should be the documented starting point or left
   untuned until measured.

### Primary-source check, 2026-10-26 (facts for question 3; nothing decided)

Read at the pinned commit `0b89958` and the `sing-quic` version its `go.mod` pins (`v0.7.0-beta.4`):

| Fact | Source |
|---|---|
| `gecko` is a recognised obfs type beside `salamander`, with `min_packet_size` and `max_packet_size` | `constant/hysteria2.go`; `option/hysteria2.go` |
| The outbound (client) and the inbound (server) both pass the obfs password and both sizes to the protocol layer, so a server the bootstrap set up could serve Gecko (question 2) with the same core | `protocol/hysteria2/outbound.go`, `protocol/hysteria2/inbound.go` |
| **512 and 1200 are the core's own defaults**, used when a size is omitted (0) | `hysteria2/gecko.go` (`geckoDefaultMinPacketSize`, `geckoDefaultMaxPacketSize`); applied in `hysteria2/client.go` and `hysteria2/service.go` |
| The core refuses `min <= 0`, `min > max` and `max > 2048` ("gecko: invalid packet size range"). This project's 256 to 1400 bound is narrower | `hysteria2/client.go`, `hysteria2/service.go` |
| Only QUIC long-header packets (first byte's top bit set) are split, into 2 to 8 chunks, each padded at random up to `max`; short-header (data) packets go out as plain Salamander | `hysteria2/gecko.go` (`WriteTo`, `writeFragmented`, `randomPadLen`) |

So the ADR-0002 example sizes are not a guess of this project's: they are what the core does when told
nothing. Whether to document them as the starting point (question 3) is still the owner's call; the last
row also bounds Gecko's cost to handshake and migration packets, which is unmeasured but no longer open
in kind.

## Consequences

If C is accepted: no code changes. T067 is closed by this record; tuning stays an open measurement that
belongs to the live gates, not to a guess. The user interface says nothing about Gecko (it is not a
claim the product can back), and the About screen and documentation describe obfuscation as concealing
content and protocol, not traffic volume or destination (FR-033).

If B is chosen: provisioning must bootstrap Gecko first, and the first-run flow must say that the layer
is newer and unmeasured here.

If A is chosen: the Gecko paths stay (the feed and credentials already carry them) but are never offered.
