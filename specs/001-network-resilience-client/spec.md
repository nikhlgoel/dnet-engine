# Feature Specification: DNet Engine v1 — Network Resilience Client

**Feature Branch**: `001-network-resilience-client`

**Created**: 2026-09-10

**Status**: Draft

**Input**: User description: "DNet Engine v1 — Windows-first network resilience, failover, and DPI-evasion client. GPLv3. Two binaries: dnetd (Rust/Tokio privileged Windows Service) and dnet-tray (Tauri v2 UI). Daemon orchestrates a supervised sing-box child process for all transports (AmneziaWG, Hysteria 2, VLESS+REALITY); no from-scratch transport implementation. Wintun for L3 interception via bundled prebuilt wintun.dll. FakeIP DNS pool 198.18.0.0/15 for domain routing; per-process routing strictly via ETW Microsoft-Windows-Kernel-Network at connect time, no API polling, no kernel drivers. BBR default, Brutal CC opt-in. Provisioning wizard for user-owned Oracle Cloud Always Free endpoints; multi-endpoint health-based rotation; idle-reclamation keepalives. No shared infrastructure. Deferred to v2: MPQUIC aggregation, multi-segment download acceleration, browser extension, non-Windows platforms. Targets: installer <=60MB, idle RAM <=150MB, idle CPU <1%. TDD mandatory; all network testing via Docker + tc/netem simulation, never live campus infrastructure. Constraints authority: .specify/memory/constitution.md and docs/Research-Critique.md."

---

## Overview

People on heavily managed networks — university campuses, hostels, corporate guest Wi-Fi — routinely
have two connections that are each individually unusable: institutional Wi-Fi that is oversubscribed,
filtered, and DNS-hijacked, and mobile data that is attenuated indoors and drops without warning.
Conventional tunnelling tools are recognised and blocked by the managed network's inspection
appliance, and even when one works today it stops working the moment the appliance is updated.

DNet Engine gives such a person a connection that keeps working. It routes their traffic through an
exit point they own, in a form the local network cannot recognise; when the network learns to block
that form, it switches to another automatically; and when one of their two connections degrades, it
moves to the other without the user noticing.

The product is free and open source. It operates no servers on the user's behalf — each user's
traffic leaves through infrastructure that user controls.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Restore access on a restrictive network (Priority: P1)

A student on campus Wi-Fi finds that many sites fail to load, some are actively blocked, and any VPN
they try stops working within minutes. They install DNet Engine, point it at an exit endpoint, and
press a single Stabilize control. The application determines on its own which connection method the
local network currently permits, establishes it, and traffic begins flowing normally.

**Why this priority**: This is the product. Everything else is refinement of, or support for, this
outcome. A build that does only this is already worth shipping.

**Independent Test**: With an endpoint configured by hand and the simulated hostile network active,
press Stabilize and confirm that a destination which the simulated appliance blocks becomes
reachable. Delivers the core value with no other story implemented.

**Acceptance Scenarios**:

1. **Given** a network that blocks the first connection method tried, **When** the user presses
   Stabilize, **Then** the application tries the remaining methods without user involvement and
   establishes a working connection, reporting which method succeeded.
2. **Given** a network that blocks all outbound traffic of one kind (for example, all connectionless
   traffic), **When** the user presses Stabilize, **Then** a method not of that kind is selected and
   succeeds.
3. **Given** an established connection, **When** the local network begins blocking the method in use,
   **Then** the application detects the failure and re-establishes on a different method without the
   user pressing anything.
4. **Given** the application is connected, **When** the user presses Stabilize again to disconnect,
   **Then** all original network settings are restored and normal connectivity resumes immediately.
5. **Given** the application crashes or is force-terminated while connected, **When** the machine is
   next used, **Then** the user is not left without working networking — original settings are
   restored automatically.

---

### User Story 2 - Obtain an exit endpoint without expertise (Priority: P1)

A user who has never provisioned a server needs somewhere for their traffic to exit. The application
walks them through creating a free cloud instance under their own account, configures it for them,
and verifies that it is reachable — after which it appears in their endpoint list ready to use.

**Why this priority**: Also P1, because without an endpoint Story 1 cannot happen for anyone who
does not already run servers. Since the project provides no shared infrastructure, self-service
provisioning is the only path to a working product for the intended audience.

**Independent Test**: Run the wizard from a clean machine with only a cloud account, and confirm it
ends with a verified, reachable endpoint recorded in the configuration.

**Acceptance Scenarios**:

1. **Given** a user with a free-tier cloud account and no server experience, **When** they complete
   the wizard, **Then** a working endpoint exists and is verified reachable before the wizard closes.
2. **Given** the chosen cloud region has no capacity available, **When** provisioning is attempted,
   **Then** the user is told this plainly, and is offered retry and alternative regions with their
   latency trade-off explained.
3. **Given** provisioning fails partway, **When** the user retries or cancels, **Then** no orphaned
   or partly configured cloud resources are left behind, or the user is told exactly what remains.
4. **Given** an endpoint has been provisioned, **When** it sits unused for an extended period,
   **Then** it is not reclaimed by the cloud provider for inactivity.
5. **Given** a user who already has their own server, **When** they choose manual configuration,
   **Then** they can add it without going through cloud provisioning at all.

---

### User Story 3 - Keep working when a connection degrades (Priority: P2)

A user working over hostel Wi-Fi walks into a part of the building where the signal collapses, or
their Wi-Fi becomes saturated in the evening. Their mobile data is also available. The application
moves their traffic to the healthier connection and back again as conditions change, without the
user intervening.

**Why this priority**: This is the second half of the stated problem, and the most visible
day-to-day benefit once access itself is restored. It is separable from Story 1 and can ship after.

**Independent Test**: With traffic flowing over a simulated primary connection, degrade or remove it
and confirm traffic continues over the secondary within the target window.

**Acceptance Scenarios**:

1. **Given** traffic is flowing over the primary connection, **When** that connection is lost
   entirely, **Then** traffic resumes over the secondary connection within the recovery target.
2. **Given** traffic is flowing over the primary connection, **When** it degrades badly but does not
   disappear, **Then** the application detects the degradation and moves traffic rather than waiting
   for a total failure.
3. **Given** traffic has moved to the secondary connection, **When** the primary recovers and remains
   healthy, **Then** traffic returns to it without disruption.
4. **Given** connections are alternating rapidly in quality, **When** the application evaluates them,
   **Then** it does not switch back and forth continuously.
5. **Given** only one connection is available, **When** it degrades, **Then** the application reports
   the degradation honestly rather than implying a switch has occurred.

---

### User Story 4 - Survive the endpoint being blocked (Priority: P2)

The managed network notices sustained traffic to the user's endpoint and blocks its address. Rather
than the product simply ceasing to work, the application detects that the endpoint has become
unreachable and moves to another the user has configured.

**Why this priority**: Without this, the product has a limited and unpredictable lifespan on any
given network — a single blocked address ends it. It depends on Story 1 and can follow it.

**Independent Test**: With multiple endpoints configured, make the active one unreachable in
simulation and confirm traffic moves to another.

**Acceptance Scenarios**:

1. **Given** several configured endpoints, **When** the active one becomes unreachable, **Then**
   another healthy endpoint is selected automatically and the user is informed.
2. **Given** all configured endpoints are unreachable, **When** connection is attempted, **Then** the
   user is told clearly that no endpoint is reachable, and is not left believing they are protected.
3. **Given** a previously blocked endpoint becomes reachable again, **When** health is next assessed,
   **Then** it returns to the pool of usable endpoints.

---

### User Story 5 - Choose what goes through the tunnel (Priority: P3)

A user wants most traffic tunnelled but needs some things to stay on the local network — the campus
intranet, a printer, a game that needs a direct connection. They add rules by destination, and
optionally by application, and the application honours them.

**Why this priority**: Valuable and frequently requested, but the product is useful without it. Rules
by destination are reliable; rules by application are inherently approximate and must be presented
as such.

**Independent Test**: Configure a destination to bypass the tunnel and confirm, by observation, that
its traffic does not traverse it while other traffic does.

**Acceptance Scenarios**:

1. **Given** a destination rule excluding a domain, **When** traffic goes to that domain, **Then** it
   bypasses the tunnel and reaches the local network directly.
2. **Given** an application rule, **When** that application connects, **Then** the rule is applied on
   a best-effort basis, and the interface states plainly that application rules are best-effort.
3. **Given** overlapping rules, **When** traffic matches more than one, **Then** precedence is
   defined, documented, and visible to the user.
4. **Given** local network resources such as printers and intranet hosts, **When** the tunnel is
   active with default settings, **Then** they remain reachable without the user adding rules.

---

### User Story 6 - Get online behind a captive portal (Priority: P3)

The hostel network requires a browser login before any traffic is permitted. The user must be able
to reach that login page and complete it, then connect normally.

**Why this priority**: A hard blocker when encountered — the product cannot connect at all until the
portal is satisfied — but it affects only the first connection on such networks.

**Independent Test**: Simulate a network that intercepts all traffic until a login is completed, and
confirm the login can be reached and completed with the application installed.

**Acceptance Scenarios**:

1. **Given** an unauthenticated captive network, **When** the user opens a browser, **Then** the
   login page loads and can be completed.
2. **Given** the portal has been satisfied, **When** the user presses Stabilize, **Then** connection
   proceeds normally.
3. **Given** the tunnel is active and the portal session expires, **When** connectivity is lost,
   **Then** the application recognises a captive portal as the cause and says so, rather than
   reporting a generic failure.

---

### Edge Cases

**Connection and transport**
- All connection methods are blocked simultaneously — the user must be told this clearly and
  distinguishably from "no endpoint reachable" and from "not logged into the portal".
- The local network permits the connection but throttles it to unusability — success must be judged
  on usable throughput, not merely on a handshake completing.
- The machine sleeps and wakes on a different network.
- The user connects from a network with no restrictions at all — the product must not make things
  worse or add meaningful latency.

**Endpoint and provisioning**
- Cloud credentials are revoked, expire, or lack sufficient permission mid-provisioning.
- The user's cloud free-tier allowance is already consumed by other resources.
- The user provisions a second endpoint while one already exists.
- The endpoint runs out of its monthly transfer allowance.
- The clock on the client is materially wrong, breaking certificate validation.

**Name resolution and routing**
- Applications that bypass system name resolution entirely — this silently defeats destination-based
  routing for exactly the applications most users care about.
- Applications that connect to hardcoded addresses with no name lookup.
- Destinations reachable by both older and newer address families, where the two race each other.
- The synthetic address range collides with something else in use on the local network.
- Rules reference an application that is not installed, or one that has been replaced by an update.

**Failure, safety, and lifecycle**
- The supervised transport process crashes repeatedly in a tight loop.
- The application is terminated abruptly while holding modified system network settings.
- Another tunnelling product is installed and active at the same time.
- Endpoint security software on the machine blocks or quarantines the application.
- The user is not an administrator, or declines the elevation prompt.
- Uninstallation while connected must leave the machine's networking intact.

---

## Requirements *(mandatory)*

### Functional Requirements

**Connection establishment and transport selection**

- **FR-001**: System MUST establish a tunnelled connection to a user-configured endpoint and route
  the machine's traffic through it.
- **FR-002**: System MUST support at least three distinct connection methods, at least one of which
  does not rely on connectionless transport, so that networks blocking that transport entirely are
  still usable.
- **FR-003**: System MUST determine automatically which connection methods the current network
  permits, and select a working one without requiring the user to choose.
- **FR-004**: System MUST judge a connection method successful only when it carries usable traffic,
  not merely when it completes a handshake.
- **FR-005**: System MUST detect loss of the active connection method and re-establish on an
  alternative automatically.
- **FR-006**: System MUST default to a congestion-control behaviour that shares network capacity
  fairly. Behaviour that deliberately ignores congestion signals MUST be opt-in, and MUST warn the
  user that it degrades the connection of everyone else on the same access point.
- **FR-007**: System MUST allow connection method definitions to be updated without installing a new
  version of the application, so that users can respond when a method becomes recognised.
- **FR-008**: System MUST verify the integrity and authenticity of any externally supplied connection
  method definitions before applying them.

**Endpoints**

- **FR-009**: System MUST guide a non-expert user through provisioning an exit endpoint under the
  user's own cloud account, and MUST verify reachability before declaring success. The wizard MUST
  provision automatically using a **scoped, least-privilege credential that the wizard walks the user
  through creating**, and MUST NOT accept or store an account-wide or root credential. The credential
  MUST be revocable by the user in a single documented step, and the wizard MUST tell the user how
  before requesting it.
- **FR-009a**: System MUST store any cloud credential encrypted at rest under the operating system's
  user-scoped protection, MUST NOT write it to logs or diagnostics, and MUST offer to delete it once
  provisioning has completed successfully.
- **FR-010**: System MUST allow a user to add an endpoint they already control, without cloud
  provisioning.
- **FR-011**: System MUST support multiple configured endpoints and select among them based on
  observed health.
- **FR-012**: System MUST detect that an endpoint has become unreachable and move to another healthy
  endpoint automatically.
- **FR-013**: System MUST prevent a provisioned endpoint from being reclaimed by its cloud provider
  for inactivity.
- **FR-014**: System MUST report plainly when no endpoint is reachable, and MUST NOT leave the user
  believing traffic is tunnelled when it is not.
- **FR-015**: System MUST NOT route any user's traffic through infrastructure operated by the
  project. Every endpoint is owned by the user.

**Connection resilience**

- **FR-016**: System MUST detect when the active network connection degrades or is lost, and move
  traffic to a healthier available connection.
- **FR-016a**: Connection methods fall into two documented failover tiers. **Tier 1** methods MUST
  preserve already-established connections across a change of network connection — an open transfer
  or session continues uninterrupted. **Tier 2** methods provide access only; established connections
  MAY break on a change of network connection and MUST be re-established.
- **FR-016b**: System MUST show the failover tier of the method currently in use, and MUST warn
  before selecting a Tier 2 method that established connections will not survive an interface change.
  System MUST prefer a Tier 1 method when more than one method is viable on the current network.
- **FR-017**: System MUST return to a preferred connection once it recovers and remains stable.
- **FR-018**: System MUST NOT oscillate between connections when their quality is fluctuating.
- **FR-019**: System MUST report the true state of connectivity, including when only one degraded
  connection is available and no move is possible.

**Name resolution and routing**

- **FR-020**: System MUST resolve names locally in a way that is not subject to interception or
  forgery by the local network.
- **FR-021**: System MUST make routing decisions on the requested destination name rather than on a
  resolved address.
- **FR-022**: System MUST allow rules by destination name and by address range, and MUST apply them
  deterministically with documented precedence.
- **FR-023**: System MUST allow rules by application, MUST identify the originating application at
  the moment a connection is initiated rather than by periodic inspection, and MUST present
  application rules as best-effort in the interface and documentation.
- **FR-024**: System MUST keep local network resources reachable by default without user
  configuration.
- **FR-025**: System MUST handle the case where an application bypasses system name resolution,
  either by causing it to fall back to system resolution or by informing the user that
  destination-based rules will not apply to it. System MUST, **by default, cause such applications to
  fall back to system name resolution** so that destination rules apply without user action.
- **FR-025a**: System MUST disclose that behaviour prominently — in the first-run flow, not only in
  documentation — explaining that it overrides the application's own encrypted-resolution setting and
  why, and MUST provide a single-action opt-out. On opt-out, System MUST state the consequence:
  destination-based rules will not apply to that application's traffic.
- **FR-026**: System MUST permit the traffic required to detect and satisfy a captive portal.

**Safety, privilege, and lifecycle**

- **FR-027**: System MUST restrict the ability to alter system network configuration to a single
  privileged component; user-facing components MUST NOT hold that ability.
- **FR-028**: System MUST authenticate and authorise every request from a user-facing component to
  the privileged component, and MUST reject unauthenticated requests.
- **FR-029**: System MUST restore the machine's original network configuration on disconnect, on
  exit, on crash, and on uninstall.
- **FR-030**: System MUST supervise its subordinate processes, restart them on failure, and stop
  attempting restarts when failure is persistent — reporting the condition rather than looping.
- **FR-031**: System MUST require administrative privilege only for the privileged component, and
  MUST fail with a clear explanation rather than silently misbehaving when it is unavailable.
- **FR-032**: System MUST warn the user, before first connection, that using it on a managed network
  may violate that network's acceptable use policy.
- **FR-033**: System MUST NOT claim to conceal the existence of tunnelled traffic. Documentation and
  interface MUST state that traffic volume and destination remain observable to the network operator
  even when its content and protocol are not identifiable.
- **FR-034**: System MUST NOT ship with any endpoint address, credential, or key embedded in it.
- **FR-035**: System MUST record diagnostic information sufficient to explain a failure, and MUST NOT
  record the user's browsing destinations by default.

**Interface**

- **FR-036**: Users MUST be able to connect and disconnect with a single control, with no
  configuration beyond having an endpoint.
- **FR-037**: System MUST show, at a glance, whether it is connected, which connection method and
  endpoint are in use, and which network connection is carrying traffic.
- **FR-038**: System MUST expose advanced configuration — rules, endpoints, connection methods — to
  users who want it, without imposing it on those who do not.
- **FR-039**: System MUST distinguish between failure causes in what it reports to the user: no
  endpoint reachable, all methods blocked, captive portal unsatisfied, insufficient privilege.
- **FR-040**: System MUST make its source available under its stated licence, and MUST comply with
  the licence terms of every component it distributes.

### Key Entities

- **Endpoint**: A destination the user owns through which their traffic exits. Has an address,
  credentials, an observed health state and history, an optional cloud-provider association for
  provisioned endpoints, and a user-assigned label.
- **Connection Method**: A named way of reaching an endpoint, with the parameters that shape how it
  appears to an observing network. Has a kind, a set of tunable parameters, a fairness-affecting
  congestion setting, and a record of whether it currently works on this network.
- **Network Connection**: One of the machine's physical ways of reaching the internet. Has a
  measured quality, a user-assigned preference, and a current role (carrying traffic, standby,
  unusable).
- **Routing Rule**: A statement that traffic matching some criterion goes through the tunnel or
  bypasses it. Has a match type (destination name, address range, application), a match value, an
  action, a precedence, and a reliability class (deterministic or best-effort).
- **Connection Session**: One period of being connected. Records which method and endpoint were
  selected and why, which network connections carried traffic and when it moved between them, and
  how the session ended.
- **Provisioning Job**: One attempt to create an endpoint in a user's cloud account. Records its
  stage, the resources created so far so they can be cleaned up, and its outcome.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

**Core capability**

- **SC-001**: On a network configured to block every connection method the product supports except
  one, the user reaches a working connection by pressing a single control, in 100% of attempts.
- **SC-002**: On a network that blocks all connectionless traffic outright, the user still reaches a
  working connection.
- **SC-003**: Time from pressing the connect control to usable traffic is under 15 seconds when the
  first method attempted works, and under 45 seconds when methods must be tried in turn.
- **SC-004**: When the network begins blocking the method in use mid-session, traffic is flowing
  again within 30 seconds without any user action.

**Resilience**

- **SC-005**: When the connection carrying traffic is lost entirely, traffic resumes over another
  available connection within 5 seconds.
- **SC-006**: Over a one-hour session on a connection simulating 20% loss and 150 ms ± 50 ms latency,
  the connection is usable for at least 95% of the period.
- **SC-007**: Under connection quality that fluctuates every few seconds, the product changes which
  connection carries traffic no more than 4 times in 10 minutes.
- **SC-008**: When the active endpoint becomes unreachable and another healthy one is configured,
  traffic is flowing through the other within 30 seconds.

**Onboarding**

- **SC-009**: A user who has never provisioned a server reaches a verified working endpoint in under
  20 minutes, unaided, following only the in-product wizard.
- **SC-010**: 90% of first-time users reach a working connection on their first session without
  consulting documentation beyond the wizard.
- **SC-011**: A failed or cancelled provisioning attempt leaves no unaccounted-for cloud resources in
  100% of cases; anything that cannot be removed automatically is reported explicitly to the user.

**Resource impact**

- **SC-012**: The installer is 60 MB or smaller.
- **SC-013**: While connected and idle, total memory use across all components stays at or below
  150 MB.
- **SC-014**: While connected and idle, total processor use stays below 1% of a four-core machine.
- **SC-015**: A developer running a compile, a test suite, and an editor sees no measurable slowdown
  attributable to the product while it is connected.

**Correctness and safety**

- **SC-016**: After disconnect, exit, forced termination, or uninstall, the machine's networking
  works exactly as it did before installation, in 100% of trials — including forced termination
  while connected.
- **SC-017**: Traffic matching a destination-based bypass rule never traverses the tunnel, across
  1,000 consecutive test connections.
- **SC-018**: Local network resources remain reachable while connected with default settings, with no
  user configuration.
- **SC-019**: An unprivileged process cannot alter routing, name resolution, or adapter state through
  any interface the product exposes; verified by explicit attempt.
- **SC-020**: Every distinct failure cause produces a distinct, actionable message; no failure
  produces only a generic error.

**Process**

- **SC-021**: Every requirement is verified inside the simulated network environment. Zero tests are
  run against a live managed network.
- **SC-022**: Automated test coverage is at least 80% of logic outside the user interface and outside
  supervised third-party processes.

---

## Assumptions

**Inherited decisions.** The following are already settled in `.specify/memory/constitution.md` and
`docs/Research-Critique.md` and are not reopened here. They are recorded because they bound the
solution space this specification is written against.

- The product is Windows-only in v1 (Windows 10 1809+ and Windows 11, x64 and ARM64). Other platforms
  are later ports, not v1 scope.
- Transport is delegated to a supervised third-party process rather than implemented from scratch.
  The product's own contribution is provisioning, method probing and switching, connection failover,
  onboarding, and interface.
- No kernel-mode driver is written or shipped. This is why application-based routing is best-effort
  rather than guaranteed.
- The licence is GPLv3.
- Packet-level aggregation of multiple connections, multi-segment download acceleration, and the
  browser control surface are deferred to v2. The primary supervised transport core implements no
  multipath aggregation, confirming aggregation cannot be in v1 scope.
- The v1 method set is AmneziaWG, Hysteria 2, and VLESS+REALITY — the last being the mandatory
  non-connectionless fallback required by FR-002, and the only Tier 2 method under FR-016a.
  **Verified constraint:** the primary transport core does **not** implement AmneziaWG, so that
  method is provided by a **second supervised process**. The system therefore supervises two
  subordinate transport processes, not one — FR-030 applies to both.

**Assumptions made in writing this specification.**

- The user has, or can create, a free-tier account with a cloud provider. Without one, and without an
  existing server, the product cannot function — and this is accepted, because the alternative is
  operating shared infrastructure, which is explicitly refused.
- The user has administrative rights on their own machine. Managed corporate machines where this is
  not true are out of scope.
- Two network connections are available when connection failover is expected to help; with one, the
  product reports degradation rather than concealing it.
- Free-tier cloud allowances (compute, transfer) are sufficient for one person's ordinary use. Heavy
  sustained transfer may exceed them, and the product should surface consumption rather than fail
  opaquely.
- Reasonable defaults are used for: retry and backoff intervals, health-check cadence, oscillation
  damping thresholds, and log retention. These are tuned during implementation against the simulated
  network rather than specified here.
- "Seamless" failover in SC-005 is measured as traffic resuming, which is a weaker claim than
  established connections surviving. See Q3 below — this needs resolution before planning.

**Dependencies.**

- Two supervised third-party transport processes and a virtual network adapter component, all
  distributed with the product. Licence compatibility with GPLv3 is **verified and closed** (open
  item O1, see `docs/Research-Critique.md` §6.1). Two obligations follow and are binding:
  1. The product MUST NOT use the primary transport core's name in its own branding, product name,
     or marketing, nor imply association or endorsement. Attribution in documentation and an about
     screen is required; branding is not permitted.
  2. The virtual adapter MUST be bundled as its vendor-signed prebuilt binary only, never built from
     source, because the source carries an earlier licence version incompatible with GPLv3.
- A cloud provider's provisioning interface, whose behaviour and free-tier terms are outside the
  project's control and may change.
- Protocol-level claims inherited from the original research are **verified and closed** (open item
  O2, see `docs/Research-Critique.md` §6.2). One claim was refuted and is reflected above.

**Remaining open items** (tracked in `docs/Research-Critique.md` §7; none blocks planning):
O5 — integrity model for the connection-method update feed, blocking FR-007/FR-008 only.
O6 — cost and coverage of connect-time application identification, blocking FR-023 only.
O7 — whether the pinned transport core version implements the newer of the two obfuscation layers,
blocking method tuning only.

---

## Out of Scope for v1

Packet-level multi-connection aggregation · multi-segment download acceleration · browser extension
and its control channel · Linux, Android, macOS, iOS · kernel-mode components · code signing ·
any project-operated shared endpoint · replacing the supervised transport core with a native
implementation.
