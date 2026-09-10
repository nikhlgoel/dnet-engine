# Contract: Phase 0 Network Simulation Harness

**Location**: `testing/harness/` | **Constitution**: Principle III | **Blocks**: every other phase

No feature is complete until it passes inside this harness. **Testing against a live managed network
is prohibited.** The harness is built first, before any transport work.

---

## 1. Required conditions

Each is independently selectable and composable.

| ID | Condition | Mechanism | Serves |
|---|---|---|---|
| **H1** | 150 ms ± 50 ms latency, 20% loss | `tc qdisc … netem delay 150ms 50ms loss 20%` | SC-006 |
| **H2** | Total outbound UDP block | `iptables -A OUTPUT -p udp -j DROP` | FR-002, SC-002 |
| **H3** | WireGuard signature drop | `iptables` match on the fixed handshake prefix | Proves obfuscation, not merely connectivity |
| **H4** | Selective profile block | Per-port and per-signature drop rules, toggleable at runtime | SC-001, SC-004 |
| **H5** | DNS hijack | Redirect port 53 and return forged answers | FR-020 |
| **H6** | Captive portal | Intercept all traffic until a login endpoint is satisfied | US6, FR-026 |
| **H7** | Interface loss and restore | Bring a container interface down/up at will | SC-005 |
| **H8** | Endpoint blocklisting | Drop traffic to a specific endpoint address | SC-008, US4 |
| **H9** | Bandwidth ceiling | `tc tbf` | Detects "handshake succeeded but unusable" (FR-004) |

**H3 and H4 are the ones that matter most.** A harness that only degrades quality proves nothing
about DPI evasion — it must actively drop recognised signatures, or the obfuscation claim is
untested.

---

## 2. Topology

```
[ client container ]---[ simulated UTM ]---[ mock endpoint ]
   dnetd under test      netem + iptables     both server-side cores
                         toggled at runtime   + a plain HTTP origin
```

The mock endpoint runs the same server-side cores the provisioning bootstrap installs, pinned to the
same versions, so Phase 3 and Phase 4 test the real handshake rather than a stub.

---

## 3. Harness contract

| # | Requirement |
|---|---|
| HN-01 | Every condition is toggleable **at runtime**, mid-session, without restarting the client — mid-session blocking is what SC-004 measures |
| HN-02 | Conditions are reproducible: same seed, same behaviour, sufficient for CI |
| HN-03 | The harness reports ground truth (packets dropped, by which rule) so a test can distinguish "obfuscation worked" from "the rule did not fire" |
| HN-04 | Runs unprivileged on the host; container privilege is confined to `NET_ADMIN` |
| HN-05 | Runs in CI on Windows with Docker, and locally with one command |
| HN-06 | No harness component reaches any real external network |

---

## 4. Verification scenarios

Each maps to a success criterion and becomes an integration test.

| ID | Scenario | Conditions | Passes when |
|---|---|---|---|
| HV-01 | Profile selection under selective blocking | H4 blocks two of three | Remaining profile selected; SC-001 |
| HV-02 | UDP fully blocked | H2 | TCP-carrier profile selected and works; SC-002 |
| HV-03 | Obfuscation actually obfuscates | H3 | Profile A connects; plain WireGuard control **fails**. Both assertions required |
| HV-04 | Mid-session profile block | H4 toggled while connected | Traffic flows again within 30 s, unattended; SC-004 |
| HV-05 | Degraded link usability | H1 for one hour | Usable ≥95% of the period; SC-006 |
| HV-06 | Interface loss | H7 | Traffic resumes within 5 s; SC-005 |
| HV-07 | Tier 1 survival | H7 while a transfer is open | Transfer completes uninterrupted on both Tier 1 profiles. **Gates SPIKE-R9** |
| HV-08 | Tier 2 honesty | H7 on the TCP profile | Connection breaks **and** the UI said it would beforehand |
| HV-09 | Endpoint blocklisted | H8 | Migration to another endpoint within 30 s; SC-008 |
| HV-10 | DNS hijack defeated | H5 | Correct resolution and routing despite forged answers |
| HV-11 | Captive portal | H6 | Login reachable, completed, then connection proceeds; US6 |
| HV-12 | Throttled but connected | H9 | Profile judged unusable and another tried; FR-004 |
| HV-13 | No routing loop | Profile A active | Packet counts on the tunnel adapter and physical interface show no re-entry. **Gates SPIKE-R4** |
| HV-14 | Crash restoration | Kill `dnetd` mid-session | Networking identical to pre-installation; SC-016 |

---

## 5. Phase 0 exit gate

Phase 0 is complete when H1–H9 are demonstrable on demand, HN-01 through HN-06 hold, and HV-03 can
be executed with a **deliberately unobfuscated control** that fails — proving the harness can tell
the difference. A harness that passes everything proves nothing.
