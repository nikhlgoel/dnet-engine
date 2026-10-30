# What DNet Engine sends over the network, and why

Written 2026-10-30 from the constants in the code. **These are worst cases derived from the code, not
measurements on a wire** (nothing here has run on a real connection yet); the tests named below fail if a
constant changes so that a number here is no longer true.

| When | What is sent | Cost | Where it is pinned |
|---|---|---|---|
| Connecting | A race: each of the three methods fetches `RACE_BYTES` (192 KiB) through its own tunnel at once; the first usable wins and the rest are cancelled | at most 576 KiB, usually less (was up to 1.5 MB) | `checks::the_race_asks_for…` (compile-time), `…exactly what they are documented…` |
| Connected, idle: every 5 s | A *sliver*: connect and fetch 1 KiB from the server's tunnel-only origin | about 1 MB an hour with HTTP overhead (was a 128 KiB download every 5 s: about 92 MB an hour) | `a_healthy_tunnel_is_checked_with_a_sliver…`, `an_idle_connection_costs_at_most_two_megabytes…` |
| Connected, idle: every 10 min | One full throughput check (128 KiB) | 0.75 MB an hour | `the_full_check_happens_once_per_interval…` |
| Whenever a sliver comes up short | The full check at once, to decide | 128 KiB, only while something is wrong | `a_short_answer_to_the_sliver_is_settled…` |
| Connected: every 15 s | Opening a connection to the origin, to time it | a few hundred bytes | `orchestrator` timing |
| Connected: every 10 s (carrying) and 30 s (standby networks) | One small probe of the network's gateway | under 100 bytes each | `path_monitor` timing |
| Every 6 h, while a tunnel is up (and 30 min of jitter) | A check for updated method definitions, over the tunnel | one small signed file | `feed::fetch::FETCH_INTERVAL_SECS` |
| While left on and the connection is down | A connect attempt: 15 s, 30 s, 1, 2, 4, then every 5 min, and on a network change but not twice a minute | handshake packets only; no transfer happens until a method connects | `keep_trying` tests |
| The server, idle | Nothing but the keepalive (CPU only, no network, no disk) and a weekly log trim | none | `bootstrap` tests |

## What is deliberately not done

- No telemetry, no usage reports, no update pings of any kind outside the signed-definitions check above.
- No check on a metered connection is treated differently yet (a phone hotspot is counted like any network):
  **not built**, listed as a proposal in `docs/plans/2026-10-30-guided-onboarding.md`.
- The full check is not run while the tunnel is carrying a person's traffic and healthy; a slow degradation that
  still moves a kilobyte in three seconds is found at the next full check, ten minutes at most.

## Leaks

Pinned by `leak_01_every_profile_takes_all_traffic_and_lets_nothing_go_around`, for all three methods: the tunnel
takes all routes (`auto_route`), refuses what would go around it (`strict_route`, which is also what stops IPv6,
which the tunnel does not carry), answers name lookups itself (`dns_mode: hijack`), has no IPv6 address, and the
fallback route is never the open network. Seeded defect: switching `strict_route` off fails it. Other leak
protections already in the specification (encrypted-DNS block, DNS capture first, endpoint bypass first) are
tested in `dnet-core` and `dnetd::plan`. **Not verified on Windows:** that the firewall rules `strict_route`
installs are actually in force (owner step 9.3 in `LOCAL-COMMANDS.md`).
