# Starting the local Windows session

Do this on your Windows laptop (needs Git, Rust, Node 22 + pnpm, Go, and PowerShell as administrator):

1. In your clone (`D:\main\projects\personal\dnet-engine`): `git fetch --all`, then `git checkout wip`, then `git pull`.
   The local session only sees what has been pushed.
2. Start Claude Code in that folder, from an administrator PowerShell.
3. Paste the prompt below.

## The prompt (state of 2026-11-04)

> Read `docs/session-rules.md` first, then `LOCAL-COMMANDS.md`. You are the local Windows session for DNet Engine; the cloud Linux session has handed the work over to you. Run `git fetch --all`, `git checkout wip`, `git pull`, and check that `git log -1` shows "docs: hand the work over to the Windows session" or a later commit.
>
> **Where the work stands.** The last cloud batch is on `wip`, ahead of `master`; no pull request is open, and CI runs only on pull requests and on `master`.
> - T160 (a): a change the service holds for approval is no longer shown as a refusal. The window has a fifth outcome code, `ApprovalRequired`. The guided setup waits in place with an Approve button and goes on by itself once the server is listed; Servers and Rules say the change "waits for your approval above".
> - The service refuses at once a held change that applying would refuse (a wrong paste, an expired setup, a name in use, a program rule, a connection that is up), so no Windows prompt is raised for it. A feed import is still held unchecked.
> - The dock's icon-only links (a window narrower than 760 px) now have names for screen readers.
> - Verified on Linux only: 2184 Rust tests pass (one fails only in the container: `checks::tests::silence_is_unknown_never_unreachable`), 282 web tests, clippy for the Windows target, mutation tests. **Nothing has run on real Windows.** The details are under T160 and T111 in `specs/001-network-resilience-client/tasks.md`.
>
> **Do these in order, one at a time; after each, say what ran, what it showed and what is next:**
> 1. `LOCAL-COMMANDS.md` sections 0 and 1 (1.1 to 1.4, and 1.7): fetch the cores, fmt, clippy, every test, and the window's check, tests and build. Fix any failure test first. `silence_is_unknown_never_unreachable` should pass on Windows; if it does not, find out why.
> 2. 4.1 and 4.2 (build, then start the development service as admin), then section 10, 10.8 to 10.12: a new server waits for approval, the Windows prompt approves it, a change that could not be made is refused with no prompt (10.11), and the window says "waits for your approval above" instead of an error (10.12). I answer the Windows prompt and type `yes`: tell me when it is time. 10.12 has no log, so ask me what I saw.
> 3. The sections that have never run on Windows: 1.5 and 2 (the admin tests), the rest of 4 and 5 (Brutal and rules, in the window too), then 7.1 and 7.2 (stage and build the installer, and report its size). Section 7.3 onwards only on a VM with a snapshot, and only when I say so.
> 4. When I say so, open one pull request from `wip` to `master` (one per batch, squash-merged), read every CI job's log, and fix what fails, test first. Then T173's open item: CI warns that Node.js 20 is deprecated. Move each action in `.github/workflows/` to a release that runs on Node 24, checking `runs.using` in that action's own `action.yml` at the tag rather than trusting memory, and confirm it on the pull request's CI.
> 5. Then T170's open item (1), the cores in the live map. The Windows runtime (`crates/dnet-supervisor/src/windows_runtime.rs`) knows a core's process id but not whether it is still alive or how often it restarted, and `crates/dnetd/src/components.rs` leaves the cores out rather than guess. Read both, propose the smallest design that gives each core a true state, and build nothing before I agree.
>
> **Waiting on me; do not start them:** the development-only switch for the rules-by-program lab check (`LOCAL-COMMANDS.md` section 11), a kill-switch filter model before ADR-0006 P3 is approved (T161), the ADR-0001 question of the core's own program matching, and T166 to T168.
>
> **Rules:** test first, and read the whole output; the logs are in `.local-logs`, so read them yourself rather than asking me to paste them. Never test against a live network other than my own connection and my own server. Fail closed. A security review before any commit that touches the IPC boundary, privileged operations, key material, routing, DNS, the undo path, the feed or core-config generation. No commit or push without my say-so; author `nikhlgoel <goelnikhil.com@gmail.com>`, no Co-Authored-By line and no sign of AI. Do not name the primary core, WireGuard or Wintun in UI strings or manifests (`cargo run -p xtask -- lint-branding`). Do not claim a Windows-only thing passes without having run it. Record what you did under its task in `tasks.md`. When something needs a decision or a thing from me (a server address, a key file, a Windows prompt), stop and say exactly what.
>
> End every reply with the "Next" block from `docs/session-rules.md`.
