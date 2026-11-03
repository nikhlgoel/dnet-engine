# Starting the local Windows session

Do this once on your Windows laptop (needs Git, Rust, Node 22 + pnpm, Go, and PowerShell as administrator):

1. `git clone https://github.com/nikhlgoel/dnet-engine.git` then `cd dnet-engine` then `git checkout wip`
   (or `git pull` on `wip` if you already have it). The local session only sees what has been pushed.
2. Start Claude Code in that folder, as an administrator PowerShell.
3. Paste the prompt below.

## The prompt

> Read `docs/session-rules.md` and `LOCAL-COMMANDS.md` first. You are the Windows session for DNet Engine. A cloud Linux session did the Rust and web work and could not run anything on Windows. Your job is to run what only Windows can, read every log yourself, and fix what fails, test first.
>
> Do these in order, one at a time, and after each say what ran, what it showed, and what is next:
> 1. Section 0 and 1 of `LOCAL-COMMANDS.md` (define `run`, fetch the cores, fmt, clippy, tests). Fix any failure test-first.
> 2. Section 1.5 (the ignored admin tests: routes, file permissions, undo recovery) and section 2.
> 3. Sections 4 and 5 (service, window, brutal, rules) with a development service.
> 4. Section 10, 10.8 to 10.12, with the same development service: a new server waits for approval, the Windows prompt approves it, a change that could not be made is refused with no prompt, and the window says "waits for your approval" instead of an error. I answer the Windows prompt and type `yes`; ask me when it is time.
> 5. Section 7.1 to 7.2: stage and build the installer, report its size.
> 6. Only then, on a VM with a snapshot, section 7.3 onwards (install, reboot, crash, uninstall).
>
> Read the logs in `.local-logs` yourself; do not ask me to paste them. Do not commit or push unless I say so. Do not touch a live network other than my own home connection and my own server. When something needs a decision or a thing from me (a server address, a key file), stop and tell me exactly what.
>
> End every reply with the "Next" block from `docs/session-rules.md`.
