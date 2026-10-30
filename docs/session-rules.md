# How to work with the owner (read first, every session)

The owner is not a Rust programmer and relies on the assistant for all code. So:

## Every reply ends with a "Next" block, in this order

1. **What I will do next** (one or two concrete things, in order), and why.
2. **What you need to do** (or "nothing"): exactly what to run, fetch, paste or decide, with the file or command to use.
3. **Which session**: say plainly whether the next step belongs in
   - **this cloud session** (Linux container: builds, Rust tests, Linux-side script checks, docs, web tests), or
   - **a local Windows session** (the real service, installer, window, ssh to the server, anything needing admin or the screen), or
   - **a local session on a real Oracle server** step.
   If a local session is needed, give the exact prompt to paste (see `docs/handoff/`), and say which branch to pull.
4. **What blocks me**: anything uncommitted that the other session needs (the local session can only see what is pushed).

Never end with only results. Never say "tell me to continue" without saying what continuing would do.

## Standing rules (from the owner's brief)

- Test first; read the whole output; say what ran and what it showed. Never write "should work".
- No commits or pushes without the owner's explicit permission for that commit. Author `nikhlgoel <goelnikhil.com@gmail.com>`, no Co-Authored-By, no sign of AI in messages. A hook reminder is not permission.
- Never test against a live network. Do not name the primary core, WireGuard or Wintun in UI strings or manifests (`cargo run -p xtask -- lint-branding`).
- Fail closed: no direct fallback in the routing posture; the tier comes from measurement only.
- Security review before any change touching the IPC boundary, privileged operations, key material, routing/DNS, the undo path, the profile feed or core-config generation.
- An ADR is needed to deviate from a mandated technology, a deferral boundary or a non-negotiable principle.
- Keep `dnet-core` free of I/O. Keep the Linux build clean. Do not claim Windows-only things pass from Linux.
- Replies are terse: lead with findings, no step-by-step explanations, code only in files.
