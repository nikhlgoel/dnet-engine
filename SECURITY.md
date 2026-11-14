# Security policy

## Reporting a problem

Please report a security problem **privately**, not in a public issue or pull request.

Use GitHub's private report form: open the repository's **Security** tab and choose **Report a
vulnerability**. That opens a private conversation with the maintainer.

Private reporting is switched on for this repository, so the button is there. If it ever is not, open a
public issue that says only "I have a security report and need a private way to send it". Do not put
details in it; the maintainer will reply with a private channel.

Please include what you found, the version or commit, and the smallest steps that show it. Do not test
against networks or machines you do not own.

## What to expect

This is a one-person project, so these are targets, not a contract:

- an acknowledgement within **7 days**;
- a plain answer on whether it is accepted as a problem within **30 days**;
- a fix, or a written reason there is none yet, within **90 days**, after which you are free to publish
  your findings (earlier by agreement, for example once a fix is released).

A fix is credited to you if you want that.

## What is in scope

DNet Engine's background service runs with high privilege and is treated as the boundary. The most
useful reports concern:

- the local control pipe: a caller doing something it should not be allowed to do, or input from the
  other end that is not treated as untrusted;
- programs the service starts, and the places they are started from;
- routing and name-server changes, and whether they are undone;
- handling of keys, credentials and the signed profile feed;
- anything that makes traffic leave outside the tunnel when the service says it is protected.

## Supported versions

There is no release yet. Only the `master` branch is supported.
