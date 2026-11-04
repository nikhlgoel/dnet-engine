# Release signing

DNet Engine releases are signed with **the project's own key**, the way an Android app is signed with its own
keystore. It is not a purchased Windows certificate, and it does not make Windows trust the program.

## What the signature does, and does not

| It does | It does not |
|---|---|
| Lets anyone check that a file is unchanged since it was signed, and was signed by *this* key, by comparing the key's published fingerprint | Remove Windows SmartScreen's "unknown publisher" warning: Windows trusts only certificates from its own list of authorities, and the project's key is not on it |
| Keeps a different program from claiming to be this one, for anyone who compares the fingerprint | Prove who the person behind the key is: nobody vouches for that, only the fingerprint is published |

There are two independent checks, and they say different things:

1. **The key signature** (Authenticode). The fingerprint is in `installer/signing-cert.sha256` and
   `installer/dnet-engine-signing.cer`, both in this repository.
2. **The build attestation** (Sigstore, no key to steal). It says the file was built by this repository's
   release workflow at a given commit: `gh attestation verify <file> --repo nikhlgoel/dnet-engine`.

Checking both is stronger than either. The SHA-256 of each installer is also in the release's `SHA256SUMS.txt`.

## Checking a download

```powershell
installer\Test-Signature.ps1 -CertSha256 (Get-Content installer\signing-cert.sha256 -Raw).Trim() <the file>
```

`OK` means signed, unchanged, and by the project's key. `FAIL` says why (not signed, changed after signing, or a
different key). Windows will call the signature "not trusted" in the file's Properties: that is expected.

## What is signed

`dnetd.exe`, `dnetctl.exe`, the tray program and the installer (and its uninstaller). **Not** signed by us: the
third-party transport programs and the adapter library. They are pinned by digest instead (ADR-0004), and the
adapter library carries its own vendor's signature, which must not be replaced.

## One-time: make the key (the owner does this)

```powershell
installer\New-SigningCertificate.ps1
```

It asks for a password (16 or more characters, with at least three of lower case, upper case, digits and symbols: a
stolen key file can be attacked offline), writes `dnet-engine-signing.pfx` (private, AES-256) and `.cer` (public) to
a folder **outside** the repository, removes the key from your certificate store (an exportable copy there would let
any program running as you copy it), and prints the fingerprint and the commands for the next steps. It refuses to
overwrite an existing key, to write inside the repository, and to accept a weak password. Then:

1. Commit the fingerprint and the public certificate (`installer\signing-cert.sha256`,
   `installer\dnet-engine-signing.cer`).
2. Give the release workflow the key as the secrets `SIGN_PFX_BASE64` and `SIGN_PFX_PASSWORD` (the script prints the
   `gh secret set` commands). Put them in a GitHub **Environment** named `release` rather than at repository level
   (`gh secret set ... --env release`), and in the environment's settings allow deployment only from tags matching
   `v*.*.*` and require your own approval. A self-made key cannot be revoked, so who can reach it matters: with
   repository-level secrets, anyone with write access could run a branch that reads them. Add a tag ruleset too, so
   only you can create a `v*` tag.
3. **Back up the `.pfx` and its password offline.** If the key is lost, the project has a new identity: old and new
   releases can no longer be tied together, and everyone must be told the new fingerprint.

The key is valid for ten years. Signatures are timestamped, so a file signed while the key was valid stays
verifiable after it expires. To rotate, make a new key, publish the new fingerprint beside the old one, and say so in
the release notes.

**Where to check the tray program:** Tauri signs it, packs it into the installer, and then restores the loose copy in
the build folder, so that copy carries no signature. Check the installed one: after installing, run
`Test-Signature.ps1` on `C:\Program Files\DNet Engine\dnetd.exe`, `dnetctl.exe` and the tray program.

## How a release uses it

The release workflow signs **only on a release tag**, and only if the secrets exist. A branch build never signs. A tag
without the secrets builds an unsigned installer and says so as a warning in the run; the attestation is made either
way. With the key, the workflow imports it into the runner's certificate store as a key that cannot be exported,
deletes the key file at once, and signs by thumbprint: the password is used by that one step and by nothing after
it. It signs the service and the command-line tool, lets Tauri sign the tray program and the installer
(`bundle.windows.signCommand`), then fails the job unless every file checks out against
`installer/signing-cert.sha256`, and finally removes the key from the runner. A key set without that file is refused:
nothing would say whose it is.

A local build signs with `DNET_SIGN_PFX` and `DNET_SIGN_PFX_PASSWORD` (the key file), or with
`DNET_SIGN_THUMBPRINT` if you kept the key in your store (`-KeepInStore`, at the risk described above). With none of
them set, `installer\Sign-Files.ps1` signs nothing and succeeds.

**What a signature does not cover:** the check does not require a timestamp, so a file signed later with a stolen key
would still pass against the old fingerprint. That follows from the design; the answer is rotation (above). The build
step that signs runs the whole dependency tree (cargo build scripts, the web build) in a job that can use the imported
key, which is why the lockfiles are frozen and dependency install scripts are off.

## Later: a certificate Windows trusts

Not needed to test. When the program is stable, two routes remove the warning: the **SignPath Foundation**
(free signing for open-source projects, by application; it signs with its own certificate after verifying the build
came from this repository), or a purchased code-signing certificate (hundreds of dollars a year, with a hardware
key). Microsoft's own signing service lists individuals in the USA and Canada only. Either replaces the step that
runs `Sign-Files.ps1`; the attestation stays.
