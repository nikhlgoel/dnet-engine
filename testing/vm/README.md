# The lab VM

A throwaway Windows 11 for the tests that must not run on a person's own computer: routes, the firewall guard
(T161), install and uninstall, sleep and resume. ADR-0006 §5a condition 5 says nothing that changes the firewall goes
onto a real machine before it has run in a virtual one with a snapshot. This is that machine.

It needs **no elevation and no system-wide install**: QEMU is unpacked into a folder and uses the Windows Hypervisor
Platform that Windows already has (the same one WSL2 and Docker use). Everything lives under `D:\vm` (set
`DNET_VM_DIR` to move it); only these scripts are in the repository. No image, key or password is committed.

```
D:\vm\iso\win11-ent-eval-*.iso     Microsoft's 90-day evaluation image (Enterprise, en-US, build 26300)
D:\vm\qemu\                        QEMU, unpacked from its installer (never run)
D:\vm\win11-lab\disk.qcow2         the guest's disk (60 GB, grows as used)
D:\vm\win11-lab\keys\              the key the host uses to reach the guest over SSH
D:\vm\win11-lab\lab-credentials.txt the guest's local account (a throwaway; not in the repository)
```

## Making it

1. The evaluation ISO is downloaded from the Evaluation Center link on
   <https://www.microsoft.com/evalcenter/download-windows-11-enterprise> (8.2 GB; resume with `curl -C -`).
2. QEMU for Windows from <https://qemu.weilnetz.de/w64/>. Its installer asks for administrator rights, so it is not
   run: it is unpacked with `7z` (inside a throwaway container: `docker run --rm -v ...:/in -v ...:/out alpine sh -c
   "apk add 7zip && 7z x /in/qemu-setup.exe -o/out"`).
3. `autounattend.xml` is built from `unattend.template.xml` (the password is filled in from
   `lab-credentials.txt`), put with `lab_setup.ps1` and the public key into `answer.iso` (`mkisofs`), and attached as a
   second CD. Windows Setup finds it, installs unattended, creates the `lab` account, and `lab_setup.ps1` turns on SSH
   with the key as the only way in.
4. `.\lab.ps1 start -Install`. About ten minutes.

## Using it

```powershell
.\lab.ps1 start                       # boot the installed guest
.\lab.ps1 status                      # running? does SSH answer?
.\lab.ps1 ssh "whoami /groups"        # runs elevated (the lab account is an administrator)
.\lab.ps1 put target\debug\x.exe C:\lab\bin
.\lab.ps1 snapshot clean              # while stopped; `restore clean` goes back
.\lab.ps1 shot                        # a screenshot of the guest's screen
.\lab.ps1 stop
```

The guest reaches this computer's localhost (including the Docker harness's ports) at **10.0.2.2**. This computer
reaches the guest's SSH at 127.0.0.1:2222.

## What this hardware needed (measured, not assumed)

- **Two virtual CPUs and a fixed CPU model.** Windows 11 Setup refuses a machine with fewer than two cores, and the
  Windows 11 bypass keys in the answer file do not cover that check. With `-cpu host` the guest hung with every
  virtual CPU at 100% (the host is a hybrid performance/efficiency-core processor, and QEMU warned `failed to get
  xsave state`); with one CPU it ran but Setup refused it. `-cpu Haswell-noTSX,-hypervisor -smp 2` with the
  hypervisor-side interrupt controller (`kernel-irqchip=on`) installs and runs.
- **The CD drives on the machine's own ports** (`bus=ide.0`, `ide.1`). A separately added AHCI controller left the
  firmware stuck.
- **No TPM, no Secure Boot**: Setup's checks for them are bypassed in the answer file (`LabConfig`). The guest is a lab
  machine, not a model of a customer's.
- **The firmware logo with one moving dot is Windows booting**, not the firmware hanging. The firmware's own debug log
  (`-debugcon`, written to `ovmf-debug.log`) shows it handing over to the boot loader.
- The network is QEMU's user-mode network: no driver, no administrator rights, and no bridge to the real network.

## What it cannot show

It is one machine with a virtual network card. It says nothing about a real network card's offloads, a real Wi-Fi
adapter, a real captive portal, a real VPN-blocking network, or sleep on real hardware. Those stay the owner's
(`docs/owner-gates.md`).
