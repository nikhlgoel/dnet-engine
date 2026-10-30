# Local commands

Run from the repository root in PowerShell. Each command saves its output to `.local-logs\<number>.log`.
"(admin)" means an elevated PowerShell. Replace `<...>` before running.

## 0. Once per terminal

0.1 Define `run` (saves each command's output to `.local-logs`)
```powershell
function run { powershell -NoProfile -ExecutionPolicy Bypass -File testing\log.ps1 @args }
```

## 1. Build and test

1.1 Fetch and verify the vendored cores
```powershell
run 1.1 "cargo run -p xtask -- fetch-vendor; cargo run -p xtask -- verify-vendor"
```

1.2 Format check
```powershell
run 1.2 "cargo fmt --all --check"
```

1.3 Clippy, whole workspace
```powershell
run 1.3 "cargo clippy --workspace --all-targets -- -D warnings"
```

1.4 All tests
```powershell
run 1.4 "cargo test --workspace --no-fail-fast"
```

1.5 Elevated tests: routes, file permissions, undo recovery (admin)
```powershell
run 1.5 "cargo test -p dnet-netstate -p dnet-config -p dnetd -- --ignored"
```

1.6 Coverage of the four crates not yet in CI
```powershell
run 1.6 "cargo llvm-cov -p dnet-supervisor -p dnet-netstate -p dnet-etw -p dnet-provision --summary-only"
```

1.7 Web view
```powershell
run 1.7 "cd apps\dnet-tray; pnpm install --frozen-lockfile; pnpm check; pnpm test; pnpm build"
```

1.8 Dependency advisories
```powershell
run 1.8 "cargo audit"
```

## 2. Check today's Windows-only fixes

2.1 ETW: a session left behind by a crash is taken back (admin)
```powershell
run 2.1 "logman create trace DNetEngineAttribution -rt -ets; cargo test -p dnet-etw -- --ignored; logman query DNetEngineAttribution -ets"
```

2.2 Control pipe and client: identity and owner checks on a real pipe (admin)
```powershell
run 2.2 "cargo test -p dnet-ipc; cargo test -p dnetctl"
```

## 3. Gates (see docs/owner-gates.md before running)

3.1 Build the routing-loop runner (admin)
```powershell
run 3.1 "cargo build --release -p dnet-netstate --example spike_r4"
```

3.2 Routing-loop gate, Profile A, as SYSTEM (admin; results in testing\spike-r4\results)
```powershell
run 3.2 "psexec -accepteula -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$PWD\testing\spike-r4\Invoke-SpikeR4.ps1' -EndpointIp <vm-ip> -SkipBuild"
```

3.3 Same, with an interface change (phone tethered) (admin)
```powershell
run 3.3 "psexec -accepteula -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$PWD\testing\spike-r4\Invoke-SpikeR4.ps1' -EndpointIp <vm-ip> -AltGateway <tether-gateway> -SkipBuild"
```

3.4 Routing-loop gate, Hysteria 2 (admin)
```powershell
run 3.4 "psexec -accepteula -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$PWD\testing\spike-r4\Invoke-SpikeR4.ps1' -EndpointIp <vm-ip> -Transport Hy2 -SkipBuild"
```

3.5 Hysteria 2 with an interface change (admin)
```powershell
run 3.5 "psexec -accepteula -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$PWD\testing\spike-r4\Invoke-SpikeR4.ps1' -EndpointIp <vm-ip> -Transport Hy2 -AltGateway <tether-gateway> -SkipBuild"
```

3.6 Show the latest gate summaries
```powershell
run 3.6 "Get-ChildItem testing\spike-r4\results -Recurse -Filter summary.md | Sort-Object FullName | Select-Object -Last 4 | Select-String -Pattern '.'"
```

## 4. New: aggressive speed mode (Brutal, T105)

4.1 Build the service and the command-line tool
```powershell
run 4.1 "cargo build -p dnetd -p dnetctl"
```

4.2 Start the service as SYSTEM in the background (admin; it uses your real saved settings)
```powershell
run 4.2 "psexec -accepteula -s -d '$PWD\target\debug\dnetd.exe' --console --allow-untrusted-install --no-path-watch"
```

4.3 Turn the mode on and off through dnetctl (admin)
```powershell
run 4.3 ".\target\debug\dnetctl.exe profiles; .\target\debug\dnetctl.exe brutal-on hy2-default --up 50 --down 200; .\target\debug\dnetctl.exe brutal-on hy2-default --up 50 --down 200 --accept-warning; .\target\debug\dnetctl.exe profiles; .\target\debug\dnetctl.exe brutal-off hy2-default; .\target\debug\dnetctl.exe profiles"
```

4.4 Build and lint the window
```powershell
run 4.4 "cd apps\dnet-tray; pnpm build; cargo clippy --manifest-path src-tauri\Cargo.toml -- -D warnings"
```

4.5 Open the window, go to Settings, try the mode on and off, then close it (admin)
```powershell
run 4.5 "cargo run --manifest-path apps\dnet-tray\src-tauri\Cargo.toml"
```

4.6 Stop the service started in 4.2 (admin)
```powershell
run 4.6 "taskkill /im dnetd.exe /f"
```

## 5. New: your own routing rules (T108)

5.1 Add, list and remove a rule through dnetctl, with the service from 4.2 running (admin)
```powershell
run 5.1 ".\target\debug\dnetctl.exe rules; .\target\debug\dnetctl.exe add-rule --suffix example.com --bypass; .\target\debug\dnetctl.exe rules; .\target\debug\dnetctl.exe add-rule --cidr 198.18.0.0/16 --tunnel; .\target\debug\dnetctl.exe --json rules"
```

5.2 Remove the rule added in 5.1 (replace <id> with the RULE column from 5.1)
```powershell
run 5.2 ".\target\debug\dnetctl.exe remove-rule <id>; .\target\debug\dnetctl.exe rules"
```

5.3 Open the window, go to Rules, add and remove a rule, then close it (admin)
```powershell
run 5.3 "cargo run --manifest-path apps\dnet-tray\src-tauri\Cargo.toml"
```

## 6. New: stays on after restart (T147), keeps trying (T148), service self-install (T114)

6.1 The new tests on Windows
```powershell
run 6.1 "cargo test -p dnetd t147; cargo test -p dnetd t148; cargo test -p dnetd keep_trying; cargo test -p dnetd install::; cargo test -p dnetd nothing_is_changed_while; cargo test -p xtask stage_installer"
```

6.2 Lint the service for Windows, and the branding check over the new installer files
```powershell
run 6.2 "cargo clippy -p dnetd -p xtask --all-targets -- -D warnings; cargo run -p xtask -- lint-branding"
```

## 7. New: the installer (T114). Sections 7.3 onwards on a Windows 11 VM with a snapshot

7.1 Stage the payload (needs 1.1 done once; verifies, builds release `dnetd`/`dnetctl`, copies)
```powershell
run 7.1 "cargo run -p xtask -- stage-installer"
```

7.2 Build the installer and show its size and SHA-256 (limit 60 MB)
```powershell
run 7.2 "cd apps\dnet-tray; pnpm install --frozen-lockfile; pnpm installer; Get-ChildItem src-tauri\target\release\bundle\nsis\*-setup.exe | ForEach-Object { '{0}  {1:N1} MB' -f `$_.Name, (`$_.Length/1MB); (Get-FileHash `$_.FullName).Hash }"
```

7.3 Network state before installing (VM, admin; compared with 7.8)
```powershell
run 7.3 "route print; Get-DnsClientServerAddress | Format-Table -AutoSize | Out-String -Width 200; Get-NetAdapter | Format-Table Name,InterfaceDescription,Status -AutoSize | Out-String -Width 200"
```

7.4 Install silently, then check the service, its recovery actions, the folders and their owners (VM, admin)
```powershell
run 7.4 "`$exe = (Get-ChildItem apps\dnet-tray\src-tauri\target\release\bundle\nsis\*-setup.exe)[0].FullName; (Start-Process -Wait -PassThru -FilePath `$exe -ArgumentList '/S').ExitCode; sc.exe qc DNetEngine; sc.exe qfailure DNetEngine; sc.exe query DNetEngine; Get-ChildItem 'C:\Program Files\DNet Engine' | Format-Table Name,Length -AutoSize | Out-String; icacls 'C:\Program Files\DNet Engine'; icacls 'C:\ProgramData\DNet Engine'; icacls 'C:\ProgramData\DNet Engine\run'; icacls 'C:\ProgramData\DNet Engine\state'; Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Out-String"
```

7.5 Turn it on with the installed CLI, then restart Windows (VM, admin; needs an endpoint added as in 5.x)
```powershell
run 7.5 "& 'C:\Program Files\DNet Engine\dnetctl.exe' connect; & 'C:\Program Files\DNet Engine\dnetctl.exe' status; Get-Content 'C:\ProgramData\DNet Engine\state\connection-intent.json'; Restart-Computer -Confirm"
```

7.6 After the restart: it should be connected again without anyone pressing anything (VM, admin)
```powershell
run 7.6 "Start-Sleep 60; & 'C:\Program Files\DNet Engine\dnetctl.exe' status; & 'C:\Program Files\DNet Engine\dnetctl.exe' --json events; Get-WinEvent -LogName System -MaxEvents 200 | Where-Object Message -match 'DNet Engine' | Format-List TimeCreated,Message | Out-String -Width 200"
```

7.7 Crash recovery: kill the service; the SCM should restart it and it should reconnect (VM, admin)
```powershell
run 7.7 "taskkill /im dnetd.exe /f; Start-Sleep 45; sc.exe query DNetEngine; & 'C:\Program Files\DNet Engine\dnetctl.exe' status"
```

7.8 Uninstall silently, then the same network state as 7.3 (VM, admin)
```powershell
run 7.8 "(Start-Process -Wait -PassThru -FilePath 'C:\Program Files\DNet Engine\uninstall.exe' -ArgumentList '/S').ExitCode; Start-Sleep 5; sc.exe query DNetEngine; Test-Path 'C:\Program Files\DNet Engine\dnetd.exe'; route print; Get-DnsClientServerAddress | Format-Table -AutoSize | Out-String -Width 200; Get-NetAdapter | Format-Table Name,InterfaceDescription,Status -AutoSize | Out-String -Width 200"
```

7.9 Refuses a data folder someone else owns (VM: run 7.9a as an ordinary user, then 7.9b as admin)
```powershell
run 7.9a "New-Item -ItemType Directory 'C:\ProgramData\DNet Engine' -Force | Out-Null; icacls 'C:\ProgramData\DNet Engine'"
```
```powershell
run 7.9b "`$exe = (Get-ChildItem apps\dnet-tray\src-tauri\target\release\bundle\nsis\*-setup.exe)[0].FullName; (Start-Process -Wait -PassThru -FilePath `$exe -ArgumentList '/S').ExitCode; sc.exe query DNetEngine"
```

7.10 Sleep and wake while on: put the VM to sleep for 2 minutes, wake it, then check it reconnected by itself (VM, admin)
```powershell
run 7.10 "& 'C:\Program Files\DNet Engine\dnetctl.exe' status; rundll32.exe powrprof.dll,SetSuspendState 0,1,0; Start-Sleep 90; & 'C:\Program Files\DNet Engine\dnetctl.exe' status; & 'C:\Program Files\DNet Engine\dnetctl.exe' --json events"
```

## 8. New: the guided server setup (T149 to T151)

8.1 The new tests, Rust side (whole workspace; includes the script checks that run `sh`)
```powershell
run 8.1 "cargo test -p dnet-provision -p dnet-ipc -p dnet-view -p dnetd -p xtask"
```

8.2 The new tests, window side
```powershell
run 8.2 "cd apps\dnet-tray; pnpm install --frozen-lockfile; pnpm check; pnpm test; pnpm build"
```

8.3 Build the Linux server programs and their list (needs Go; takes a few minutes; downloads the pinned sources)
```powershell
run 8.3 "cargo run -p xtask -- build-server-cores --base-url https://example.invalid/releases/download/local/; Get-Content target\server-cores\server-pins.json"
```

8.4 Put the list beside a development service so the window can prepare a script (admin; replaces `--base-url` with where you host the files for a real run)
```powershell
run 8.4 "Copy-Item target\server-cores\server-pins.json target\debug\server-pins.json -Force; Get-Item target\debug\server-pins.json | Format-List Name,Length"
```

8.5 Print the script the window would show, for a real AMD server (read it before running it anywhere)
```powershell
run 8.5 "cargo run -p dnet-provision --example dump_script -- target\server-cores\server-pins.json amd64"
```

8.6 Then follow `docs/owner-gates.md` section "T149-T151": the window's guide, on a real Oracle account.

