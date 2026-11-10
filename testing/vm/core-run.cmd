@echo off
rem Run in the guest, as the system account, by guard-checks.ps1: the guard's "core" stand-in (a copy of curl at the
rem path the plan names) makes an outbound connection to an outside address. The result is written for the host to read.
C:\lab\bin\core-standin.exe -sS -m 8 -o NUL -w "%%{http_code}" https://1.1.1.1/ > C:\lab\core.out 2>&1
echo exit=%errorlevel% >> C:\lab\core.out
