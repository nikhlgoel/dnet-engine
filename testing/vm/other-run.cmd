@echo off
rem Run in the guest by guard-checks.ps1: the same program as the core's stand-in (curl), but at another path, as the
rem lab account. With the guard on it must be refused. The result is written for the host to read.
C:\Windows\System32\curl.exe -sS -m 6 -o NUL https://1.1.1.1/ > C:\lab\other.out 2>&1
echo exit=%errorlevel% >> C:\lab\other.out
