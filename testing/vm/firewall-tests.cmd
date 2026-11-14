@echo off
rem Run in the guest by the host: the two tests of dnetd that put the real guard into the real firewall.
rem   firewall-tests.cmd 1   runs them (the lab switch on)
rem   firewall-tests.cmd 0   shows that without the switch they skip and change nothing
rem They are #[ignore]d and also refuse to run unless DNET_LAB_VM is exactly 1, so that `cargo test -- --ignored`
rem on a person's own computer never changes its firewall (ADR-0006 section 5a, condition 5).
rem The test binary is put at C:\lab\bin\dnetd_tests.exe first (see README.md).
set DNET_LAB_VM=%1
for %%T in (
  guard_control::real_firewall::the_real_guard_goes_in_reads_as_in_and_comes_out
  recovery::windows_ops::tests::a_guard_left_by_a_crashed_run_is_kept_at_the_next_start_when_the_switch_is_on_and_removed_when_off
) do (
  C:\lab\bin\dnetd_tests.exe --ignored --exact %%T --nocapture > C:\lab\fw.out 2>&1
  findstr /C:"skipped: this changes the firewall" /C:"test result" /C:"panicked" C:\lab\fw.out
)
C:\lab\bin\guard_lab.exe status
