<#
.SYNOPSIS
  Measure the memory of a program and everything it starts, in three phases.

.DESCRIPTION
  Starts -Exe with SPIKE_SCRIPT=1 (the spikes then open a window 15 s in and destroy it at 45 s),
  samples the whole process tree every 2 s for -Seconds, and reports the median of each phase.

  The figure that matters is PRIVATE working set: what Task Manager calls Memory, which does not
  count a shared library once per process. Working set (the RSS of the budget, SC-013) is reported
  beside it because it is what the requirement says, and it overstates a tree that shares pages.

  Phases:  tray only (1-14 s) | window open (22-44 s) | window destroyed (58-end)
  Sampling is about every 3 s (each query of the performance counters takes a while), so a phase
  holds only a few samples; the first one is also slow, which is why it is not skipped.
#>
param(
  [Parameter(Mandatory)][string]$Exe,
  [int]$Seconds = 85,
  [string]$Label = 'spike'
)

$ErrorActionPreference = 'Stop'

function Get-Tree([int]$RootId) {
  $all = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId
  $ids = [System.Collections.Generic.HashSet[int]]::new()
  [void]$ids.Add($RootId)
  $grew = $true
  while ($grew) {
    $grew = $false
    foreach ($p in $all) {
      if ($ids.Contains([int]$p.ParentProcessId) -and $ids.Add([int]$p.ProcessId)) { $grew = $true }
    }
  }
  $ids
}

$env:SPIKE_SCRIPT = '1'
$proc = Start-Process -FilePath $Exe -PassThru
$start = Get-Date
$rows = @()
try {
  while (((Get-Date) - $start).TotalSeconds -lt $Seconds) {
    Start-Sleep -Seconds 2
    if ($proc.HasExited) { throw "the program exited early (code $($proc.ExitCode))" }
    $t = [int]((Get-Date) - $start).TotalSeconds
    $ids = Get-Tree $proc.Id
    $perf = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
      Where-Object { $ids.Contains([int]$_.IDProcess) }
    $rows += [pscustomobject]@{
      T         = $t
      Processes = @($perf).Count
      PrivateMB = [math]::Round((($perf | Measure-Object WorkingSetPrivate -Sum).Sum) / 1MB, 1)
      WorkingMB = [math]::Round((($perf | Measure-Object WorkingSet -Sum).Sum) / 1MB, 1)
    }
  }
}
finally {
  Get-Tree $proc.Id | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
  Remove-Item Env:SPIKE_SCRIPT -ErrorAction SilentlyContinue
}

function Median($v) { $s = $v | Sort-Object; $s[[int][math]::Floor(($s.Count - 1) / 2)] }

$phases = [ordered]@{
  'tray only'        = { $_.T -ge 1 -and $_.T -le 14 }
  'window open'      = { $_.T -ge 22 -and $_.T -le 44 }
  'window destroyed' = { $_.T -ge 58 }
}
"[$Label] $Exe"
foreach ($name in $phases.Keys) {
  $sel = @($rows | Where-Object $phases[$name])
  if ($sel.Count -eq 0) { "  {0,-17} no samples" -f $name; continue }
  "  {0,-17} processes {1,2}   private {2,6} MB   working set {3,6} MB   ({4} samples)" -f `
    $name, (Median $sel.Processes), (Median $sel.PrivateMB), (Median $sel.WorkingMB), $sel.Count
}
$rows | Export-Csv -NoTypeInformation -Path (Join-Path (Split-Path $Exe) "$Label-samples.csv")
