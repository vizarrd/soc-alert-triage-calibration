# Matched comparison for Table III: all-draw vs certified coverage over the SAME scenarios.
# Certified coverage is only defined for scenarios with >= 100 certified draws (of 1,000) at a given k, so the
# all-draw number must be computed over exactly those scenarios to be comparable. Also report the scenario list.
# Noise cleared and fallback (reported over all 8 scenarios in the paper) are shown for the matched subset too.
# Source: 23_per_cell_results.csv, model = LogReg, rho = 0.90, rule = guaranteed.
$rows = Import-Csv "$PSScriptRoot\23_per_cell_results.csv" | Where-Object { $_.model -eq 'LogReg' -and $_.rho -eq '0.9' -and $_.rule -eq 'guaranteed' }
"k | scenarios used | all-draw cov (same scenarios) | certified cov (same scenarios) | cleared (same) | fallback (same) || ALL 8: all-draw cov | cleared | fallback"
foreach ($k in 50,100,200,500,1000) {
  $r = $rows | Where-Object { [int]$_.k -eq $k }
  $used = $r | Where-Object { (1 - [double]$_.fallback) * 1000 -ge 100 }
  $allcov = ($used | ForEach-Object { [double]$_.coverage } | Measure-Object -Average).Average
  $certsucc = 0.0; $certn = 0.0
  foreach ($x in $used) { $nc = (1-[double]$x.fallback)*1000; $certn += $nc; $certsucc += ([double]$x.coverage - [double]$x.fallback)/(1-[double]$x.fallback)*$nc }
  $cleared = ($used | ForEach-Object { [double]$_.cleared } | Measure-Object -Average).Average
  $fb = ($used | ForEach-Object { [double]$_.fallback } | Measure-Object -Average).Average
  $a8 = ($r | ForEach-Object { [double]$_.coverage } | Measure-Object -Average).Average
  $c8 = ($r | ForEach-Object { [double]$_.cleared } | Measure-Object -Average).Average
  $f8 = ($r | ForEach-Object { [double]$_.fallback } | Measure-Object -Average).Average
  "{0} | {1} ({2}) | {3:N5} | {4:N5} | diff={10:N5} | {5:N2} | {6:N2} || {7:N3} | {8:N2} | {9:N2}" -f $k, $used.Count, (($used | ForEach-Object { $_.scenario }) -join ','), $allcov, ($certsucc/$certn), $cleared, $fb, $a8, $c8, $f8, ($allcov - ($certsucc/$certn))
}
