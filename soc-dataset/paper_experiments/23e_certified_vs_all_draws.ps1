# Table-III companion: for the guaranteed rule (LogReg, rho = 0.90), by number of labels k, report
#   - coverage over ALL draws (fallback draws count as successes; an "operational success rate")
#   - coverage among CERTIFIED draws only (the nontrivial check of the threshold rule), pooled over the
#     scenarios with >= 100 certified draws of 1,000, with the number of certified draws and a 95% Wilson interval
# Source: 23_per_cell_results.csv (exp. 23). Pooling treats draws as independent (descriptive: draws within a
# setting share one fitted model and stream).
function Wilson($k, $n) {
  $z = 1.96; $p = $k / $n; $d = 1 + $z*$z/$n
  $c = ($p + $z*$z/(2*$n)) / $d; $h = $z * [math]::Sqrt($p*(1-$p)/$n + $z*$z/(4*$n*$n)) / $d
  return @(($c-$h), ($c+$h))
}
$rows = Import-Csv "$PSScriptRoot\23_per_cell_results.csv" | Where-Object { $_.model -eq 'LogReg' -and $_.rho -eq '0.9' -and $_.rule -eq 'guaranteed' }
"k | all-draw cov (mean over 8 scenarios) | cells used | certified draws | certified successes | certified cov [95% Wilson] | mean fallback"
foreach ($k in 50,100,200,500,1000) {
  $r = $rows | Where-Object { [int]$_.k -eq $k }
  $allcov = ($r | ForEach-Object { [double]$_.coverage } | Measure-Object -Average).Average
  $fb = ($r | ForEach-Object { [double]$_.fallback } | Measure-Object -Average).Average
  $nc = 0; $succ = 0.0; $cells = 0
  foreach ($x in $r) {
    $ncert = (1 - [double]$x.fallback) * 1000
    if ($ncert -ge 100) { $cells++; $nc += $ncert; $succ += ([double]$x.coverage - [double]$x.fallback) / (1 - [double]$x.fallback) * $ncert }
  }
  if ($nc -gt 0) { $w = Wilson $succ $nc; $cc = $succ / $nc }
  "{0} | {1:N3} | {2} | {3:N0} | {4:N0} | {5:N3} [{6:N3}, {7:N3}] | {8:N2}" -f $k, $allcov, $cells, $nc, $succ, $cc, $w[0], $w[1], $fb
}
