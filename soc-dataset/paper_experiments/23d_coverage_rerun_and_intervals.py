"""Quantifies the finite-simulation uncertainty of the coverage estimates (exp. 23/23b).

Part 1: Wilson 95% intervals for certified coverage in every setting of exp. 23 with >= 100 certified draws,
        plus pooled coverage over all certified draws (is the guarantee violated beyond Monte Carlo error?).
Part 2: re-run the two settings that fell below target (santos/LogReg/k=100/rho=0.80 and shaw/RF/k=200/rho=0.90)
        with 10,000 independent labelling draws, evaluating recall on the alerts EXCLUDED from the labelled
        sample (not on the whole stream), counting certified draws only, with Wilson intervals.
Models are refit with a fresh training sample (seed 7), so this is also an independent replication."""
import numpy as np, pandas as pd
from scipy.stats import beta, binomtest

def wilson(k, n, z=1.96):
    if n == 0: return (np.nan, np.nan)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h, c + h)

# ---------------- Part 1 ----------------
r = pd.read_csv('23_per_cell_results.csv')
g = r[r.rule == 'guaranteed'].copy()
g['n_cert'] = ((1 - g.fallback) * 1000).round().astype(int)
g = g[g.n_cert >= 100].copy()
g['cert_cov'] = (g.coverage - g.fallback) / (1 - g.fallback)
g['succ'] = (g.cert_cov * g.n_cert).round().astype(int)
g[['lo', 'hi']] = [wilson(s, n) for s, n in zip(g.succ, g.n_cert)]
g['target'] = 0.90   # nominal COVERAGE level is 1 - delta = 0.90 for every rho (rho is the RECALL target)
print("Part 1: settings whose certified coverage is below the nominal 0.90:")
below = g[g.cert_cov < g.target]
print(below[['scenario', 'model', 'k', 'rho', 'cert_cov', 'n_cert', 'lo', 'hi']].round(3).to_string())
print(f"Wilson 95% interval reaches the nominal 0.90 in {(below.hi >= below.target).sum()}/{len(below)} of these.")
print(f"settings with certified coverage CI entirely below the (1-delta)=0.90 nominal level: {int((g.hi < 0.90).sum())} of {len(g)}")
tot_s, tot_n = int(g.succ.sum()), int(g.n_cert.sum())
lo, hi = wilson(tot_s, tot_n)
print(f"\nPooled over all {len(g)} settings: {tot_s:,}/{tot_n:,} certified draws met their recall target "
      f"= {tot_s/tot_n:.4f} (95% Wilson [{lo:.4f}, {hi:.4f}]); nominal guarantee >= 0.90")

# ---------------- Part 2 ----------------
import sys
src = open('23_large_scale_guarantee_validation.py').read().split("rows = []\nfor held in sorted(set(scen)):")[0]
ns = {}; exec(src, ns)
scen, X, y_all, fit_score, df = ns['scen'], ns['X'], ns['y_all'], ns['fit_score'], ns['df']
best_r = ns['best_r']
rng = np.random.default_rng(7)
DRAWS = 10000

def thr_guar_remainder(sl, yl, rho):
    pos = np.sort(sl[yl]); r_ = best_r(len(pos), rho)
    return (-np.inf, True) if r_ == 0 else (pos[r_ - 1], False)

def rerun(held, model, k, rho):
    te = scen == held; tr_idx = np.where(~te)[0]
    sub = np.concatenate([rng.choice(tr_idx[scen[tr_idx] == s], min(10000, (scen[tr_idx] == s).sum()), replace=False)
                          for s in sorted(set(scen)) if s != held])
    s = fit_score(model, X.iloc[sub], y_all[sub], X[te]); y = y_all[te]; N = len(s)
    sp = np.sort(s[y]); P = len(sp)
    ok = tot = fb = 0
    for _ in range(DRAWS):
        idx = rng.choice(N, k, replace=False); sl, yl = s[idx], y[idx]
        t, fallback = thr_guar_remainder(sl, yl, rho)
        if fallback: fb += 1; continue
        # recall on alerts NOT in the labelled sample
        n_pos_ge = P - np.searchsorted(sp, t, 'left')
        lab_pos_ge = int(((sl >= t) & yl).sum())
        rec = (n_pos_ge - lab_pos_ge) / (P - int(yl.sum()))
        tot += 1; ok += rec >= rho
    lo, hi = wilson(ok, tot)
    print(f"{held}/{model}/k={k}/rho={rho}: certified draws {tot}/{DRAWS} (fallback {fb/DRAWS:.2f}); "
          f"coverage on held-out remainder = {ok/max(tot,1):.4f}  95% Wilson [{lo:.4f}, {hi:.4f}]")

print("\nPart 2: re-runs with 10,000 draws, recall on the unlabelled remainder, certified draws only")
rerun('santos', 'LogReg', 100, 0.80)
rerun('shaw', 'RF', 200, 0.90)
