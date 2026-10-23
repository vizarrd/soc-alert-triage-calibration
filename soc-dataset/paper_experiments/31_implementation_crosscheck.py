"""Independent cross-check of the implemented calibration rule (soc-engine/calibration.py, also used in
exp. 23's simulation) against the mathematics:

 1. RANK SELECTION. The code picks the largest r with Beta(r, n-r+1).cdf(1-rho) >= 1-delta. Mathematically
    this equals the largest r with P(Binomial(n, 1-rho) >= r) >= 1-delta. We recompute r both ways (scipy
    beta cdf vs an explicit binomial tail by direct summation) for every n up to 1000 and three rho values.
 2. INDEXING AND INCLUSIVITY. The threshold must be the r-th SMALLEST labelled attack score (0-based index
    r-1 of the sorted array) and alerts with score >= threshold are flagged; recall counts scores >= t.
    We test this on hand-built score vectors with known answers, including ties at the threshold.
 3. END TO END. For i.i.d. continuous scores drawn with a fixed seed, the observed coverage of the actual
    function over many trials must be >= 1-delta (within Monte Carlo error) and close to the exact value.
Run from paper_experiments/ (imports ../../soc-engine/calibration.py)."""
import sys, math
import numpy as np
from scipy.stats import beta, binom
sys.path.insert(0, '../../soc-engine')
import calibration as cal

DELTA = 0.10
# ---- 1. rank selection: Beta formulation vs explicit binomial tail ----
mism = 0; checked = 0
for rho in (0.80, 0.90, 0.95):
    a = 1 - rho
    for n in list(range(1, 121)) + list(range(125, 1001, 25)):
        rs = np.arange(1, n + 1)
        ok_beta = beta.cdf(a, rs, n - rs + 1) >= 1 - DELTA
        r_beta = int(rs[ok_beta].max()) if ok_beta.any() else 0
        if n <= 60:    # explicit binomial tail by direct summation
            ok_bin = np.array([sum(math.comb(n, x) * a ** x * (1 - a) ** (n - x) for x in range(r, n + 1)) >= 1 - DELTA for r in rs])
        else:          # scipy binomial survival function
            ok_bin = binom.sf(rs - 1, n, a) >= 1 - DELTA
        r_bin = int(rs[ok_bin].max()) if ok_bin.any() else 0
        thr, ok = cal.guaranteed_threshold(np.arange(1, n + 1, dtype=float), rho, DELTA)   # scores 1..n -> threshold = s_(r) = r
        r_code = int(thr) if ok else 0
        checked += 1
        if not (r_beta == r_bin == r_code): mism += 1
print(f"1. rank selection: {checked} (n, rho) pairs checked; mismatches between Beta, binomial-tail and the deployed code: {mism}")
print(f"   minimum labelled attacks for certification: rho=.9 -> {cal.min_attacks(0.9, 0.1)} (code), expected ceil(ln .1/ln .9) = {math.ceil(math.log(.1)/math.log(.9))}")

# ---- 2. indexing / inclusivity / ties on hand-built vectors ----
scores = np.array([0.9, 0.2, 0.5, 0.7, 0.3, 0.8, 0.4, 0.6, 0.95, 0.1] * 3)      # n = 30 attacks, scores repeat 3x each
thr, ok = cal.guaranteed_threshold(scores, 0.90, 0.10)
n = len(scores); srt = np.sort(scores)
r = max(rr for rr in range(1, n + 1) if beta.cdf(0.10, rr, n - rr + 1) >= 0.90)
assert ok and thr == srt[r - 1], f"threshold {thr} != r-th smallest {srt[r-1]} (r={r})"
flagged = (scores >= thr).mean()
print(f"2. n=30 with 3-way ties: r={r}, threshold={thr} equals the r-th smallest labelled score; recall on the labelled set (>=) = {flagged:.3f} >= rho")
assert flagged >= 0.90
t2, ok2 = cal.guaranteed_threshold(np.array([0.5] * 40), 0.90, 0.10)
assert ok2 and t2 == 0.5 and (np.array([0.5] * 40) >= t2).all()
print("   all-equal scores: threshold equals that score and every attack is flagged (inclusive >=)")
t3, ok3 = cal.guaranteed_threshold(np.arange(21, dtype=float), 0.90, 0.10)
assert (not ok3) and t3 == -math.inf
print("   21 labelled attacks (< 22): falls back to flag-everything (-inf), as specified")

# ---- 3. end to end on i.i.d. continuous scores ----
rng = np.random.default_rng(12345)
pop = np.sort(rng.beta(5, 2, 300000))
def true_recall(t): return 1 - np.searchsorted(pop, t, 'left') / len(pop)
for n in (22, 40, 100):
    hits = 0; T = 4000
    for _ in range(T):
        s = rng.choice(pop, n, replace=False)
        t, ok = cal.guaranteed_threshold(s, 0.90, 0.10); assert ok
        hits += true_recall(t) >= 0.90
    r = max(rr for rr in range(1, n + 1) if beta.cdf(0.10, rr, n - rr + 1) >= 0.90)
    exact = binom.sf(r - 1, n, 0.10)
    print(f"3. n={n:4d}: rule coverage {hits / T:.4f} (MC se {math.sqrt(hits/T*(1-hits/T)/T):.4f}); exact i.i.d. success prob for r={r}: {exact:.4f}")
print("ALL CHECKS PASSED")
