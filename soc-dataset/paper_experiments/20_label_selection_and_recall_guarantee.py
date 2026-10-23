"""Method experiment: how should an analyst's few labels be used to set the alert threshold
in a NEW environment, and can we promise a recall level?

Setting: a frozen model scores the new environment's alert stream. The analyst labels k alerts.
We pick the threshold. Question A -- WHICH alerts to label:
   random          : k random alerts, threshold = 95% of labelled attacks kept   (baseline, exp. 15/18)
   uncertainty     : the k alerts with score closest to 0.5 (standard active learning)
   stratified      : one random alert from each of k equal-size score bins, importance-weighted
Question B -- CAN WE GUARANTEE RECALL ("calibrated threshold"):
   guaranteed      : k random alerts; among the n labelled attacks, pick the threshold from an
                     order-statistic bound so that, with probability >= 1-delta (delta=0.1), the
                     true attack recall is >= 0.90. Distribution-free; needs iid-sampled labels.
                     If n is too small to certify, it falls back to "flag everything".
Reported per method and k (100 repeated draws per target): mean recall, share of draws with
recall >= 0.90 (the 'coverage'; the guarantee targets >= 0.90), 5th-percentile recall, and mean
noise cleared. Targets: 8 held-out AIT-ADS scenarios (LogReg and RF, leave-one-scenario-out) and
our own round 4 (LogReg, MLP). Evaluation uses the unlabelled remainder.
"""
import numpy as np, pandas as pd
from scipy.stats import beta
from sklearn.pipeline import Pipeline

TARGET_RECALL, DELTA = 0.90, 0.10
rng = np.random.default_rng(0)

# ---------- threshold rules ----------
def thr_unweighted(s, y, target=0.95):
    pos = np.sort(s[y])[::-1]
    return -np.inf if len(pos) == 0 else pos[int(np.ceil(target * len(pos))) - 1]

def thr_weighted(s, y, w, target=0.95):
    if not y.any():
        return -np.inf
    sp, wp = s[y], w[y]
    o = np.argsort(-sp); sp, wp = sp[o], wp[o]
    cum = np.cumsum(wp) / wp.sum()
    return sp[np.searchsorted(cum, target)]

def thr_guaranteed(s, y, recall=TARGET_RECALL, delta=DELTA):
    """Largest rank r (ascending order statistic) such that P(miss-rate at s_(r) <= 1-recall) >= 1-delta,
    using F(s_(r)) ~ Beta(r, n-r+1). Threshold = s_(r): keeps attacks with score >= s_(r)."""
    pos = np.sort(s[y]); n = len(pos)
    best = None
    for r in range(1, n + 1):
        if beta.cdf(1 - recall, r, n - r + 1) >= 1 - delta:
            best = r
    return -np.inf if best is None else pos[best - 1]

# ---------- selection strategies ----------
def pick(strategy, s, k):
    n = len(s)
    if strategy in ('random', 'guaranteed'):
        idx = rng.choice(n, k, replace=False); return idx, np.ones(n)
    if strategy == 'uncertainty':
        idx = np.argsort(np.abs(s - 0.5))[:k]; return idx, np.ones(n)
    if strategy == 'stratified':
        order = np.argsort(s); bins = np.array_split(order, k)
        idx = np.array([rng.choice(b) for b in bins])
        w = np.zeros(n)
        for b, i in zip(bins, idx): w[i] = len(b)
        return idx, w

def run_target(s, y, ks=(20, 50, 100, 200), reps=100):
    out = []
    for strat in ('random', 'uncertainty', 'stratified', 'guaranteed'):
        for k in ks:
            if k >= len(s): continue
            R, C = [], []
            for _ in range(reps):
                idx, w = pick(strat, s, k)
                if strat == 'stratified':
                    t = thr_weighted(s[idx], y[idx], w[idx])
                elif strat == 'guaranteed':
                    t = thr_guaranteed(s[idx], y[idx])
                else:
                    t = thr_unweighted(s[idx], y[idx])
                m = np.ones(len(s), bool); m[idx] = False
                p = s[m] >= t; yy = y[m]
                if yy.sum() == 0 or (~yy).sum() == 0: continue
                R.append(p[yy].mean()); C.append(1 - p[~yy].mean())
            R = np.array(R)
            out.append(dict(strategy=strat, k=k, mean_recall=R.mean(), coverage_ge90=(R >= TARGET_RECALL).mean(),
                            p5_recall=np.percentile(R, 5), mean_cleared=np.mean(C)))
    return pd.DataFrame(out)

# =============== AIT-ADS (leave-one-scenario-out) ===============
src = open('18_external_validation_ait_ads.py').read().split("scen = df['scenario'].values")[0]
ns = {}; exec(src, ns)
df, X_clean, y_all, fit_score = ns['df'], ns['X_clean'], ns['y_all'], ns['fit_score']
scen = df['scenario'].values
frames = []
for held in sorted(set(scen)):
    te = scen == held; tr = ~te
    for name in ('LogReg', 'RF'):
        s = fit_score(name, X_clean[tr], y_all[tr], X_clean[te])
        r = run_target(s, y_all[te]); r['model'] = name; r['target'] = held; frames.append(r)
    print('AIT done', held, flush=True)
ait = pd.concat(frames)
agg = ait.groupby(['model', 'strategy', 'k'])[['mean_recall', 'coverage_ge90', 'p5_recall', 'mean_cleared']].mean().round(3)
pd.set_option('display.width', 200); pd.set_option('display.max_rows', 200)
print("\n===== AIT-ADS: mean over 8 held-out scenarios =====")
print(agg.to_string())
worst = ait.groupby(['model', 'strategy', 'k'])['mean_recall'].min().round(3)
print("\nWorst held-out scenario (min of mean recall):")
print(worst.to_string())
ait.to_csv('20_ait_per_target.csv', index=False)

# =============== our own data (rounds 1-3 -> round 4) ===============
ns2 = {}
exec(open('13_triage_relief_analysis.py').read().split("curves, yte = run(")[0], ns2)
d0, r4, prep0, pre0, mm = ns2['df'], ns2['r4'], ns2['prep'], ns2['pre'], ns2['make_models']
tr0 = d0[~r4].dropna(subset=['is_true_positive']).sort_values('timestamp')
te0 = d0[r4].dropna(subset=['is_true_positive'])
ytr0 = tr0['is_true_positive'].astype(bool).values; yte0 = te0['is_true_positive'].astype(bool).values
rows = []
for name in ('LogReg', 'MLP'):
    p = Pipeline([('f', pre0()), ('c', mm(0)[name])]).fit(prep0(tr0), ytr0)
    s = p.predict_proba(prep0(te0))[:, 1]
    r = run_target(s, yte0, ks=(20, 50, 100)); r['model'] = name; rows.append(r)
own = pd.concat(rows)
print("\n===== Our dataset: train rounds 1-3 -> round 4 =====")
print(own.set_index(['model', 'strategy', 'k']).round(3).to_string())
