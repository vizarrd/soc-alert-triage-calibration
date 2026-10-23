"""Large-scale validation of the recall-guaranteed threshold (experiment 20) on full-size streams.

Setup: AIT-ADS leave-one-scenario-out. Train on up to 10,000 alerts per training scenario (70k);
test stream = up to 50,000 alerts of the held-out scenario (ait_large.csv). Models: Logistic
Regression and Random Forest. For each (scenario, model, number of labelled alerts k, target
recall rho) we repeat 1,000 draws: label k random alerts, set the threshold with
  (a) naive      : keep a fraction rho of the labelled attacks (empirical quantile)
  (b) guaranteed : order-statistic rule, recall >= rho with probability >= 1 - delta (delta = 0.10)
and compute the stream's TRUE recall and noise cleared at that threshold (population values on
the sorted score arrays, which is what the guarantee is about).
Reported: coverage = share of draws with recall >= rho (guarantee: >= 0.90), 5th-percentile
recall, mean noise cleared, share of draws where the rule could not certify (fallback = flag all).
Also: coverage as the target rho varies (0.80, 0.90, 0.95)."""
import numpy as np, pandas as pd
from scipy.stats import beta
from sklearn.metrics import roc_auc_score

ns = {}
src = open('18_external_validation_ait_ads.py').read()
head = src.split("df = pd.read_csv('../external_data/ait_ads/ait_sample.csv')")[0]
funcs = src.split("y_all = df['is_true_positive'].astype(bool).values")[1].split("scen = df['scenario'].values")[0]
exec(head, ns)
df = pd.read_csv('../external_data/ait_ads/ait_large.csv', keep_default_na=False)
df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, format='ISO8601')
df['is_true_positive'] = df['is_true_positive'].astype(str).str.lower().eq('true')
ns['df'] = df
exec(funcs, ns)
X, y_all, fit_score = ns['X_clean'], df['is_true_positive'].values, ns['fit_score']
scen = df['scenario'].values
DELTA, REPS = 0.10, 1000
KS, RHOS = (50, 100, 200, 500, 1000), (0.80, 0.90, 0.95)
rng = np.random.default_rng(0)
_r_cache = {}

def best_r(n, rho):
    key = (n, rho)
    if key not in _r_cache:
        best = 0
        for r in range(1, n + 1):
            if beta.cdf(1 - rho, r, n - r + 1) >= 1 - DELTA:
                best = r
        _r_cache[key] = best
    return _r_cache[key]

def thr_guar(sl, yl, rho):
    pos = np.sort(sl[yl]); r = best_r(len(pos), rho)
    return (-np.inf, True) if r == 0 else (pos[r - 1], False)

def thr_naive(sl, yl, rho):
    pos = np.sort(sl[yl])[::-1]
    return -np.inf if len(pos) == 0 else pos[int(np.ceil(rho * len(pos))) - 1]

rows = []
for held in sorted(set(scen)):
    te = scen == held; tr_idx = np.where(~te)[0]
    sub = np.concatenate([rng.choice(tr_idx[scen[tr_idx] == s], min(10000, (scen[tr_idx] == s).sum()), replace=False)
                          for s in sorted(set(scen)) if s != held])
    s_te_all, y_te = {}, y_all[te]
    for name in ('LogReg', 'RF'):
        pipe_scores = fit_score(name, X.iloc[sub], y_all[sub], X[te])
        s_te_all[name] = pipe_scores
    for name, s in s_te_all.items():
        auc = roc_auc_score(y_te, s)
        sp, sn = np.sort(s[y_te]), np.sort(s[~y_te])
        N = len(s)
        for k in KS:
            for rho in RHOS:
                res = {'naive': [], 'guaranteed': []}; clr = {'naive': [], 'guaranteed': []}; fb = 0
                for _ in range(REPS):
                    idx = rng.choice(N, k, replace=False); sl, yl = s[idx], y_te[idx]
                    tn = thr_naive(sl, yl, rho); tg, fallback = thr_guar(sl, yl, rho); fb += fallback
                    for rule, t in (('naive', tn), ('guaranteed', tg)):
                        res[rule].append(1 - np.searchsorted(sp, t, 'left') / len(sp))   # recall: positives with score >= t
                        clr[rule].append(np.searchsorted(sn, t, 'left') / len(sn))      # noise cleared: negatives with score < t
                for rule in res:
                    R = np.array(res[rule])
                    rows.append(dict(scenario=held, model=name, k=k, rho=rho, rule=rule, auc=auc, prev=y_te.mean(), n_stream=N,
                                     coverage=(R >= rho).mean(), p5_recall=np.percentile(R, 5), cleared=np.mean(clr[rule]),
                                     fallback=(fb / REPS if rule == 'guaranteed' else 0.0)))
    print('done', held, 'stream', te.sum(), 'prev', round(y_te.mean(), 3), flush=True)

res = pd.DataFrame(rows); res.to_csv('23_per_cell_results.csv', index=False)
pd.set_option('display.width', 220); pd.set_option('display.max_rows', 400)
print("\nStream sizes / prevalence / AUC:")
print(res.groupby(['scenario', 'model'])[['n_stream', 'prev', 'auc']].first().round(3).to_string())
print("\n=== rho=0.90: mean over 8 scenarios (coverage target >= 0.90) ===")
sel = res[res.rho == 0.90]
print(sel.groupby(['model', 'rule', 'k'])[['coverage', 'p5_recall', 'cleared', 'fallback']].mean().round(3).to_string())
print("\n=== rho=0.90: WORST scenario coverage ===")
print(sel.groupby(['model', 'rule', 'k'])['coverage'].min().round(3).to_string())
print("\n=== Coverage vs target rho (k=200, guaranteed vs naive; mean over scenarios) ===")
print(res[res.k == 200].groupby(['model', 'rule', 'rho'])[['coverage', 'cleared', 'fallback']].mean().round(3).to_string())
print("\n=== Per scenario, LogReg, rho=0.90, k=200 ===")
print(res[(res.model == 'LogReg') & (res.rho == 0.90) & (res.k == 200)].pivot(index='scenario', columns='rule', values=['coverage', 'cleared']).round(3).to_string())
