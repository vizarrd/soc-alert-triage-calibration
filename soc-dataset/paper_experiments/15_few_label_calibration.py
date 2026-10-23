"""Experiment 14 showed thresholds chosen on source-environment data do not transfer under
distribution shift (forward direction: rankers flag everything). Hypothesis: a SMALL number of
analyst-labelled alerts from the target environment suffices to re-calibrate the threshold.

Protocol (forward direction, train rounds 1-3 -> deploy on round 4): model weights stay frozen
(trained on rounds 1-3 only). The first k alerts of the target stream are shown to an analyst
(labelled); the threshold is set to the largest value reaching >= 95% recall on those k labelled
alerts (needs >=1 labelled attack, and uses a conservative fallback otherwise). Evaluated on the
remaining unlabelled alerts. k random draws (200 repeats) -> mean, 5th percentile.
Random draws (not first-k) are used so results are not an artifact of one stream prefix.
"""
import numpy as np
from sklearn.pipeline import Pipeline
ns = {}
exec(open('13_triage_relief_analysis.py').read().split("curves, yte = run(")[0], ns)
df, r4, prep, pre, make_models = ns['df'], ns['r4'], ns['prep'], ns['pre'], ns['make_models']

tr = df[~r4].dropna(subset=['is_true_positive']).sort_values('timestamp')
te = df[r4].dropna(subset=['is_true_positive']).sort_values('timestamp')
ytr = tr['is_true_positive'].astype(bool).values; yte = te['is_true_positive'].astype(bool).values
Xtr, Xte = prep(tr), prep(te)

scores = {'rule_level': Xte['rule_level'].values.astype(float)}
for n in ['LogReg', 'RF', 'MLP']:
    p = Pipeline([('f', pre()), ('c', make_models(0)[n])]).fit(Xtr, ytr)
    scores[n] = p.predict_proba(Xte)[:, 1]

def thr_from_labels(s, y, target=0.95):
    pos = np.sort(s[y])[::-1]
    if len(pos) == 0:
        return -np.inf  # nothing labelled as attack: be conservative, flag all
    k = int(np.ceil(target * len(pos)))
    return pos[k - 1]

rng = np.random.default_rng(0)
print(f"{'model':11s} {'k':>4s} | recall mean (p5) | noise cleared mean (p5)")
for name, s in scores.items():
    for k in [10, 20, 50, 100]:
        rec, clr = [], []
        for _ in range(200):
            idx = rng.choice(len(s), k, replace=False)
            mask = np.ones(len(s), bool); mask[idx] = False
            t = thr_from_labels(s[idx], yte[idx])
            pred = s[mask] >= t; y = yte[mask]
            rec.append(pred[y].mean()); clr.append(1 - pred[~y].mean())
        print(f"{name:11s} {k:4d} | {np.mean(rec):.3f} ({np.percentile(rec, 5):.3f}) | {np.mean(clr):.3f} ({np.percentile(clr, 5):.3f})")
