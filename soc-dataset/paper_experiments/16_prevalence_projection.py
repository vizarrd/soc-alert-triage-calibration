"""Addresses the main validity objection to experiments 03/06: round 4 is 82% attacks, an
artifact of us running pentest tools against our own server. Real SOC streams are the
opposite (the literature cites ~99% false positives).

Method: a detector's true-positive rate (TPR) and false-positive rate (FPR) do not depend on
class prevalence pi. Measure TPR and FPR on round 4 (with bootstrap CIs), then project
precision and F1 analytically to any deployment prevalence:
    precision(pi) = pi*TPR / (pi*TPR + (1-pi)*FPR)
    F1(pi)        = 2*P*R / (P+R),  R = TPR
This shows what "flag everything" and each model would score at realistic prevalence.
Also projects the frozen models after few-label recalibration (k=20, experiment 15 protocol)
and the LLM (hard labels from experiment 03). Alerts-to-review per true attack
(1/precision) is the analyst-workload view.
"""
import numpy as np, pandas as pd
from sklearn.pipeline import Pipeline
ns = {}
exec(open('13_triage_relief_analysis.py').read().split("curves, yte = run(")[0], ns)
df, r4, prep, pre, make_models = ns['df'], ns['r4'], ns['prep'], ns['pre'], ns['make_models']
from sklearn.metrics import roc_curve

tr = df[~r4].dropna(subset=['is_true_positive']).sort_values('timestamp')
te = df[r4].dropna(subset=['is_true_positive'])          # original order = LLM row_id order
y_te = te['is_true_positive'].astype(bool).values
ytr = tr['is_true_positive'].astype(bool).values
Xtr, Xte = prep(tr), prep(te)

llm = pd.read_csv('03d_llm_scored_comparison.csv')
assert (llm['is_true_positive_true'].astype(bool).values == y_te).all(), 'LLM row alignment mismatch'
llm_pred = llm['is_true_positive_llm'].astype(bool).values

preds = {'flag-everything': np.ones(len(y_te), bool), 'LLM (Claude)': llm_pred}
fpr_, tpr_, th = roc_curve(ytr, Xtr['rule_level'].values); t = th[np.argmax(tpr_ - fpr_)]
preds['rule_level (Youden)'] = Xte['rule_level'].values >= t
scores = {}
for n in ['LogReg', 'RF', 'MLP']:
    p = Pipeline([('f', pre()), ('c', make_models(0)[n])]).fit(Xtr, ytr)
    scores[n] = p.predict_proba(Xte)[:, 1]
    preds[n + ' @0.5'] = scores[n] >= .5

# few-label recalibration (k=20), average TPR/FPR over 200 draws
rng = np.random.default_rng(0)
def thr_from_labels(s, y, target=0.95):
    pos = np.sort(s[y])[::-1]
    return -np.inf if len(pos) == 0 else pos[int(np.ceil(target * len(pos))) - 1]
recal = {}
for n in ['LogReg', 'MLP']:
    pr = []
    for _ in range(200):
        idx = rng.choice(len(y_te), 20, replace=False)
        pr.append(scores[n] >= thr_from_labels(scores[n][idx], y_te[idx]))
    recal[n + ' +20 labels'] = pr   # list of prediction vectors

def rates(pred, y):
    return pred[y].mean(), pred[~y].mean()

def proj(tpr, fpr, pi):
    P = pi * tpr / (pi * tpr + (1 - pi) * fpr) if (pi * tpr + (1 - pi) * fpr) > 0 else 0
    F = 2 * P * tpr / (P + tpr) if (P + tpr) > 0 else 0
    return P, F

PIS = [0.01, 0.05, 0.10, 0.30, 0.82]
rows = []
def add(name, tpr, fpr, tpr_lo=None, tpr_hi=None):
    r = {'method': name, 'TPR': tpr, 'FPR': fpr}
    for pi in PIS:
        P, F = proj(tpr, fpr, pi)
        r[f'F1@{int(pi*100)}%'] = F; r[f'rev/atk@{int(pi*100)}%'] = (1 / P) if P > 0 else np.inf
    rows.append(r)
for name, pred in preds.items():
    add(name, *rates(pred, y_te))
for name, plist in recal.items():
    tp = np.mean([rates(p, y_te)[0] for p in plist]); fp = np.mean([rates(p, y_te)[1] for p in plist])
    add(name, tp, fp)

out = pd.DataFrame(rows).set_index('method')
pd.set_option('display.width', 250); pd.set_option('display.max_columns', 30)
print("Projected F1 by deployment prevalence (alerts that are real attacks):")
print(out[['TPR', 'FPR'] + [f'F1@{int(p*100)}%' for p in PIS]].round(3).to_string())
print("\nAlerts an analyst must review per real attack found (1/precision; lower is better):")
print(out[[f'rev/atk@{int(p*100)}%' for p in PIS]].round(1).to_string())

# bootstrap CIs on F1@5% for key methods
print("\nBootstrap 95% CI for F1 at 5% prevalence (2000 resamples of round 4):")
for name in ['flag-everything', 'LLM (Claude)', 'rule_level (Youden)', 'LogReg @0.5', 'MLP @0.5', 'RF @0.5']:
    pred = preds[name]; f = []
    for _ in range(2000):
        i = rng.integers(0, len(y_te), len(y_te)); yb = y_te[i]; pb = pred[i]
        if yb.sum() == 0 or (~yb).sum() == 0: continue
        f.append(proj(*rates(pb, yb), 0.05)[1])
    print(f"  {name:22s} {np.percentile(f, 2.5):.3f} - {np.percentile(f, 97.5):.3f}")
