"""Fair LLM vs conventional-model comparison on the public AIT data: the SAME 1,200 held-out alerts
(150 per scenario) with the same window labels and the same metrics.

The LLM (exp. 19) saw 150 alerts per scenario; the conventional models in exp. 18 were scored on 4,000
alerts per scenario. Here, for each held-out scenario, the conventional models are trained on the other
seven scenarios' alerts (same pipeline as exp. 18: leave-one-scenario-out) and scored ONLY on that
scenario's 150 LLM-evaluated alerts. Reports per-scenario mean ROC-AUC and Relief@R95 (as in exp. 18),
pooled ROC-AUC over the 1,200 alerts, paired bootstrap 95% intervals for AUC differences from the LLM,
and default-threshold TPR/FPR.  Run from paper_experiments/."""
import glob, json
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve

src = open('18_external_validation_ait_ads.py').read().split("scen = df['scenario'].values")[0]
ns = {}; exec(src, ns)
df, X, y_all, fit_score = ns['df'], ns['X_clean'], ns['y_all'], ns['fit_score']
scen = df['scenario'].values

gt = pd.read_csv('19_ait_llm_ground_truth.csv')                       # row_id, sample_idx, scenario, label
llm = pd.DataFrame([json.loads(l) for f in sorted(glob.glob('llm_ait/result_*.jsonl')) for l in open(f) if l.strip()]
                   ).drop_duplicates('row_id').set_index('row_id').reindex(gt['row_id'])
assert llm['attack_probability'].notna().all(), 'missing LLM rows'
gt['llm_prob'] = llm['attack_probability'].values / 100.0
gt['llm_pred'] = llm['is_true_positive'].astype(bool).values
sidx = gt['sample_idx'].values
assert (y_all[sidx] == gt['is_true_positive'].astype(bool).values).all(), 'label alignment mismatch'
assert (scen[sidx] == gt['scenario'].values).all(), 'scenario alignment mismatch'
print(f"{len(gt)} alerts; attack share {gt.is_true_positive.mean():.3f}")

def relief95(y, s):
    f, t, _ = roc_curve(y, s); ok = t >= .95
    return 1 - f[ok].min() if ok.any() else 0.0

scores = {'LLM (few-shot)': gt['llm_prob'].values.copy()}
for name in ['LogReg', 'RF', 'MLP']:
    scores[name] = np.zeros(len(gt))
scores['rule_level'] = X['rule_level'].values[sidx].astype(float)
for held in sorted(set(scen)):
    tr = scen != held; te_rows = np.where(gt['scenario'].values == held)[0]
    for name in ['LogReg', 'RF', 'MLP']:
        s = fit_score(name, X[tr], y_all[tr], X.iloc[sidx[te_rows]])
        scores[name][te_rows] = s
    print('scored', held, flush=True)

y = gt['is_true_positive'].astype(bool).values
sc_arr = gt['scenario'].values
rows = []
for name, s in scores.items():
    per = []; per_r = []
    for sc in sorted(set(sc_arr)):
        m = sc_arr == sc
        if y[m].min() == y[m].max(): continue
        per.append(roc_auc_score(y[m], s[m])); per_r.append(relief95(y[m], s[m]))
    rows.append((name, np.mean(per), np.mean(per_r), roc_auc_score(y, s)))
print("\nSame 1,200 alerts (leave-one-scenario-out for trained models):")
print(f"{'method':16s} {'mean per-scenario AUC':>22s} {'mean Relief@R95':>16s} {'pooled AUC':>11s}")
for r in rows: print(f"{r[0]:16s} {r[1]:22.3f} {r[2]:16.3f} {r[3]:11.3f}")

rng = np.random.default_rng(0)
print("\nPaired bootstrap (2,000 resamples of alerts) 95% CI for mean-per-scenario AUC difference, LLM minus method:")
idx_by_sc = {sc: np.where(sc_arr == sc)[0] for sc in sorted(set(sc_arr))}
def mean_auc(s, idxs):
    out = []
    for sc, ii in idxs.items():
        if y[ii].min() == y[ii].max(): continue
        out.append(roc_auc_score(y[ii], s[ii]))
    return np.mean(out)
for other in ['LogReg', 'RF', 'MLP', 'rule_level']:
    d = []
    for _ in range(2000):
        idxs = {sc: ii[rng.integers(0, len(ii), len(ii))] for sc, ii in idx_by_sc.items()}
        d.append(mean_auc(scores['LLM (few-shot)'], idxs) - mean_auc(scores[other], idxs))
    d = np.array(d); print(f"  LLM - {other:10s}: mean {d.mean():+.4f}  95% CI [{np.percentile(d, 2.5):+.4f}, {np.percentile(d, 97.5):+.4f}]")

# ---- scenario-level uncertainty: the 8 scenarios are the sampling units ----
per_sc = {name: np.array([roc_auc_score(y[idx_by_sc[sc]], scores[name][idx_by_sc[sc]]) for sc in sorted(idx_by_sc)])
          for name in scores}
print("\nPer-scenario AUC (scenarios:", ', '.join(sorted(idx_by_sc)), ")")
for name, v in per_sc.items(): print(f"  {name:16s}", ' '.join(f"{a:.3f}" for a in v))
print("\nScenario-level analysis of LLM minus method (8 scenarios as sampling units):")
for other in ['LogReg', 'RF', 'MLP', 'rule_level']:
    d = per_sc['LLM (few-shot)'] - per_sc[other]
    boots = np.array([d[rng.integers(0, len(d), len(d))].mean() for _ in range(10000)])
    print(f"  LLM - {other:10s}: mean diff {d.mean():+.4f}; LLM higher in {(d > 0).sum()}/{len(d)} scenarios; "
          f"scenario-bootstrap 95% CI [{np.percentile(boots, 2.5):+.4f}, {np.percentile(boots, 97.5):+.4f}] (10,000 resamples of the 8 scenarios)")
np.savez('30_scores.npz', y=y, scenario=sc_arr, **{k.replace(' ', '_').replace('(', '').replace(')', ''): v for k, v in scores.items()})

print("\nDefault decisions on the same alerts (TPR / FPR): LLM hard labels; models at score >= 0.5; rule_level at Youden-free level >= 5")
pred = {'LLM (few-shot)': gt['llm_pred'].values, 'LogReg': scores['LogReg'] >= .5, 'RF': scores['RF'] >= .5, 'MLP': scores['MLP'] >= .5}
for k, p in pred.items(): print(f"  {k:16s} TPR {p[y].mean():.3f}  FPR {p[~y].mean():.3f}")
