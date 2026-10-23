"""Label-convention sensitivity. 107 of the 123 benign round-4 alerts are 'Web server 400 error code'
scanner noise that WE labelled benign by convention, while the public AIT data labels the same alert
type as attack. Which convention is 'right' is a policy question, not a fact, so we evaluate every
method under BOTH conventions on the same predictions:

  Convention A (paper default):  scanner noise = benign   (attacks 573, benign 123)
  Convention B (alternative):    scanner noise = attack   (attacks 680, benign 16)

Reports, per method (mean over seeds for stochastic models): recall on attacks, fraction of the
16 non-scanner benign alerts cleared, ROC-AUC under each convention, and the paper's headline
quantity 'noise cleared' under A. A conclusion that flips between A and B is convention-dependent."""
import json, glob
import numpy as np, pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.metrics import roc_auc_score

ns = {}
exec(open('13_triage_relief_analysis.py').read().split("curves, yte = run(")[0], ns)
df, r4, prep, pre, make_models = ns['df'], ns['r4'], ns['prep'], ns['pre'], ns['make_models']
tr = df[~r4].dropna(subset=['is_true_positive']).sort_values('timestamp')
te = df[r4].dropna(subset=['is_true_positive']).copy(); te['pos'] = np.arange(len(te)); te = te.sort_values('timestamp')
ytr = tr['is_true_positive'].astype(bool).values
yA = te['is_true_positive'].astype(bool).values
scan = ((~yA) & (te['attack_category'].values == 'web_scan_noise_400'))
yB = yA | scan
other = (~yB)
print(f"A: attacks={yA.sum()} benign={(~yA).sum()}   B: attacks={yB.sum()} benign={(~yB).sum()} (the non-scanner benign alerts)")
Xtr, Xte = prep(tr), prep(te)

preds, scores = {}, {}
fpr_t = None
from sklearn.metrics import roc_curve
f, t, th = roc_curve(ytr, Xtr['rule_level'].values); thr = th[np.argmax(t - f)]
scores['rule_level'] = Xte['rule_level'].values.astype(float); preds['rule_level'] = [scores['rule_level'] >= thr]
pos = te['pos'].values
llm0 = pd.read_csv('03d_llm_scored_comparison.csv')['is_true_positive_llm'].astype(bool).values[pos]
preds['LLM zero-shot'] = [llm0]; scores['LLM zero-shot'] = llm0.astype(float)
llm2 = pd.DataFrame([json.loads(l) for f_ in sorted(glob.glob('llm_v2/result_*.jsonl')) for l in open(f_) if l.strip()]).drop_duplicates('row_id').set_index('row_id').sort_index()
preds['LLM few-shot'] = [llm2['is_true_positive'].astype(bool).values[pos]]; scores['LLM few-shot'] = llm2['attack_probability'].values[pos] / 100.0
p = Pipeline([('f', pre()), ('c', make_models(0)['LogReg'])]).fit(Xtr, ytr); s = p.predict_proba(Xte)[:, 1]
preds['LogReg'] = [s >= .5]; scores['LogReg'] = s
rf_p, rf_s = [], []
for seed in range(20):
    p = Pipeline([('f', pre()), ('c', make_models(seed)['RF'])]).fit(Xtr, ytr); s = p.predict_proba(Xte)[:, 1]
    rf_p.append(s >= .5); rf_s.append(s)
preds['Random Forest (20 seeds)'] = rf_p; scores['Random Forest (20 seeds)'] = np.mean(rf_s, axis=0)

rows = []
for name, plist in preds.items():
    sc = scores[name]
    ra = np.mean([pr[yA].mean() for pr in plist]); ca = np.mean([1 - pr[~yA].mean() for pr in plist])
    rb = np.mean([pr[yB].mean() for pr in plist]); cb = np.mean([1 - pr[other].mean() for pr in plist])
    rows.append(dict(method=name, A_recall=ra, A_noise_cleared=ca, A_AUC=roc_auc_score(yA, sc),
                     B_recall=rb, B_other_benign_cleared=cb, B_AUC=roc_auc_score(yB, sc)))
out = pd.DataFrame(rows).set_index('method').round(3)
pd.set_option('display.width', 220); pd.set_option('display.max_columns', 20)
print("\nSame predictions, two label conventions:")
print(out.to_string())
out.to_csv('26_convention_sensitivity.csv')
