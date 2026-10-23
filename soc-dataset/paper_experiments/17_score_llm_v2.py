"""Score the improved (calibrated prompt + 8 few-shot examples from training rounds) LLM
baseline on round 4, with the same TPR/FPR, prevalence projection and (via attack_probability)
threshold-free metrics used for the other models. Ground truth is read only here."""
import glob, json
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve, f1_score

ns = {}
exec(open('13_triage_relief_analysis.py').read().split("curves, yte = run(")[0], ns)
df, r4 = ns['df'], ns['r4']
te = df[r4].dropna(subset=['is_true_positive']).reset_index(drop=True)
y = te['is_true_positive'].astype(bool).values

rows = [json.loads(l) for f in sorted(glob.glob('llm_v2/result_*.jsonl')) for l in open(f) if l.strip()]
res = pd.DataFrame(rows).drop_duplicates('row_id').set_index('row_id')
print(f"scored {len(res)}/{len(te)}")
res = res.reindex(range(len(te)))
missing = res['is_true_positive'].isna().sum()
print("missing:", missing)
pred = res['is_true_positive'].fillna(True).astype(bool).values
prob = res['attack_probability'].fillna(100).astype(float).values / 100

tpr, fpr = pred[y].mean(), pred[~y].mean()
print(f"LLM v2 hard labels: TPR={tpr:.3f}  FPR={fpr:.3f}  noise cleared={1-fpr:.3f}  F1(r4)={f1_score(y, pred):.3f}")
print(f"LLM v2 ROC-AUC (attack_probability): {roc_auc_score(y, prob):.3f}")
fp_, tp_, _ = roc_curve(y, prob)
for r in (.90, .95):
    ok = tp_ >= r
    print(f"  Relief@R{int(r*100)} = {1 - fp_[ok].min():.3f}")
for pi in (.01, .05, .10, .30):
    P = pi * tpr / (pi * tpr + (1 - pi) * fpr) if tpr + fpr > 0 else 0
    F = 2 * P * tpr / (P + tpr) if P + tpr > 0 else 0
    print(f"  projected F1@{int(pi*100)}% = {F:.3f}   alerts reviewed per attack = {1/P if P else float('inf'):.1f}")
