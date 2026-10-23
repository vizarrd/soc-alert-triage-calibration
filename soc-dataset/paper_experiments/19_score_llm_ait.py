"""Scores the calibrated few-shot LLM baseline on the public AIT-ADS sample (150 alerts per
scenario, 1200 total) against window labels; compares with flag-everything and with the
leave-one-scenario-out classifiers' hard decisions on the same rows (exp. 18 protocol)."""
import glob, json
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve
gt = pd.read_csv('19_ait_llm_ground_truth.csv')
rows = [json.loads(l) for f in sorted(glob.glob('llm_ait/result_*.jsonl')) for l in open(f) if l.strip()]
res = pd.DataFrame(rows).drop_duplicates('row_id').set_index('row_id').reindex(gt['row_id'])
gt['pred'] = res['is_true_positive'].fillna(True).astype(bool).values
gt['prob'] = res['attack_probability'].fillna(100).astype(float).values / 100
print('scored', res['is_true_positive'].notna().sum(), '/', len(gt))
y = gt['is_true_positive'].astype(bool)
def relief95(y, s):
    f, t, _ = roc_curve(y, s); ok = t >= .95
    return 1 - f[ok].min() if ok.any() else 0.0
print(f"pooled: TPR={gt.pred[y].mean():.3f} FPR={gt.pred[~y].mean():.3f} AUC={roc_auc_score(y, gt.prob):.3f} Relief@R95={relief95(y, gt.prob):.3f}")
print("\nper scenario:  prev  TPR  FPR(1-cleared)  AUC")
for sc, g in gt.groupby('scenario'):
    yy = g.is_true_positive.astype(bool)
    print(f"{sc:16s} {yy.mean():.2f}  {g.pred[yy].mean():.3f}  {g.pred[~yy].mean():.3f}  {roc_auc_score(yy, g.prob) if yy.nunique()>1 else float('nan'):.3f}")
