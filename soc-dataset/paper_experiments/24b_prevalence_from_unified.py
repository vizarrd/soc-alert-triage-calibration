"""Prevalence projection (F1, alerts-reviewed-per-attack) from the per-seed results of experiment 24,
so the prevalence table uses exactly the same runs as the other tables. For stochastic models the
projection is computed per seed and then averaged (mean +- sd of F1@5%)."""
import numpy as np, pandas as pd
r = pd.read_csv('24_per_seed_results.csv')
def proj(tpr, fpr, pi):
    P = pi * tpr / (pi * tpr + (1 - pi) * fpr) if (pi * tpr + (1 - pi) * fpr) > 0 else 0.0
    F = 2 * P * tpr / (P + tpr) if (P + tpr) > 0 else 0.0
    return P, F
rows = []
flag = pd.DataFrame([{'method': 'Flag everything', 'seed': '-', 'recall': 1.0, 'cleared': 0.0}])
for _, x in pd.concat([flag, r[['method', 'seed', 'recall', 'cleared']]]).iterrows():
    out = {'method': x.method, 'seed': x.seed, 'TPR': x.recall, 'FPR': 1 - x.cleared}
    for pi in (0.01, 0.05, 0.10):
        P, F = proj(x.recall, 1 - x.cleared, pi); out[f'F1@{int(pi*100)}'] = F; out[f'rev@{int(pi*100)}'] = (1 / P) if P > 0 else np.inf
    rows.append(out)
d = pd.DataFrame(rows)
g = d.groupby('method', sort=False)
pd.set_option('display.width', 220)
print(g[['TPR', 'FPR', 'F1@1', 'F1@5', 'F1@10']].mean().round(3).to_string())
print('\nalerts reviewed per attack at 5% (mean over seeds):')
print(g['rev@5'].mean().round(1).to_string())
print('\nsd of F1@5% over seeds:'); print(g['F1@5'].std().fillna(0).round(3).to_string())
