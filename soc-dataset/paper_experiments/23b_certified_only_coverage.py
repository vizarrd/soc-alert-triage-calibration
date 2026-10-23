"""Coverage restricted to draws where the guaranteed rule actually CERTIFIED (no fallback).
Fallback draws flag everything and so trivially have recall 1; counting them as coverage successes
inflates the headline numbers in low-prevalence scenarios. From the saved per-cell results of exp. 23:
    certified_coverage = (coverage - fallback) / (1 - fallback)      (fallback draws have recall 1)
Cells with fallback > 0.9 have too few certified draws (<100 of 1000) and are excluded from the summary."""
import pandas as pd
r = pd.read_csv('23_per_cell_results.csv')
g = r[(r.rule == 'guaranteed')].copy()
g['n_cert'] = (1 - g.fallback) * 1000
g['cert_cov'] = (g.coverage - g.fallback) / (1 - g.fallback)
ok = g[g.n_cert >= 100]
print(f"cells total={len(g)}, with >=100 certified draws={len(ok)}")
print("\ncertified-only coverage by rho (target >= 0.90), all k, all scenarios/models:")
print(ok.groupby('rho').cert_cov.agg(['min', 'mean', 'count']).round(3).to_string())
print("\nrho=0.90 by k (min / mean / n cells):")
print(ok[ok.rho == 0.90].groupby(['model', 'k']).cert_cov.agg(['min', 'mean', 'count']).round(3).to_string())
low = ok[ok.cert_cov < 0.90]
print(f"\ncells with certified coverage < 0.90: {len(low)}")
if len(low): print(low[['scenario', 'model', 'k', 'rho', 'cert_cov', 'n_cert']].round(3).to_string())
print("\nfallback rate (rho=0.90) by k, mean over scenarios:"); print(g[g.rho == 0.90].groupby('k').fallback.mean().round(3).to_string())
