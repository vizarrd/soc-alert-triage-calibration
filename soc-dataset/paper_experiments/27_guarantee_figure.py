"""Figure for the paper: coverage and noise cleared versus number of analyst labels k, naive rule vs
recall-guaranteed rule (AIT-ADS large streams, Logistic Regression, rho = 0.90, mean over 8 scenarios).
Design: two series -> colour-blind-safe Okabe-Ito hues AND different markers/line styles (survives
grayscale print); one y-axis per panel (no dual axis); nominal level drawn and labelled; thin lines.
Guaranteed-rule coverage uses certified draws only (cells with >= 100 certified draws)."""
import numpy as np, pandas as pd
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt

BLUE, ORANGE, GRAY = '#0072B2', '#D55E00', '#6b7280'
r = pd.read_csv('23_per_cell_results.csv')
r = r[(r.model == 'LogReg') & (r.rho == 0.90)]
ks = sorted(r.k.unique())
naive = r[r.rule == 'naive'].groupby('k')[['coverage', 'cleared']].mean()
g = r[r.rule == 'guaranteed'].copy()
g['n_cert'] = (1 - g.fallback) * 1000
g['cert_cov'] = (g.coverage - g.fallback) / (1 - g.fallback)
gc = g[g.n_cert >= 100].groupby('k').cert_cov.mean()
gcl = g.groupby('k').cleared.mean()
fb = g.groupby('k').fallback.mean()

plt.rcParams.update({'font.size': 7, 'axes.linewidth': 0.6, 'font.family': 'DejaVu Sans'})
fig, ax = plt.subplots(1, 2, figsize=(3.45, 1.9))
a = ax[0]
a.axhline(0.90, color=GRAY, lw=0.6, ls=':'); a.text(1050, 0.885, 'nominal 0.90', ha='right', va='top', color=GRAY, fontsize=6)
a.plot(ks, naive.coverage.loc[ks], color=ORANGE, marker='s', ms=3, lw=1.0, ls='--')
a.plot(gc.index, gc.values, color=BLUE, marker='o', ms=3, lw=1.0)
a.text(210, 0.60, 'naive', color=ORANGE, fontsize=7); a.text(55, 1.012, 'guaranteed (certified draws)', color=BLUE, fontsize=6.5, va='bottom')
a.set_xscale('log'); a.set_xticks(ks); a.set_xticklabels([str(k) for k in ks]); a.minorticks_off()
a.set_ylim(0.4, 1.08); a.set_xlabel('labelled alerts $k$'); a.set_ylabel('coverage (share of draws\nwith recall $\\geq$ 0.90)')
b = ax[1]
b.plot(ks, naive.cleared.loc[ks], color=ORANGE, marker='s', ms=3, lw=1.0, ls='--')
b.plot(ks, gcl.loc[ks], color=BLUE, marker='o', ms=3, lw=1.0)
b.text(60, 0.885, 'naive', color=ORANGE, fontsize=7); b.text(150, 0.30, 'guaranteed', color=BLUE, fontsize=7)
b.set_xscale('log'); b.set_xticks(ks); b.set_xticklabels([str(k) for k in ks]); b.minorticks_off()
b.set_ylim(0.0, 1.0); b.set_xlabel('labelled alerts $k$'); b.set_ylabel('benign alerts cleared')
for x in ax:
    x.spines[['top', 'right']].set_visible(False); x.tick_params(width=0.5, length=2)
    x.grid(axis='y', color='#e5e7eb', lw=0.4)
fig.tight_layout(pad=0.4)
fig.savefig('fig_guarantee.png', dpi=300)
print('saved; guaranteed certified coverage by k:', gc.round(3).to_dict(), ' naive:', naive.coverage.round(3).to_dict())
print('guaranteed cleared by k:', gcl.round(3).to_dict(), 'naive cleared:', naive.cleared.round(3).to_dict(), 'fallback:', fb.round(3).to_dict())
