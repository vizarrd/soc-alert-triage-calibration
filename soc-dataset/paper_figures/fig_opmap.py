"""Operating-point map: the same eight methods on the (false-positive rate, recall) plane, drawn over (a) the F1 field at
the test-set prevalence (82 % attacks) and (b) the review-burden field at a realistic 5 % prevalence.
TPR/FPR: exp. 24 (round 4, mean over seeds); 'LogReg + 20 labels': exp. 16."""
import os, numpy as np
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

HERE = os.path.dirname(os.path.abspath(__file__))
plt.rcParams.update({'font.family': 'serif', 'font.serif': ['STIXGeneral', 'Times New Roman'], 'mathtext.fontset': 'stix',
    'font.size': 8, 'axes.labelsize': 8, 'xtick.labelsize': 7, 'ytick.labelsize': 7, 'axes.linewidth': 0.6,
    'xtick.direction': 'in', 'ytick.direction': 'in', 'savefig.dpi': 400, 'pdf.fonttype': 42})

fpr = np.logspace(np.log10(0.03), np.log10(1.0), 500); tpr = np.linspace(0.2, 1.0, 400)
FP, TP = np.meshgrid(fpr, tpr)
def prec(pi): return pi * TP / (pi * TP + (1 - pi) * FP)
F1 = 2 * prec(0.823) * TP / (prec(0.823) + TP)
BUR = 1 / prec(0.05)

fig, ax = plt.subplots(1, 2, figsize=(7.16, 3.1), sharey=True)
blues = LinearSegmentedColormap.from_list('b', ['#ffffff', '#d3e0f3', '#8fb0de'])
ax[0].contourf(FP, TP, F1, levels=np.arange(0.2, 1.01, 0.1), cmap=blues)
cs = ax[0].contour(FP, TP, F1, levels=[0.4, 0.6, 0.8, 0.9], colors='#35557f', linewidths=0.5)
def f1_pos(L, x):
    ix = np.argmin(abs(fpr - x)); return (x, tpr[np.argmin(abs(F1[:, ix] - L))])
ax[0].clabel(cs, fmt=lambda v: f'F1 = {v:.1f}', fontsize=6, inline=True, levels=[0.4, 0.6, 0.8], manual=[f1_pos(0.4, 0.3), f1_pos(0.6, 0.3), f1_pos(0.8, 0.3)])
rev = LinearSegmentedColormap.from_list('r', ['#8fb0de', '#d3e0f3', '#ffffff'])
ax[1].contourf(FP, TP, np.log10(BUR), levels=np.log10([1, 1.5, 2, 3, 5, 10, 20, 50, 200]), cmap=rev)
cs2 = ax[1].contour(FP, TP, BUR, levels=[2, 5, 10, 20, 50], colors='#35557f', linewidths=0.5)
def bur_pos(B, y):
    iy = np.argmin(abs(tpr - y)); return (fpr[np.argmin(abs(BUR[iy] - B))], y)
ax[1].clabel(cs2, levels=[2, 5, 10, 20], fmt=lambda v: f'{v:g} per attack', fontsize=6, inline=True, manual=[bur_pos(2, 0.72), bur_pos(5, 0.72), bur_pos(10, 0.72), bur_pos(20, 0.62)])

pts = {  # name: (fpr, tpr, colour, marker, size)
    'flag': (1.0, 1.0, 'k', 'x', 5), 'llm': (0.976, 1.0, '#8e44ad', 'D', 4.2), 'lr': (0.935, 1.0, '#1f4e9c', 'o', 4.4),
    'xgb': (0.919, 0.545, '#c77700', 'P', 5), 'mlp': (0.189, 0.561, '#00838f', 'v', 5), 'rf': (0.056, 0.319, '#2e7d32', '^', 5),
    'ens': (0.049, 0.512, '#b22222', 'X', 5), 'lr20': (0.065, 0.963, '#1f4e9c', '*', 10)}
for a in ax:
    for k, (x, y, c, m, sz) in pts.items():
        a.plot(x, y, marker=m, color=c, ms=sz, mec='k' if m not in 'x' else c, mew=0.45, ls='none', zorder=6, clip_on=False)
def lab(a, k, text, xy, ha='left', col=None):
    x, y, c, *_ = pts[k]
    a.annotate(text, (x, y), xytext=xy, fontsize=6.6, ha=ha, va='center', color=col or c, zorder=7,
               bbox=dict(boxstyle='round,pad=0.12', fc='white', ec='none', alpha=0.85),
               arrowprops=dict(arrowstyle='-', lw=0.45, color='#333333', shrinkA=0, shrinkB=3))
for a in ax:
    lab(a, 'lr20', 'LogReg + 20 labels', (0.085, 0.86), col='#1f4e9c')
    lab(a, 'rf', 'Random forest', (0.075, 0.27))
    lab(a, 'ens', 'RF + accumulation', (0.075, 0.47))
    lab(a, 'mlp', 'MLP', (0.26, 0.50))
    lab(a, 'xgb', 'XGBoost', (0.55, 0.45))
    a.annotate('Flag everything, LLM,\nrule-level, LogReg (default)', (0.96, 1.0), xytext=(0.30, 0.93), fontsize=6.6, ha='left', va='center',
               bbox=dict(boxstyle='round,pad=0.12', fc='white', ec='none', alpha=0.85), zorder=7,
               arrowprops=dict(arrowstyle='-', lw=0.45, color='#333333', shrinkA=0, shrinkB=4))
    a.set_xscale('log'); a.set_xlim(0.03, 1.1); a.set_ylim(0.2, 1.04)
    a.set_xticks([0.05, 0.1, 0.2, 0.5, 1.0]); a.set_xticklabels(['0.05', '0.1', '0.2', '0.5', '1.0']); a.minorticks_off()
    a.set_xlabel('False-positive rate (share of benign alerts still reviewed)')
    a.tick_params(top=True, right=True)
    a.text(0.035, 1.015, r'$\nwarrow$ better', fontsize=6.6, color='#35557f', va='top', zorder=7)
ax[0].set_ylabel('Recall (share of attacks flagged)')
for a, t in zip(ax, ['(a) Our test set (82% attacks): shading shows F1', '(b) Realistic SOC (5% attacks): shading shows review burden']):
    a.text(0.5, -0.26, t, transform=a.transAxes, ha='center', va='top', fontsize=7.5)
fig.tight_layout(w_pad=0.8)
for ext in ('png', 'pdf'): fig.savefig(os.path.join(HERE, f'fig_opmap.{ext}'), bbox_inches='tight', pad_inches=0.02)
print('saved fig_opmap')
