"""Two non-chart data figures in journal style.
 fig_opmap  : operating-point map -- the same eight methods placed on the (benign cleared, attack recall) plane, over the
              F1 field at the test-set prevalence (82 %) and over the review-burden field at a realistic 5 %.
 fig_heat   : scenario x label-budget heat maps of certified coverage and of benign alerts cleared (LogReg, rho = 0.9).
Numbers come from ../paper_experiments (exp. 24 for TPR/FPR, 16 for 'LogReg + 20 labels', 23 for the guarantee study)."""
import os, numpy as np, pandas as pd
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap, TwoSlopeNorm

HERE = os.path.dirname(os.path.abspath(__file__)); EXP = os.path.join(HERE, '..', 'paper_experiments')
plt.rcParams.update({'font.family': 'serif', 'font.serif': ['STIXGeneral', 'Times New Roman'], 'mathtext.fontset': 'stix',
    'font.size': 8, 'axes.labelsize': 8, 'xtick.labelsize': 7, 'ytick.labelsize': 7, 'axes.linewidth': 0.6,
    'xtick.direction': 'in', 'ytick.direction': 'in', 'savefig.dpi': 400, 'pdf.fonttype': 42})
def save(fig, name):
    fig.savefig(os.path.join(HERE, name + '.png'), bbox_inches='tight', pad_inches=0.02)
    fig.savefig(os.path.join(HERE, name + '.pdf'), bbox_inches='tight', pad_inches=0.02); plt.close(fig); print('saved', name)

# ================================================================== heat maps of the guarantee study
c = pd.read_csv(os.path.join(EXP, '23_per_cell_results.csv'))
g = c[(c.model == 'LogReg') & (c.rho == 0.90) & (c.rule == 'guaranteed')]
prev = g.groupby('scenario').prev.first().sort_values(); scen = list(prev.index); ks = [50, 100, 200, 500, 1000]
cov = np.full((len(scen), len(ks)), np.nan); clr = np.full_like(cov, np.nan); fb = np.zeros_like(cov)
for i, s in enumerate(scen):
    for j, k in enumerate(ks):
        r = g[(g.scenario == s) & (g.k == k)].iloc[0]
        fb[i, j] = r.fallback
        if r.fallback < 0.5:
            cov[i, j] = (r.coverage - r.fallback) / (1 - r.fallback)
        clr[i, j] = r.cleared
nv = c[(c.model == 'LogReg') & (c.rho == 0.90) & (c.rule == 'naive') & (c.k == 200)].set_index('scenario').coverage.reindex(scen).values
fig, ax = plt.subplots(1, 2, figsize=(7.16, 2.45), sharey=True)
ylab = [f'{s}  ({p * 100:.0f}%)' for s, p in zip(scen, prev.values)]
cm_cov = LinearSegmentedColormap.from_list('c', ['#b22222', '#f4d3c4', '#ffffff', '#c9d9ef', '#1f4e9c'])
im = ax[0].imshow(np.ma.masked_invalid(cov), cmap=cm_cov, norm=TwoSlopeNorm(vmin=0.7, vcenter=0.9, vmax=1.0), aspect='auto')
cm_clr = LinearSegmentedColormap.from_list('d', ['#ffffff', '#c9d9ef', '#1f4e9c'])
im2 = ax[1].imshow(clr, cmap=cm_clr, vmin=0, vmax=1, aspect='auto')
for i in range(len(scen)):
    for j in range(len(ks)):
        if np.isnan(cov[i, j]):
            ax[0].add_patch(plt.Rectangle((j - .5, i - .5), 1, 1, fc='#eeeeee', ec='white', hatch='////', lw=0)); ax[0].text(j, i, 'no cert.', ha='center', va='center', fontsize=5.8, color='#666666')
        else:
            ax[0].text(j, i, f'{cov[i, j]:.2f}', ha='center', va='center', fontsize=6.8, color='white' if cov[i, j] > 0.985 else 'k')
        ax[1].text(j, i, f'{clr[i, j]:.2f}', ha='center', va='center', fontsize=6.8, color='white' if clr[i, j] > 0.6 else 'k')
for a in ax:
    a.set_xticks(range(len(ks))); a.set_xticklabels(ks); a.set_xlabel('Labelled alerts $k$')
    a.set_xticks(np.arange(-.5, len(ks), 1), minor=True); a.set_yticks(np.arange(-.5, len(scen), 1), minor=True)
    a.grid(which='minor', color='white', lw=1.2); a.tick_params(which='minor', length=0); a.tick_params(length=0)
    for sp in a.spines.values(): sp.set_visible(False)
ax[0].set_yticks(range(len(scen))); ax[0].set_yticklabels(ylab); ax[0].set_ylabel('Scenario (attack prevalence)')
for a, t in zip(ax, ['(a) Coverage of recall $\\geq 0.9$ among certified trials\n      (blue $\\geq$ 0.9 target, red below)', '(b) Benign alerts cleared at the guaranteed threshold']):
    a.text(0.5, -0.27, t, transform=a.transAxes, ha='center', va='top', fontsize=7.3)
cb = fig.colorbar(im, ax=ax[0], fraction=0.04, pad=0.02, ticks=[0.7, 0.8, 0.9, 1.0]); cb.ax.tick_params(labelsize=6, length=2); cb.outline.set_linewidth(0.4)
cb2 = fig.colorbar(im2, ax=ax[1], fraction=0.04, pad=0.02, ticks=[0, 0.5, 1.0]); cb2.ax.tick_params(labelsize=6, length=2); cb2.outline.set_linewidth(0.4)
fig.tight_layout(w_pad=0.6)
save(fig, 'fig_heat')
