"""Column-width versions of the two panels of the threshold-mechanism figure (same seeded illustrative simulation as fig_rule.py):
fig_rule_a.png  -- stream + labelled sample + threshold t = s_(r)
fig_rule_b.png  -- the Beta-bound curve that chooses r"""
import os, numpy as np
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from scipy import stats

HERE = os.path.dirname(os.path.abspath(__file__))
plt.rcParams.update({'font.family': 'serif', 'font.serif': ['STIXGeneral', 'Times New Roman'], 'mathtext.fontset': 'stix',
    'font.size': 8, 'axes.labelsize': 8, 'xtick.labelsize': 7, 'ytick.labelsize': 7, 'axes.linewidth': 0.6,
    'xtick.direction': 'in', 'ytick.direction': 'in', 'savefig.dpi': 500, 'pdf.fonttype': 42})
BLUE, RED = '#1f4e9c', '#b22222'
rho, delta = 0.90, 0.10

rng = np.random.default_rng(11)                       # identical simulation to fig_rule.py
N = 600; attack = rng.random(N) < 0.25
sc = np.where(attack, rng.beta(5.0, 1.7, N), rng.beta(1.3, 7.0, N))
lab = rng.choice(N, 160, replace=False); mask = np.zeros(N, bool); mask[lab] = True
sa = np.sort(sc[mask & attack]); n = len(sa)
r = max(rr for rr in range(1, n + 1) if stats.beta.cdf(1 - rho, rr, n - rr + 1) >= 1 - delta)
t = sa[r - 1]
rec = (sc[attack & ~mask] >= t).mean(); clr = (sc[~attack & ~mask] < t).mean()
print(f'n={n} r={r} t={t:.3f} held-out recall={rec:.3f} cleared={clr:.3f}')

def jit(k, seed): return np.random.default_rng(seed).uniform(-0.3, 0.3, k)

# ------------------------------------------------------------------ (a)
fig, ax = plt.subplots(figsize=(3.45, 2.0))
Y_S, Y_L = 2.1, 0.7
hb = ~attack & ~mask; ha = attack & ~mask; lb = mask & ~attack; la = mask & attack
ax.scatter(sc[hb], Y_S + jit(hb.sum(), 1), s=4, c='#9a9a9a', lw=0)
ax.scatter(sc[ha], Y_S + jit(ha.sum(), 2), s=4, c=BLUE, lw=0)
ax.scatter(sc[lb], Y_L + jit(lb.sum(), 3), s=8, facecolors='none', edgecolors='#8a8a8a', lw=0.45)
ax.scatter(sc[la], Y_L + jit(la.sum(), 4), s=8, facecolors='none', edgecolors=BLUE, lw=0.45)
ax.scatter(sa[:r], np.full(r, Y_L), s=8, c=BLUE, lw=0, zorder=5)
ax.axvline(t, color=RED, lw=1.0, ls='--', zorder=6)
ax.axvspan(-0.02, t, color='#efefef', zorder=0); ax.axvspan(t, 1.02, color='#e6eef9', zorder=0)
ax.text(t - 0.015, 3.3, f'auto-closed\n{clr*100:.0f}% of benign', fontsize=6.6, ha='right', va='top', linespacing=1.15)
ax.text(t + 0.015, 3.3, f'to review\n{rec*100:.0f}% of attacks', fontsize=6.6, ha='left', va='top', color=BLUE, linespacing=1.15)
ax.text(t + 0.015, 3.45, '$t=s_{(r)}$', color=RED, ha='left', va='bottom', fontsize=8)
if r > 1:
    ax.text(t - 0.015, 0.12, f'{r-1} labelled attack below $t$' if r == 2 else f'{r-1} labelled attacks below $t$', fontsize=6.4, ha='right', va='top', color=BLUE)
ax.set_yticks([Y_S, Y_L]); ax.set_yticklabels(['held-out\nstream', f'labelled\nsample'], fontsize=7)
ax.set_ylim(-0.3, 3.75); ax.set_xlim(-0.02, 1.02); ax.set_xlabel('classifier score $s$')
ax.set_xticks([0, 0.2, 0.4, 0.6, 0.8, 1.0]); ax.tick_params(left=False, right=False, top=False)
for sp in ('top', 'right', 'left'): ax.spines[sp].set_visible(False)
fig.tight_layout(pad=0.3)
fig.savefig(os.path.join(HERE, 'fig_rule_a.png'), bbox_inches='tight', pad_inches=0.02); plt.close(fig)

# ------------------------------------------------------------------ (b)
fig, ax = plt.subplots(figsize=(3.45, 1.75))
rs = np.arange(1, min(n, 12) + 1); pv = stats.beta.cdf(1 - rho, rs, n - rs + 1)
ax.plot(rs, pv, 'o-', color='k', lw=0.9, ms=3)
ax.axhline(1 - delta, color=RED, lw=0.8, ls='--'); ax.text(rs[-1], 1 - delta + 0.04, f'$1-\\delta={1-delta:.1f}$', color=RED, fontsize=7, ha='right')
ax.plot([r], [pv[r - 1]], 'o', color=RED, ms=5.5, zorder=5)
ax.annotate(f'$r={r}$: largest $r$\nabove the line', (r, pv[r - 1]), xytext=(r + 1.6, 0.6), fontsize=6.8, ha='left', arrowprops=dict(arrowstyle='-', lw=0.5))
ax.set_xlim(0.5, rs[-1] + 0.5); ax.set_ylim(0, 1.1); ax.set_xticks(rs[::2] if len(rs) > 8 else rs)
ax.set_xlabel('candidate rank $r$'); ax.set_ylabel(r'$\Pr[\mathrm{Beta}(r,n{-}r{+}1)\leq 1{-}\rho]$', fontsize=7)
ax.grid(color='#cccccc', ls=':', lw=0.5); ax.tick_params(top=True, right=True)
fig.tight_layout(pad=0.3)
fig.savefig(os.path.join(HERE, 'fig_rule_b.png'), bbox_inches='tight', pad_inches=0.02); plt.close(fig)
print('saved fig_rule_a.png, fig_rule_b.png')
