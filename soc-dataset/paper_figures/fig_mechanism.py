"""Overview + mechanism figure.
(a) pipeline strip; (b) ILLUSTRATIVE seeded simulation (not experimental data): a stream of scored alerts, k uniformly drawn
labelled alerts, and the order-statistic threshold; (c) the Beta-bound curve that picks r for that sample."""
import os, numpy as np
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from scipy import stats

HERE = os.path.dirname(os.path.abspath(__file__))
plt.rcParams.update({'font.family': 'serif', 'font.serif': ['STIXGeneral', 'Times New Roman'], 'mathtext.fontset': 'stix',
    'font.size': 8, 'axes.labelsize': 8, 'xtick.labelsize': 7, 'ytick.labelsize': 7, 'axes.linewidth': 0.6,
    'xtick.direction': 'in', 'ytick.direction': 'in', 'savefig.dpi': 400, 'pdf.fonttype': 42})
BLUE, RED, GRY = '#1f4e9c', '#b22222', '#8a8a8a'
rho, delta = 0.90, 0.10

# ---- illustrative stream (seeded): benign mostly low, attacks mostly high with a hard tail
rng = np.random.default_rng(11)
N = 600; attack = rng.random(N) < 0.25
sc = np.where(attack, rng.beta(5.0, 1.7, N), rng.beta(1.3, 7.0, N))
lab = rng.choice(N, 160, replace=False); mask = np.zeros(N, bool); mask[lab] = True
sa = np.sort(sc[mask & attack]); n = len(sa)
r = max(rr for rr in range(1, n + 1) if stats.beta.cdf(1 - rho, rr, n - rr + 1) >= 1 - delta)
t = sa[r - 1]
rec = (sc[attack & ~mask] >= t).mean(); clr = (sc[~attack & ~mask] < t).mean()
print(f'n={n} r={r} t={t:.3f} held-out recall={rec:.3f} cleared={clr:.3f}')

fig = plt.figure(figsize=(7.16, 3.55))
gs = fig.add_gridspec(2, 2, height_ratios=[0.5, 1.0], width_ratios=[1.9, 1.0], hspace=0.5, wspace=0.26, left=0.075, right=0.985, top=0.99, bottom=0.12)

# ---------------------------------------------------------------- (a)
axa = fig.add_subplot(gs[0, :]); axa.set_xlim(0, 100); axa.set_ylim(0, 10); axa.axis('off')
def box(x, w, txt, fc='white', ec='k', lw=0.6):
    axa.add_patch(FancyBboxPatch((x, 3.4), w, 5.4, boxstyle='round,pad=0,rounding_size=0.7', fc=fc, ec=ec, lw=lw))
    axa.text(x + w / 2, 6.1, txt, ha='center', va='center', fontsize=7)
def arr(p, q, col='k', lw=0.6):
    axa.add_patch(FancyArrowPatch(p, q, arrowstyle='-|>', mutation_scale=6, lw=lw, color=col, shrinkA=0, shrinkB=0))
box(0.5, 13.5, 'Wazuh alert\n$a_i$'); box(19.5, 16, 'features\n$\\mathbf{x}_i=\\phi(a_i)$'); box(41, 18, 'frozen classifier\n$s_i=f(\\mathbf{x}_i)$')
box(65, 12, 'gate\n$s_i\\geq t\\,?$', ec=RED, lw=0.9)
for x0, x1 in ((14, 19.5), (35.5, 41), (59, 65)): arr((x0, 6.1), (x1, 6.1))
axa.add_patch(FancyBboxPatch((83, 5.9), 16.5, 2.9, boxstyle='round,pad=0,rounding_size=0.7', fc='#e6f0e6', ec='k', lw=0.6)); axa.text(91.25, 7.35, 'analyst review', fontsize=7, ha='center', va='center')
axa.add_patch(FancyBboxPatch((83, 2.2), 16.5, 2.9, boxstyle='round,pad=0,rounding_size=0.7', fc='#eeeeee', ec=GRY, lw=0.6)); axa.text(91.25, 3.65, 'auto-close', fontsize=7, ha='center', va='center', color='#555555')
axa.plot([77, 80], [6.1, 6.1], color='k', lw=0.6); axa.plot([80, 80], [3.65, 7.35], color='k', lw=0.6)
arr((80, 7.35), (83, 7.35)); arr((80, 3.65), (83, 3.65))
axa.text(81.5, 8.1, 'yes', fontsize=6.3, ha='center'); axa.text(81.5, 2.9, 'no', fontsize=6.3, ha='center', color=GRY)
axa.text(71, 9.9, 'threshold $t$ from the calibration below', fontsize=6.6, color=RED, ha='center'); arr((71, 9.5), (71, 8.85), col=RED, lw=0.8)
axa.text(0.5, 0.4, '(a) Triage pipeline: only the threshold $t$ is re-calibrated', fontsize=7.5, va='bottom')

# ---------------------------------------------------------------- (b)
axb = fig.add_subplot(gs[1, 0])
def jit(k, seed): return np.random.default_rng(seed).uniform(-0.3, 0.3, k)
Y_S, Y_L = 2.1, 0.7
hb = ~attack & ~mask; ha = attack & ~mask
axb.scatter(sc[hb], Y_S + jit(hb.sum(), 1), s=4, c='#9a9a9a', lw=0)
axb.scatter(sc[ha], Y_S + jit(ha.sum(), 2), s=4, c=BLUE, lw=0)
lb = mask & ~attack; la = mask & attack
axb.scatter(sc[lb], Y_L + jit(lb.sum(), 3), s=9, facecolors='none', edgecolors='#8a8a8a', lw=0.5)
axb.scatter(sc[la], Y_L + jit(la.sum(), 4), s=9, facecolors='none', edgecolors=BLUE, lw=0.5)
axb.scatter(sa[:r], np.full(r, Y_L), s=9, c=BLUE, lw=0, zorder=5)
axb.axvline(t, color=RED, lw=1.0, ls='--', zorder=6)
axb.axvspan(-0.02, t, color='#efefef', zorder=0); axb.axvspan(t, 1.02, color='#e6eef9', zorder=0)
axb.text(t - 0.012, 3.35, f'auto-closed: {clr*100:.0f}% of\nheld-out benign alerts', fontsize=6.6, ha='right', va='top')
axb.text(t + 0.012, 3.35, f'review: {rec*100:.0f}% of\nheld-out attacks', fontsize=6.6, ha='left', va='top', color=BLUE)
axb.text(t, 3.5, '$t=s_{(r)}$', color=RED, ha='center', va='bottom', fontsize=8)
if r > 1:
    axb.text(t, 0.05, f'{r-1} labelled attack(s) below $t$', fontsize=6.5, ha='center', va='top', color=BLUE)
axb.set_yticks([Y_S, Y_L]); axb.set_yticklabels([f'held-out stream\n({(~mask).sum()} alerts)', f'labelled sample\n$k={mask.sum()}$, $n={n}$ attacks'], fontsize=7)
axb.set_ylim(-0.35, 3.55); axb.set_xlim(-0.02, 1.02); axb.set_xlabel('classifier score $s$')
axb.set_xticks([0, 0.2, 0.4, 0.6, 0.8, 1.0]); axb.tick_params(left=False, right=False, top=False)
for sp in ('top', 'right', 'left'): axb.spines[sp].set_visible(False)
axb.text(0.5, -0.36, '(b) Threshold from $k$ random labels (illustrative simulation)', transform=axb.transAxes, ha='center', va='top', fontsize=7.5)

# ---------------------------------------------------------------- (c)
axc = fig.add_subplot(gs[1, 1])
rs = np.arange(1, min(n, 12) + 1); pv = stats.beta.cdf(1 - rho, rs, n - rs + 1)
axc.plot(rs, pv, 'o-', color='k', lw=0.9, ms=3)
axc.axhline(1 - delta, color=RED, lw=0.8, ls='--'); axc.text(rs[-1], 1 - delta + 0.04, f'$1-\\delta={1-delta:.1f}$', color=RED, fontsize=6.8, ha='right')
axc.plot([r], [pv[r - 1]], 'o', color=RED, ms=5.5, zorder=5)
axc.annotate(f'$r={r}$: largest $r$\nabove the line', (r, pv[r - 1]), xytext=(r + 1.5, 0.72), fontsize=6.6, ha='left', arrowprops=dict(arrowstyle='-', lw=0.5))
axc.set_xlim(0.5, rs[-1] + 0.5); axc.set_ylim(0, 1.08); axc.set_xticks(rs[::2] if len(rs) > 8 else rs)
axc.set_xlabel('candidate rank $r$'); axc.set_ylabel(r'$\Pr[\mathrm{Beta}(r,n{-}r{+}1)\leq 1{-}\rho]$', fontsize=7)
axc.grid(color='#cccccc', ls=':', lw=0.5); axc.tick_params(top=True, right=True)
axc.text(0.5, -0.36, f'(c) Choosing $r$ ($n={n}$, $\\rho={rho:.1f}$, $\\delta={delta:.1f}$)', transform=axc.transAxes, ha='center', va='top', fontsize=7.5)
for ext in ('png', 'pdf'): fig.savefig(os.path.join(HERE, f'fig_mechanism.{ext}'), bbox_inches='tight', pad_inches=0.02)
print('saved fig_mechanism')
