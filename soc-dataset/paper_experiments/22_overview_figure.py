"""Overview figure for the paper: pipeline from Wazuh alert to analyst, with the
label-based threshold calibration loop. Pure matplotlib, no data."""
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

fig, ax = plt.subplots(figsize=(7.2, 2.6)); ax.set_xlim(0, 100); ax.set_ylim(0, 36); ax.axis('off')

def box(x, y, w, h, text, fc):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.4,rounding_size=1.2', fc=fc, ec='#333', lw=1))
    ax.text(x + w / 2, y + h / 2, text, ha='center', va='center', fontsize=7)

def arrow(x1, y1, x2, y2, style='-|>', ls='-'):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=9, lw=1, color='#333', ls=ls))

box(1, 20, 14, 10, 'Wazuh\nalerts\n(stream)', '#e8eef7')
box(20, 20, 17, 10, 'Clean text\n+ features\n(IDs removed)', '#e8eef7')
box(42, 20, 15, 10, 'Frozen model\nattack score\ns in [0,1]', '#fff1d6')
box(62, 20, 15, 10, 'Threshold t\nscore >= t ?', '#fde2e2')
box(83, 25, 15, 8, 'Send to\nanalyst', '#dff2e1')
box(83, 14, 15, 8, 'Auto-close\n(noise)', '#eeeeee')
box(42, 2, 35, 10, 'Calibration (new environment)\nanalyst labels n random alerts\n-> t with recall guarantee', '#f3e5f5')
arrow(15.5, 25, 19.5, 25); arrow(37.5, 25, 41.5, 25); arrow(57.5, 25, 61.5, 25)
arrow(77.5, 27, 82.5, 29); arrow(77.5, 23, 82.5, 18)
arrow(59.5, 12.5, 69.5, 19.5, ls='--')
ax.text(64, 14.5, 'sets t', fontsize=6.5, style='italic')
ax.text(1, 6, 'Dashed: runs once per new environment,\nthen again whenever drift is suspected.', fontsize=6.5, va='center')
fig.tight_layout(); fig.savefig('fig_overview.png', dpi=300)
print('saved fig_overview.png')
