"""Scores a human annotator's blind labels (my_labels.json from audit_tool.html) against our labels
(private_key/audit_key.json). Usage: python score_audit.py my_labels.json

Reports, with the repeated items excluded from agreement statistics and used only for consistency:
  - Q1 (malicious?) agreement with our label overall and per stratum, Cohen's kappa (unsure excluded)
  - Q2 (escalate?) agreement with our label
  - the key policy finding: for scanner-noise alerts (which we labelled benign), how often the annotator
    judges them malicious (fact) vs escalation-worthy (policy)
  - annotator self-consistency on the 6 repeated items
Small sample (about 64 items): kappa has wide uncertainty; a 95% bootstrap interval is given."""
import json, sys
import numpy as np
from sklearn.metrics import cohen_kappa_score

labels = {x['id']: x for x in json.load(open(sys.argv[1]))}
key = {x['id']: x for x in json.load(open('private_key/audit_key.json'))}
rng = np.random.default_rng(0)

def yn(v): return {'yes': 1, 'no': 0}.get(v)

core = [k for k in key.values() if k['repeat_of'] is None]
answered = [k for k in core if labels.get(k['id']) and labels[k['id']]['q1'] and labels[k['id']]['q2']]
print(f"core items answered: {len(answered)}/{len(core)}")
if len(answered) < 20: print("WARNING: too few answers for meaningful statistics")

def agreement(q, items):
    pairs = [(int(k['ours_attack']), yn(labels[k['id']][q])) for k in items if yn(labels[k['id']][q]) is not None]
    if not pairs: return None
    a = np.array(pairs); return (a[:, 0] == a[:, 1]).mean(), len(a), a

print("\nAgreement with OUR labels (human says yes -> attack / escalate):")
for q, name in (('q1', 'Q1 malicious?'), ('q2', 'Q2 escalate?')):
    res = agreement(q, answered)
    if not res: continue
    ag, n, a = res
    kap = cohen_kappa_score(a[:, 0], a[:, 1]) if len(set(a[:, 0])) > 1 and len(set(a[:, 1])) > 1 else float('nan')
    boots = []
    for _ in range(2000):
        b = a[rng.integers(0, n, n)]
        if len(set(b[:, 0])) > 1 and len(set(b[:, 1])) > 1: boots.append(cohen_kappa_score(b[:, 0], b[:, 1]))
    ci = (np.percentile(boots, 2.5), np.percentile(boots, 97.5)) if boots else (float('nan'),) * 2
    print(f"  {name:16s} agreement {ag:.2f} (n={n}), Cohen kappa {kap:.2f}  95% CI [{ci[0]:.2f}, {ci[1]:.2f}]")

print("\nPer stratum: share of items where the annotator answered 'yes'")
print(f"  {'stratum':22s} {'our label':>10s} {'Q1 malicious':>13s} {'Q2 escalate':>12s}  n")
for s in ('r4_attack', 'r4_scanner_noise', 'r4_other_benign', 'ait_in_window', 'ait_outside_window'):
    items = [k for k in answered if k['stratum'] == s]
    if not items: continue
    q1 = [yn(labels[k['id']]['q1']) for k in items if yn(labels[k['id']]['q1']) is not None]
    q2 = [yn(labels[k['id']]['q2']) for k in items]
    print(f"  {s:22s} {'attack' if items[0]['ours_attack'] else 'benign':>10s} {np.mean(q1) if q1 else float('nan'):13.2f} {np.mean(q2):12.2f}  {len(items)}")

rep = [k for k in key.values() if k['repeat_of'] is not None and labels.get(k['id']) and labels.get(k['repeat_of'])
       and labels[k['id']]['q1'] and labels[k['repeat_of']]['q1']]
if rep:
    c1 = np.mean([labels[k['id']]['q1'] == labels[k['repeat_of']]['q1'] for k in rep])
    c2 = np.mean([labels[k['id']]['q2'] == labels[k['repeat_of']]['q2'] for k in rep])
    print(f"\nSelf-consistency on {len(rep)} repeated items: Q1 {c1:.2f}, Q2 {c2:.2f}")
unsure = sum(1 for k in answered if labels[k['id']]['q1'] == 'unsure')
print(f"'Unsure' on Q1: {unsure}/{len(answered)}")
