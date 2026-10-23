"""Builds a fixed-seed sample of the public AIT Alert Data Set (AIT-ADS, Landauer et al.,
Zenodo 8263181, CC BY 4.0): Wazuh alerts from 8 simulated enterprise scenarios.

Label (documented limitation): an alert is 'attack' if its timestamp falls inside ANY attack
phase window listed in the dataset's labels.csv for that scenario; otherwise 'benign'. This is
window-level, so benign alerts occurring during an attack window are labelled attack (label noise
inherent to this dataset's label granularity).

Uniform random sample of N alerts per scenario (seed 0), preserving each scenario's natural
attack prevalence (7%-89%), written to external_data/ait_ads/ait_sample.csv.
"""
import json, csv, glob, random, collections
from datetime import datetime

N = 4000
D = '../external_data/ait_ads/'
windows = collections.defaultdict(list)
for r in csv.DictReader(open(D + 'labels.csv')):
    windows[r['scenario']].append((float(r['start']), float(r['end'])))

rng = random.Random(0)
rows = []
for f in sorted(glob.glob(D + 'raw/*_wazuh.json')):
    sc = f.replace('\\', '/').split('/')[-1].split('_')[0]
    lines = open(f, encoding='utf-8', errors='replace').read().splitlines()
    for line in rng.sample(lines, min(N, len(lines))):
        try:
            a = json.loads(line)
            t = datetime.fromisoformat(a['@timestamp'].replace('Z', '+00:00'))
        except Exception:
            continue
        ts = t.timestamp()
        rows.append({'scenario': sc, 'timestamp': t.isoformat(), 'rule_level': a['rule']['level'],
                     'rule_description': a['rule'].get('description', ''), 'rule_groups': '|'.join(a['rule'].get('groups', [])),
                     'decoder': a.get('decoder', {}).get('name', ''), 'full_log': a.get('full_log', ''),
                     'src_ip': a.get('agent', {}).get('ip', ''),
                     'is_true_positive': any(s <= ts <= e for s, e in windows[sc])})
with open(D + 'ait_sample.csv', 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
c = collections.Counter((r['scenario'], r['is_true_positive']) for r in rows)
print(len(rows), 'rows'); print(sorted(c.items()))
