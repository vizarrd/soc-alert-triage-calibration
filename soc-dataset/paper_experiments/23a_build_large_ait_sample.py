"""Large-scale sample of the public AIT-ADS Wazuh alerts: up to 50,000 uniformly sampled alerts per
scenario (all alerts if a scenario has fewer), same window-level labels as 18a. Used by
experiment 23 for full-stream evaluation of the recall-guaranteed threshold.
Output: external_data/ait_ads/ait_large.csv"""
import json, csv, glob, random, collections
from datetime import datetime

N = 50000
D = '../external_data/ait_ads/'
windows = collections.defaultdict(list)
for r in csv.DictReader(open(D + 'labels.csv')):
    windows[r['scenario']].append((float(r['start']), float(r['end'])))

rng = random.Random(1)
fields = ['scenario', 'timestamp', 'rule_level', 'rule_description', 'rule_groups', 'decoder', 'full_log', 'src_ip', 'is_true_positive']
tot = collections.Counter()
with open(D + 'ait_large.csv', 'w', newline='', encoding='utf-8') as out:
    w = csv.DictWriter(out, fieldnames=fields); w.writeheader()
    for f in sorted(glob.glob(D + 'raw/*_wazuh.json')):
        sc = f.replace('\\', '/').split('/')[-1].split('_')[0]
        lines = open(f, encoding='utf-8', errors='replace').read().splitlines()
        for line in rng.sample(lines, min(N, len(lines))):
            try:
                a = json.loads(line)
                t = datetime.fromisoformat(a['@timestamp'].replace('Z', '+00:00'))
            except Exception:
                continue
            ts = t.timestamp(); y = any(s <= ts <= e for s, e in windows[sc])
            w.writerow({'scenario': sc, 'timestamp': t.isoformat(), 'rule_level': a['rule']['level'],
                        'rule_description': a['rule'].get('description', ''), 'rule_groups': '|'.join(a['rule'].get('groups', [])),
                        'decoder': a.get('decoder', {}).get('name', ''), 'full_log': a.get('full_log', ''),
                        'src_ip': a.get('agent', {}).get('ip', ''), 'is_true_positive': y})
            tot[(sc, y)] += 1
        print(sc, 'done', flush=True)
print(sorted(tot.items()))
