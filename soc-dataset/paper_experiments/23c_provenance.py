"""Data provenance of the large-scale AIT-ADS experiment (exp. 23): how many alerts exist per scenario,
how many were sampled, whether sampling was with replacement, and how many of the sampled alerts have
distinct log text (repeated text is common: scans, retries). Answers 'where do 391k alerts come from'."""
import glob, os
import pandas as pd
raw = {}
for f in sorted(glob.glob('../external_data/ait_ads/raw/*_wazuh.json')):
    sc = os.path.basename(f).split('_')[0]
    with open(f, encoding='utf-8', errors='replace') as fh:
        raw[sc] = sum(1 for _ in fh)
d = pd.read_csv('../external_data/ait_ads/ait_large.csv', keep_default_na=False)
rows = []
for sc, g in d.groupby('scenario'):
    rows.append(dict(scenario=sc, raw_alerts=raw[sc], sampled=len(g), frac=len(g) / raw[sc],
                     unique_logs=g.full_log.nunique(), unique_ratio=g.full_log.nunique() / len(g),
                     unique_rule_log_pairs=(g.rule_description + '|' + g.full_log).nunique()))
t = pd.DataFrame(rows).set_index('scenario')
pd.set_option('display.width', 200)
print(t.round(3).to_string())
print(f"\nTOTAL raw alerts={t.raw_alerts.sum():,}  sampled={t.sampled.sum():,}  unique log strings (within-scenario sum)={t.unique_logs.sum():,}")
print("Sampling: python random.sample() = uniform WITHOUT replacement, seed 1; scenarios with < 50,000 alerts are used in full.")
