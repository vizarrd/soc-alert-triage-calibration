"""How diverse is the benign class in the public AIT-ADS sample (vs our round 4, where 107/123 benign
alerts are a single alert type)? Counts distinct rule descriptions and the share of the top type."""
import pandas as pd
d = pd.read_csv('../external_data/ait_ads/ait_large.csv', keep_default_na=False)
d['is_true_positive'] = d['is_true_positive'].astype(str).str.lower().eq('true')
b, a = d[~d.is_true_positive], d[d.is_true_positive]
for name, x in (('benign', b), ('attack-window', a)):
    vc = x.rule_description.value_counts()
    print(f"{name}: n={len(x)}, distinct rule descriptions={len(vc)}, distinct decoders={x.decoder.nunique()}, top type share={vc.iloc[0]/len(x):.2f} ({vc.index[0][:50]}), top-5 share={vc.iloc[:5].sum()/len(x):.2f}")
print("\nbenign top 8 rule descriptions:"); print(b.rule_description.value_counts().head(8).to_string())
print("\nper scenario: distinct benign rule descriptions:"); print(b.groupby('scenario').rule_description.nunique().to_string())
