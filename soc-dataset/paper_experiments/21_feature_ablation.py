"""Feature-family ablation: how much does each input contribute to ranking quality (ROC-AUC)?
Drops one family at a time (log text / rule_level / decoder / rule group / hour) and also keeps
only one family. Logistic Regression, on (a) AIT-ADS leave-one-scenario-out (mean over 8
held-out scenarios) and (b) our dataset (rounds 1-3 -> round 4). Answers: does the model only
use shortcuts such as the log source, and is rule_level or the text doing the work?"""
import numpy as np, pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

FAMILIES = {'rule_level': ('rl', StandardScaler(), ['rule_level']), 'hour': ('h', StandardScaler(), ['hour']),
            'rule_group': ('pg', OneHotEncoder(handle_unknown='ignore'), ['primary_group']),
            'decoder': ('d', OneHotEncoder(handle_unknown='ignore'), ['decoder']),
            'log_text': ('t', TfidfVectorizer(max_features=300, ngram_range=(1, 2)), 'full_log')}

def build(keep):
    from sklearn.base import clone
    return Pipeline([('f', ColumnTransformer([(n, clone(t), c) for k, (n, t, c) in FAMILIES.items() if k in keep])),
                     ('c', LogisticRegression(class_weight='balanced', max_iter=1000, random_state=0))])

def configs():
    allf = list(FAMILIES)
    yield 'all features', allf
    for f in allf:
        yield f'drop {f}', [x for x in allf if x != f]
    for f in allf:
        yield f'only {f}', [f]

# (a) AIT-ADS
ns = {}; exec(open('18_external_validation_ait_ads.py').read().split("scen = df['scenario'].values")[0], ns)
df, X, y = ns['df'], ns['X_clean'], ns['y_all']
scen = df['scenario'].values
res = []
for name, keep in configs():
    aucs = []
    for held in sorted(set(scen)):
        te = scen == held
        p = build(keep).fit(X[~te], y[~te]).predict_proba(X[te])[:, 1]
        aucs.append(roc_auc_score(y[te], p))
    res.append((name, np.mean(aucs), np.min(aucs)))
print("AIT-ADS leave-one-scenario-out (LogReg): mean AUC, worst-scenario AUC")
for r in res: print(f"  {r[0]:18s} {r[1]:.3f}  {r[2]:.3f}")

# (b) our data
ns2 = {}; exec(open('13_triage_relief_analysis.py').read().split("curves, yte = run(")[0], ns2)
d0, r4, prep0 = ns2['df'], ns2['r4'], ns2['prep']
tr = d0[~r4].dropna(subset=['is_true_positive']).sort_values('timestamp')
te = d0[r4].dropna(subset=['is_true_positive'])
ytr, yte = tr['is_true_positive'].astype(bool).values, te['is_true_positive'].astype(bool).values
Xtr, Xte = prep0(tr), prep0(te)
print("\nOur dataset (train rounds 1-3 -> test round 4, LogReg): AUC")
for name, keep in configs():
    p = build(keep).fit(Xtr, ytr).predict_proba(Xte)[:, 1]
    print(f"  {name:18s} {roc_auc_score(yte, p):.3f}")
