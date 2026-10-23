"""External validation on the public AIT-ADS Wazuh alerts (CC BY 4.0, Zenodo 8263181), using
leave-one-scenario-out: train on 7 simulated enterprise scenarios, test on the held-out 8th
(different network, hostnames, users, and attack prevalence from 7% to 89%).

Replicates, on data we did not generate or label:
  (a) identifier leakage: RF on raw log text vs cleaned text
  (b) threshold-free ranking quality (ROC-AUC, Relief@R95) of rule_level / LogReg / RF / MLP
  (c) operating-point transfer: threshold for 95% recall chosen from out-of-fold TRAINING scores
      (GroupKFold over training scenarios) applied to the held-out scenario
  (d) few-label recalibration with k=20 / 50 analyst labels from the target scenario
Labels are attack-window membership (see 18a); window-level labels are noisy by construction.
"""
import re
import numpy as np, pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import roc_auc_score, roc_curve, recall_score

df = pd.read_csv('../external_data/ait_ads/ait_sample.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, format='ISO8601')
y_all = df['is_true_positive'].astype(bool).values

def clean(text):
    t = str(text)
    t = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', ' IPADDR ', t)
    t = re.sub(r'\bport\s+\d+\b', ' PORT ', t, flags=re.I)
    t = re.sub(r'\[\d+\]', ' ', t)
    t = re.sub(r'\[\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4}\]', ' TIMESTAMP ', t)
    t = re.sub(r'\b\d{1,2}/[A-Za-z]{3}/\d{4}\b', ' TIMESTAMP ', t)
    t = re.sub(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*\b', ' TIMESTAMP ', t)
    t = re.sub(r'\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b', ' ', t)
    t = re.sub(r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\s+\d{1,2}\b', ' TIMESTAMP ', t, flags=re.I)
    t = re.sub(r'\b\d{2}:\d{2}:\d{2}\b', ' TIME ', t)
    t = re.sub(r'\b(19|20)\d{2}\b', ' YEAR ', t)
    return re.sub(r'\s+', ' ', t).strip()

def prep(f, do_clean):
    w = pd.DataFrame(index=f.index)
    w['rule_level'] = pd.to_numeric(f['rule_level'], errors='coerce').fillna(0)
    w['hour'] = f['timestamp'].dt.hour
    w['primary_group'] = f['rule_groups'].fillna('').apply(lambda g: g.split('|')[0] if g else 'none')
    w['decoder'] = f['decoder'].fillna('unknown')
    log = f['full_log'].fillna('')
    w['full_log'] = log.apply(clean) if do_clean else log
    return w

X_clean, X_raw = prep(df, True), prep(df, False)

def pre():
    return ColumnTransformer([('rl', StandardScaler(), ['rule_level']), ('h', StandardScaler(), ['hour']),
        ('pg', OneHotEncoder(handle_unknown='ignore'), ['primary_group']),
        ('d', OneHotEncoder(handle_unknown='ignore'), ['decoder']),
        ('t', TfidfVectorizer(max_features=300, ngram_range=(1, 2)), 'full_log')])

def model(name):
    return {'LogReg': LogisticRegression(class_weight='balanced', max_iter=1000, random_state=0),
            'RF': RandomForestClassifier(n_estimators=200, max_depth=12, class_weight='balanced', random_state=0, n_jobs=-1),
            'MLP': MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=0, early_stopping=True)}[name]

def relief95(y, s):
    fpr, tpr, _ = roc_curve(y, s)
    ok = tpr >= .95
    return 1 - fpr[ok].min() if ok.any() else 0.0

def thr95(y, s):
    pos = np.sort(s[y])[::-1]
    return -np.inf if len(pos) == 0 else pos[int(np.ceil(.95 * len(pos))) - 1]

def fit_score(name, Xtr, ytr, Xte):
    return Pipeline([('f', pre()), ('c', model(name))]).fit(Xtr, ytr).predict_proba(Xte)[:, 1]

scen = df['scenario'].values
rng = np.random.default_rng(0)
rows = []
for held in sorted(set(scen)):
    te = scen == held; tr = ~te
    y_tr, y_te = y_all[tr], y_all[te]
    Xtr, Xte = X_clean[tr], X_clean[te]
    r = {'held_out': held, 'prev': y_te.mean()}
    # leakage replication: RF raw text vs cleaned
    s_raw = fit_score('RF', X_raw[tr], y_tr, X_raw[te])
    r['RF_raw_AUC'] = roc_auc_score(y_te, s_raw)
    scores = {'rule_level': Xte['rule_level'].values.astype(float)}
    oof_groups = scen[tr]
    oof = {'rule_level': Xtr['rule_level'].values.astype(float)}
    for name in ['LogReg', 'RF', 'MLP']:
        scores[name] = fit_score(name, Xtr, y_tr, Xte)
        o = np.zeros(tr.sum())
        for a, b in GroupKFold(3).split(Xtr, y_tr, oof_groups):
            o[b] = fit_score(name, Xtr.iloc[a], y_tr[a], Xtr.iloc[b])
        oof[name] = o
    for name, s in scores.items():
        r[f'{name}_AUC'] = roc_auc_score(y_te, s)
        r[f'{name}_Relief95'] = relief95(y_te, s)
        t = thr95(y_tr, oof[name]); pred = s >= t
        r[f'{name}_xfer_recall'] = pred[y_te].mean(); r[f'{name}_xfer_cleared'] = 1 - pred[~y_te].mean()
        for k in (20, 50):
            rc, cl = [], []
            for _ in range(100):
                idx = rng.choice(len(s), k, replace=False); m = np.ones(len(s), bool); m[idx] = False
                p = s[m] >= thr95(y_te[idx], s[idx]); yy = y_te[m]
                rc.append(p[yy].mean()); cl.append(1 - p[~yy].mean())
            r[f'{name}_k{k}_recall'] = np.mean(rc); r[f'{name}_k{k}_cleared'] = np.mean(cl)
    rows.append(r); print('done', held, flush=True)

res = pd.DataFrame(rows).set_index('held_out')
pd.set_option('display.width', 250); pd.set_option('display.max_columns', 60)
print("\nPrevalence, AUC (leakage: RF raw vs cleaned):")
print(res[['prev', 'RF_raw_AUC', 'RF_AUC', 'rule_level_AUC', 'LogReg_AUC', 'MLP_AUC']].round(3).to_string())
print("\nMean over 8 held-out scenarios:")
cols = [c for c in res.columns if c != 'prev']
print(res[cols].mean().round(3).to_string())
for name in ['rule_level', 'LogReg', 'RF', 'MLP']:
    print(f"\n{name}: transfer (thr from train OOF)  recall/cleared per scenario:")
    print(res[[f'{name}_xfer_recall', f'{name}_xfer_cleared', f'{name}_k20_recall', f'{name}_k20_cleared']].round(3).to_string())
res.to_csv('18_per_scenario_results.csv')
