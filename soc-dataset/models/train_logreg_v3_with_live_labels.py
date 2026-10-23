"""Retrain the true-positive model with analyst labels collected on the LIVE system (round 2 of the
live calibration study). Runs on the VM (needs the socdb database and soc-engine/.env).

Training data = the 969 labelled alerts of our dataset + every analyst-labelled live alert (with the
recorded label corrections applied), the live rows up-weighted (they come from the target environment).

Before writing the model, a 5-fold cross-validation over the LIVE labelled alerts checks whether adding
live labels actually helps on held-out live alerts (not just in-sample): for each fold, train on
969 + other folds' live rows and score the held-out live rows; compare with training on the 969 alone.
Reports pooled ROC-AUC and the held-out scores of the labelled attacks the old model missed.

The new model must then be calibrated on FRESH labels (alerts scored after it is deployed); the
labels used here are training data and are never reused for calibration.
Output: /home/maro/soc-dataset/models/wazuh_tp_logreg_v3.joblib"""
import re, sys
import numpy as np, pandas as pd, joblib
sys.path.insert(0, '/home/maro/soc-engine')
import db
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score

LIVE_WEIGHT = 5.0


def clean(text):
    t = str(text)
    t = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', ' IPADDR ', t)
    t = re.sub(r'\bport\s+\d+\b', ' PORT ', t, flags=re.I)
    t = re.sub(r'\[\d+\]', ' ', t)
    t = re.sub(r'\[\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4}\]', ' TIMESTAMP ', t)
    t = re.sub(r'\b\d{1,2}/[A-Za-z]{3}/\d{4}\b', ' TIMESTAMP ', t)
    t = re.sub(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*\b', ' TIMESTAMP ', t)
    t = re.sub(r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\s+\d{1,2}\b', ' TIMESTAMP ', t, flags=re.I)
    t = re.sub(r'\b\d{2}:\d{2}:\d{2}\b', ' TIME ', t)
    t = re.sub(r'\b(19|20)\d{2}\b', ' YEAR ', t)
    return re.sub(r'\s+', ' ', t).strip()


def features(rule_level, ts, groups, decoder, log):
    return pd.DataFrame({
        'rule_level': pd.to_numeric(rule_level, errors='coerce').fillna(0).values,
        'hour': pd.to_datetime(ts, errors='coerce', utc=True).dt.hour.fillna(-1).values,
        'primary_group': pd.Series(groups).fillna('').apply(lambda g: g.split('|')[0] if g else 'none').values,
        'decoder': pd.Series(decoder).fillna('unknown').values,
        'full_log': pd.Series(log).fillna('').apply(clean).values,
    })


def pipe():
    return Pipeline([
        ('features', ColumnTransformer([
            ('rule_level', StandardScaler(), ['rule_level']), ('hour', StandardScaler(), ['hour']),
            ('primary_group', OneHotEncoder(handle_unknown='ignore'), ['primary_group']),
            ('decoder', OneHotEncoder(handle_unknown='ignore'), ['decoder']),
            ('full_log', TfidfVectorizer(max_features=300, ngram_range=(1, 2)), 'full_log')])),
        ('clf', LogisticRegression(class_weight='balanced', max_iter=1000, random_state=0))])


base = pd.read_csv('/home/maro/soc-dataset/wazuh_soc_dataset.csv').dropna(subset=['is_true_positive'])
Xb = features(base.rule_level, base.timestamp, base.rule_groups, base.decoder, base.full_log)
yb = base.is_true_positive.astype(bool).values

conn = db.get_conn()
live = pd.read_sql("""SELECT l.alert_id, l.is_attack, wa.rule_level, wa.event_timestamp, wa.rule_groups,
                             wa.decoder, wa.full_log, wa.rule_description, a.attack_score AS old_score
                      FROM analyst_labels l JOIN wazuh_alerts wa ON wa.alert_id = l.alert_id
                      LEFT JOIN ai_analyses a ON a.alert_id = l.alert_id AND a.model_version = 'tp_logreg_v2+sev_v1'""", conn)
Xl = features(live.rule_level, live.event_timestamp, live.rule_groups, live.decoder, live.full_log)
yl = live.is_attack.astype(bool).values
print(f"base alerts={len(yb)} (attacks {yb.sum()}), live labelled={len(yl)} (attacks {yl.sum()}, benign {(~yl).sum()})")

# ---- 5-fold CV over live labels: does adding live labels help on held-out live alerts? ----
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
p_with, p_without = np.zeros(len(yl)), np.zeros(len(yl))
m0 = pipe().fit(Xb, yb)
p_without[:] = m0.predict_proba(Xl)[:, 1]
for tr, te in skf.split(Xl, yl):
    X = pd.concat([Xb, Xl.iloc[tr]], ignore_index=True); y = np.concatenate([yb, yl[tr]])
    w = np.concatenate([np.ones(len(yb)), np.full(len(tr), LIVE_WEIGHT)])
    m = pipe().fit(X, y, clf__sample_weight=w)
    p_with[te] = m.predict_proba(Xl.iloc[te])[:, 1]
print(f"held-out live ROC-AUC: base model {roc_auc_score(yl, p_without):.3f} -> with live labels {roc_auc_score(yl, p_with):.3f}")
print(f"lowest held-out attack score: base {p_without[yl].min():.4f} -> with live labels {p_with[yl].min():.4f}")
print(f"held-out attacks scoring < 0.5: base {(p_without[yl] < .5).sum()}/{yl.sum()} -> with live labels {(p_with[yl] < .5).sum()}/{yl.sum()}")
print(f"held-out benign scoring >= 0.5: base {(p_without[~yl] >= .5).sum()}/{(~yl).sum()} -> with live labels {(p_with[~yl] >= .5).sum()}/{(~yl).sum()}")
low = live.assign(base=p_without, cv=p_with)[yl].sort_values('base').head(5)
print("previously lowest-scoring labelled attacks (base -> held-out CV score):")
for _, r in low.iterrows():
    print(f"  {r.alert_id}: {str(r.rule_description)[:40]:40s} {r.base:.4f} -> {r.cv:.4f}")

# ---- final model on everything ----
X = pd.concat([Xb, Xl], ignore_index=True); y = np.concatenate([yb, yl])
w = np.concatenate([np.ones(len(yb)), np.full(len(yl), LIVE_WEIGHT)])
final = pipe().fit(X, y, clf__sample_weight=w)
joblib.dump(final, '/home/maro/soc-dataset/models/wazuh_tp_logreg_v3.joblib')
print("saved wazuh_tp_logreg_v3.joblib")
