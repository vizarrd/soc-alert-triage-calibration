"""Threshold-free analysis of the "flag everything" finding, and the paper's proposed
evaluation protocol: the Triage Relief Curve (TRC).

TRC: for every operating threshold, plot fraction of benign noise cleared (specificity) vs
fraction of real attacks retained (recall). Summaries:
  - Relief@R95 / Relief@R90: noise cleared when attack recall must stay >= 95% / 90%
  - ROC-AUC, PR-AUC, MCC, balanced accuracy at the default threshold
A "flag everything" system scores ~0 relief at any recall; F1 alone hides this.
Also: reverse-direction check (train round 4 -> test rounds 1-3) and 5 seeds for the
stochastic models, so the conclusions do not rest on one direction or one seed.
"""
import re
import numpy as np, pandas as pd
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import roc_auc_score, average_precision_score, matthews_corrcoef, balanced_accuracy_score, roc_curve

df = pd.read_csv('../wazuh_soc_dataset.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
r4 = df['timestamp'] >= pd.Timestamp('2026-09-14 12:00:00', tz='UTC')

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

def prep(f):
    w = f.copy()
    w['rule_groups'] = w['rule_groups'].fillna('')
    w['full_log'] = w['full_log'].fillna('').apply(clean)
    w['decoder'] = w['decoder'].fillna('unknown')
    w['rule_level'] = pd.to_numeric(w['rule_level'], errors='coerce').fillna(0)
    w['hour'] = w['timestamp'].dt.hour.fillna(-1)
    w['primary_group'] = w['rule_groups'].apply(lambda g: g.split('|')[0] if g else 'none')
    return w[['rule_level', 'hour', 'primary_group', 'decoder', 'full_log']]

def pre():
    return ColumnTransformer([('rl', StandardScaler(), ['rule_level']), ('h', StandardScaler(), ['hour']),
        ('pg', OneHotEncoder(handle_unknown='ignore'), ['primary_group']),
        ('d', OneHotEncoder(handle_unknown='ignore'), ['decoder']),
        ('t', TfidfVectorizer(max_features=300, ngram_range=(1, 2)), 'full_log')])

def accum(frame, minutes=10):
    ips = frame['src_ip'].fillna('unknown').values; ts = frame['timestamp'].values
    w = np.timedelta64(minutes, 'm'); out = []
    for i in range(len(frame)):
        out.append(((ips[:i+1] == ips[i]) & (ts[:i+1] > ts[i] - w)).sum())
    return np.log1p(np.array(out))

def relief_at(y, s, rec):
    fpr, tpr, _ = roc_curve(y, s)
    ok = tpr >= rec
    return 1 - fpr[ok].min() if ok.any() else 0.0

def summarize(y, s, pred):
    return dict(AUC=roc_auc_score(y, s), PRAUC=average_precision_score(y, s), MCC=matthews_corrcoef(y, pred),
                BalAcc=balanced_accuracy_score(y, pred), Relief95=relief_at(y, s, .95), Relief90=relief_at(y, s, .90))

def make_models(seed):
    return {'LogReg': LogisticRegression(class_weight='balanced', max_iter=1000, random_state=seed),
            'RF': RandomForestClassifier(n_estimators=300, max_depth=12, class_weight='balanced', random_state=seed),
            'MLP': MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=500, random_state=seed, early_stopping=True)}

def run(train_mask, label, with_ensemble, seeds=(0, 1, 2, 3, 4)):
    tr = df[train_mask].dropna(subset=['is_true_positive']).sort_values('timestamp')
    te = df[~train_mask].dropna(subset=['is_true_positive']).sort_values('timestamp')
    ytr = tr['is_true_positive'].astype(bool).values; yte = te['is_true_positive'].astype(bool).values
    Xtr, Xte = prep(tr), prep(te)
    rows = []; curves = {}
    rl = Xte['rule_level'].values
    # rule_level baseline: threshold chosen on train by Youden's J
    fpr, tpr, th = roc_curve(ytr, Xtr['rule_level'].values); t_best = th[np.argmax(tpr - fpr)]
    r = summarize(yte, rl, rl >= t_best); r.update(model='rule_level', seed='-'); rows.append(r)
    curves['rule_level'] = roc_curve(yte, rl)[:2]
    for seed in seeds:
        for name, m in make_models(seed).items():
            p = Pipeline([('f', pre()), ('c', m)]).fit(Xtr, ytr)
            s = p.predict_proba(Xte)[:, 1]
            r = summarize(yte, s, s >= .5); r.update(model=name, seed=seed); rows.append(r)
            if seed == 0: curves[name] = roc_curve(yte, s)[:2]
            if with_ensemble and name == 'RF':
                M_tr = np.column_stack([p.predict_proba(Xtr)[:, 1], accum(tr), Xtr['rule_level'].values])
                M_te = np.column_stack([s, accum(te), Xte['rule_level'].values])
                sc = StandardScaler().fit(M_tr[:, 1:]); M_tr[:, 1:] = sc.transform(M_tr[:, 1:]); M_te[:, 1:] = sc.transform(M_te[:, 1:])
                meta = LogisticRegression(class_weight='balanced', random_state=seed).fit(M_tr, ytr)
                es = meta.predict_proba(M_te)[:, 1]
                r = summarize(yte, es, es >= .5); r.update(model='Ensemble', seed=seed); rows.append(r)
                if seed == 0: curves['Ensemble'] = roc_curve(yte, es)[:2]
    res = pd.DataFrame(rows)
    agg = res.groupby('model')[['AUC', 'PRAUC', 'MCC', 'BalAcc', 'Relief95', 'Relief90']].agg(['mean', 'std']).round(3)
    print(f"\n===== {label}: train n={len(tr)} (TP={ytr.sum()}), test n={len(te)} (TP={yte.sum()}, base rate {yte.mean():.2f}) =====")
    print(agg.to_string())
    return curves, yte

curves, yte = run(~r4, 'FORWARD: train rounds 1-3 -> test round 4', True)
run(r4, 'REVERSE: train round 4 -> test rounds 1-3', False)

fig, ax = plt.subplots(figsize=(3.6, 3.2))
for n, (fpr, tpr) in curves.items():
    ax.plot(tpr, 1 - fpr, label=n)
ax.set_xlabel('Attack recall retained'); ax.set_ylabel('Benign noise cleared'); ax.set_title('Triage Relief Curve (round 4)')
ax.legend(fontsize=7); ax.set_xlim(0, 1.01); ax.set_ylim(0, 1.01); fig.tight_layout(); fig.savefig('fig_triage_relief_curve.png', dpi=300)
