"""One reproducible evaluation that produces EVERY headline round-4 number in the paper, so
tables cannot disagree. Resolves the inconsistencies a reviewer would see between experiments
01/02/06/07/16 (RF recall 0.373 / 0.367 / 0.16): those came from single runs with different
random seeds (and data orderings); with only 273 training alerts the Random Forest's default-
threshold decisions are highly seed-sensitive. Here every stochastic model is run with many seeds
and reported as mean +- sd.

Protocol (fixed): train = rounds 1-3 (273 alerts), test = round 4 (696 alerts), default decision
threshold 0.5 (rule_level: Youden-J threshold from train; LLM: its hard labels).
Reports: precision, recall(TPR), F1, noise cleared (1-FPR) overall and split into the dominant
benign category (107 'web_scan_noise_400' scanner-noise alerts) vs the other 16 benign alerts,
and ROC-AUC. Seeds: RF 20, MLP 10, Ensemble 20 (RF seed shared)."""
import json, glob
import numpy as np, pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, roc_curve, precision_score, recall_score, f1_score, matthews_corrcoef
from sklearn.ensemble import RandomForestClassifier
from statsmodels.stats.contingency_tables import mcnemar
from sklearn.preprocessing import StandardScaler

ns = {}
exec(open('13_triage_relief_analysis.py').read().split("curves, yte = run(")[0], ns)
df, r4, prep, pre, make_models, accum = ns['df'], ns['r4'], ns['prep'], ns['pre'], ns['make_models'], ns['accum']

tr = df[~r4].dropna(subset=['is_true_positive']).sort_values('timestamp')
te = df[r4].dropna(subset=['is_true_positive']).copy()
te['pos'] = np.arange(len(te))                       # original order = LLM row_id order
te = te.sort_values('timestamp')
ytr = tr['is_true_positive'].astype(bool).values
yte = te['is_true_positive'].astype(bool).values
cat = te['attack_category'].values
scan = (~yte) & (cat == 'web_scan_noise_400'); other_benign = (~yte) & ~scan
print(f"test n={len(te)}  attacks={yte.sum()}  benign={(~yte).sum()}  (scanner-noise benign={scan.sum()}, other benign={other_benign.sum()})")
Xtr, Xte = prep(tr), prep(te)

def metrics(pred, score=None):
    pred = np.asarray(pred, bool)
    d = dict(precision=precision_score(yte, pred, zero_division=0), recall=recall_score(yte, pred), F1=f1_score(yte, pred),
             cleared=1 - pred[~yte].mean(), cleared_scanner=1 - pred[scan].mean(), cleared_other_benign=1 - pred[other_benign].mean())
    d['AUC'] = roc_auc_score(yte, score) if score is not None else np.nan
    d['MCC'] = matthews_corrcoef(yte, pred)
    if score is not None:
        f_, t_, _ = roc_curve(yte, score); ok = t_ >= .95
        d['Relief95'] = 1 - f_[ok].min() if ok.any() else 0.0
    else:
        d['Relief95'] = np.nan
    return d

rows = []
def add(name, seed, m): rows.append({'method': name, 'seed': seed, **m})

fpr, tpr, th = roc_curve(ytr, Xtr['rule_level'].values); t = th[np.argmax(tpr - fpr)]
add('rule_level (Youden)', '-', metrics(Xte['rule_level'].values >= t, Xte['rule_level'].values))

llm0 = pd.read_csv('03d_llm_scored_comparison.csv')['is_true_positive_llm'].astype(bool).values
pos = te['pos'].values
add('LLM zero-shot', '-', metrics(llm0[pos]))
llm2 = pd.DataFrame([json.loads(l) for f in sorted(glob.glob('llm_v2/result_*.jsonl')) for l in open(f) if l.strip()]).drop_duplicates('row_id').set_index('row_id').sort_index()
add('LLM calibrated few-shot', '-', metrics(llm2['is_true_positive'].astype(bool).values[pos], llm2['attack_probability'].values[pos] / 100.0))

p = Pipeline([('f', pre()), ('c', make_models(0)['LogReg'])]).fit(Xtr, ytr); s = p.predict_proba(Xte)[:, 1]
add('LogReg', '-', metrics(s >= .5, s))
a_tr, a_te = accum(tr), accum(te)
for seed in range(20):
    p = Pipeline([('f', pre()), ('c', make_models(seed)['RF'])]).fit(Xtr, ytr); s = p.predict_proba(Xte)[:, 1]
    add('Random Forest', seed, metrics(s >= .5, s))
    M_tr = np.column_stack([p.predict_proba(Xtr)[:, 1], a_tr, Xtr['rule_level'].values]); M_te = np.column_stack([s, a_te, Xte['rule_level'].values])
    sc = StandardScaler().fit(M_tr[:, 1:]); M_tr[:, 1:] = sc.transform(M_tr[:, 1:]); M_te[:, 1:] = sc.transform(M_te[:, 1:])
    es = LogisticRegression(class_weight='balanced', random_state=seed).fit(M_tr, ytr).predict_proba(M_te)[:, 1]
    add('Ensemble (RF+accum+level)', seed, metrics(es >= .5, es))
for seed in range(10):
    p = Pipeline([('f', pre()), ('c', make_models(seed)['MLP'])]).fit(Xtr, ytr); s = p.predict_proba(Xte)[:, 1]
    add('MLP', seed, metrics(s >= .5, s))
from xgboost import XGBClassifier
for seed in range(10):
    p = Pipeline([('f', pre()), ('c', XGBClassifier(n_estimators=300, max_depth=6, random_state=seed, eval_metric='logloss'))]).fit(Xtr, ytr)
    s = p.predict_proba(Xte)[:, 1]; add('XGBoost', seed, metrics(s >= .5, s))
# leaky variant: identical pipeline but raw (uncleaned) log text, to restate the leakage result over seeds
Xtr_raw, Xte_raw = Xtr.copy(), Xte.copy()
Xtr_raw['full_log'] = tr['full_log'].fillna('').values; Xte_raw['full_log'] = te['full_log'].fillna('').values
for seed in range(20):
    p = Pipeline([('f', pre()), ('c', make_models(seed)['RF'])]).fit(Xtr_raw, ytr); s = p.predict_proba(Xte_raw)[:, 1]
    add('Random Forest, raw text (leaky)', seed, metrics(s >= .5, s))

res = pd.DataFrame(rows)
cols = ['precision', 'recall', 'F1', 'cleared', 'cleared_scanner', 'cleared_other_benign', 'AUC', 'MCC', 'Relief95']
g = res.groupby('method', sort=False)[cols]
mean, sd = g.mean(), g.std().fillna(0)
out = mean.round(3).astype(str) + ' +- ' + sd.round(3).astype(str)
pd.set_option('display.width', 250); pd.set_option('display.max_columns', 20)
print("\nRound-4 headline metrics (mean +- sd over seeds; deterministic methods have sd 0):")
print(out.to_string())
print("\nRandom Forest per-seed recall range:", res[res.method == 'Random Forest'].recall.min().round(3), '-', res[res.method == 'Random Forest'].recall.max().round(3))
print("Random Forest per-seed F1 range:    ", res[res.method == 'Random Forest'].F1.min().round(3), '-', res[res.method == 'Random Forest'].F1.max().round(3))
res.to_csv('24_per_seed_results.csv', index=False)

# paired comparison: Ensemble vs content classifier (RF), same seeds
rf = res[res.method == 'Random Forest'].set_index('seed'); en = res[res.method == 'Ensemble (RF+accum+level)'].set_index('seed')
print(f"\nEnsemble F1 > RF F1 in {(en.F1 > rf.F1).sum()}/20 seeds; recall higher in {(en.recall > rf.recall).sum()}/20; mean F1 gain {(en.F1 - rf.F1).mean():.3f}")
lk = res[res.method == 'Random Forest, raw text (leaky)']; fx = rf
print(f"Leaky vs cleaned RF (20 seeds): F1 {lk.F1.mean():.3f}+-{lk.F1.std():.3f} vs {fx.F1.mean():.3f}+-{fx.F1.std():.3f}; recall {lk.recall.mean():.3f} vs {fx.recall.mean():.3f}")
# McNemar on seed 0 (decision-level, same test set)
s0 = 0
def decisions(seed, ens):
    p = Pipeline([('f', pre()), ('c', make_models(seed)['RF'])]).fit(Xtr, ytr); s = p.predict_proba(Xte)[:, 1]
    if not ens: return s >= .5
    M_tr = np.column_stack([p.predict_proba(Xtr)[:, 1], a_tr, Xtr['rule_level'].values]); M_te = np.column_stack([s, a_te, Xte['rule_level'].values])
    sc = StandardScaler().fit(M_tr[:, 1:]); M_tr[:, 1:] = sc.transform(M_tr[:, 1:]); M_te[:, 1:] = sc.transform(M_te[:, 1:])
    return LogisticRegression(class_weight='balanced', random_state=seed).fit(M_tr, ytr).predict_proba(M_te)[:, 1] >= .5
for seed in (0, 1, 2):
    a, b = decisions(seed, False) == yte, decisions(seed, True) == yte
    tab = [[(a & b).sum(), (a & ~b).sum()], [(~a & b).sum(), (~a & ~b).sum()]]
    print(f"McNemar seed {seed}: classifier-only-correct={tab[0][1]}, ensemble-only-correct={tab[1][0]}, p={mcnemar(tab, exact=False, correction=True).pvalue:.2e}")
