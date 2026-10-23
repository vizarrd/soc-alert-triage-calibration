"""Experiment 13 showed that ranking quality (AUC) and the default-threshold behaviour of
the models disagree: the RandomForest has round-4 AUC < 0.5, so its high noise-clearing at
threshold 0.5 is a conservative-threshold artifact, not discrimination; LogReg/MLP rank well.

Practical question: can an operating threshold be chosen from TRAINING data only (no test
peeking) such that attack recall >= 95% holds on the shifted test distribution, and how much
noise is cleared there? Threshold selection uses out-of-fold training scores (contiguous
time-blocked folds to limit within-campaign leakage). Both directions are reported.
"""
import numpy as np, pandas as pd
import importlib.util, sys
from sklearn.pipeline import Pipeline
from sklearn.model_selection import KFold
from sklearn.metrics import recall_score

spec = importlib.util.spec_from_file_location('t13', '13_triage_relief_analysis.py')
src = open('13_triage_relief_analysis.py').read().split("curves, yte = run(")[0]
ns = {}
exec(src, ns)
df, r4, prep, pre, make_models = ns['df'], ns['r4'], ns['prep'], ns['pre'], ns['make_models']

TARGET = 0.95

def oof_scores(model_fn, X, y, folds=5):
    s = np.zeros(len(y))
    for tr_i, va_i in KFold(folds, shuffle=False).split(X):  # contiguous time blocks (data is time-sorted)
        if y[tr_i].sum() == 0 or (~y[tr_i]).sum() == 0:
            s[va_i] = 0.5; continue
        p = Pipeline([('f', pre()), ('c', model_fn())]).fit(X.iloc[tr_i], y[tr_i])
        s[va_i] = p.predict_proba(X.iloc[va_i])[:, 1]
    return s

def pick_threshold(y, s, target):
    # largest threshold whose recall on the (OOF) training scores is still >= target
    cands = np.unique(s)[::-1]
    for t in cands:
        if recall_score(y, s >= t) >= target:
            return t
    return cands[-1]

def evaluate(train_mask, label):
    tr = df[train_mask].dropna(subset=['is_true_positive']).sort_values('timestamp')
    te = df[~train_mask].dropna(subset=['is_true_positive']).sort_values('timestamp')
    ytr = tr['is_true_positive'].astype(bool).values; yte = te['is_true_positive'].astype(bool).values
    Xtr, Xte = prep(tr), prep(te)
    print(f"\n===== {label} (target recall {TARGET}) =====")
    print(f"{'model':12s} {'thr':>7s} {'test recall':>12s} {'noise cleared':>14s}")
    # rule_level baseline
    rl_tr, rl_te = Xtr['rule_level'].values, Xte['rule_level'].values
    t = pick_threshold(ytr, rl_tr, TARGET); pred = rl_te >= t
    print(f"{'rule_level':12s} {t:7.2f} {recall_score(yte, pred):12.3f} {1 - pred[~yte].mean():14.3f}")
    for name in ['LogReg', 'RF', 'MLP']:
        fn = lambda n=name: make_models(0)[n]
        s_oof = oof_scores(fn, Xtr, ytr)
        t = pick_threshold(ytr, s_oof, TARGET)
        p = Pipeline([('f', pre()), ('c', fn())]).fit(Xtr, ytr)
        pred = p.predict_proba(Xte)[:, 1] >= t
        print(f"{name:12s} {t:7.3f} {recall_score(yte, pred):12.3f} {1 - pred[~yte].mean():14.3f}")

evaluate(~r4, 'FORWARD: train rounds 1-3 -> test round 4')
evaluate(r4, 'REVERSE: train round 4 -> test rounds 1-3')
