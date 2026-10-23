"""Ensemble experiment: does fusing the content-based classifier with a lightweight,
unsupervised correlation signal (Accumulation, same idea as Fraunhofer's risk hypothesis)
and the raw rule_level score recover some of the generalization gap found in the leakage
experiment (round 1-3 train, round 4 test -- unseen IP, real pentest-tool traffic)?

Unlike Fraunhofer's manually grid-searched weights, the combination here is LEARNED: a
logistic regression meta-classifier is fit on the three base signals using only the
training split (rounds 1-3), then evaluated on the fully unseen round 4 -- same rigorous
split as the leakage experiment, so results are directly comparable.
"""
import re
import pandas as pd
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
from statsmodels.stats.contingency_tables import mcnemar

RANDOM_STATE = 42

df = pd.read_csv('wazuh_soc_dataset.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
r4_mask = df['timestamp'] >= pd.Timestamp('2026-09-14 12:00:00', tz='UTC')

def clean_log_text(text):
    text = str(text)
    text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', ' IPADDR ', text)
    text = re.sub(r'\bport\s+\d+\b', ' PORT ', text, flags=re.I)
    text = re.sub(r'\[\d+\]', ' ', text)
    text = re.sub(r'\[\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4}\]', ' TIMESTAMP ', text)
    text = re.sub(r'\b\d{1,2}/[A-Za-z]{3}/\d{4}\b', ' TIMESTAMP ', text)
    text = re.sub(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*\b', ' TIMESTAMP ', text)
    text = re.sub(r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\s+\d{1,2}\b', ' TIMESTAMP ', text, flags=re.I)
    text = re.sub(r'\b\d{2}:\d{2}:\d{2}\b', ' TIME ', text)
    text = re.sub(r'\b(19|20)\d{2}\b', ' YEAR ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def prep(frame):
    work = frame.copy()
    work['rule_groups'] = work['rule_groups'].fillna('')
    work['full_log'] = work['full_log'].fillna('').apply(clean_log_text)
    work['decoder'] = work['decoder'].fillna('unknown')
    work['rule_level'] = pd.to_numeric(work['rule_level'], errors='coerce').fillna(0)
    work['hour'] = work['timestamp'].dt.hour.fillna(-1)
    work['primary_group'] = work['rule_groups'].apply(lambda g: g.split('|')[0] if g else 'none')
    return work[['rule_level', 'hour', 'primary_group', 'decoder', 'full_log']]

def accumulation_score(frame, window_minutes=10):
    """Trailing-window count of alerts from the same src_ip, same spirit as Fraunhofer's
    Accumulation risk hypothesis -- a cheap, content-blind correlation signal."""
    frame = frame.sort_values('timestamp').copy()
    scores = []
    ips = frame['src_ip'].fillna('unknown').values
    times = frame['timestamp'].values
    window = np.timedelta64(window_minutes, 'm')
    for i in range(len(frame)):
        t0 = times[i]
        ip = ips[i]
        # count alerts from the same ip in the trailing window up to and including this alert
        mask = (ips[:i+1] == ip) & (times[:i+1] > t0 - window) & (times[:i+1] <= t0)
        scores.append(mask.sum())
    frame['accumulation'] = scores
    return frame

def build_preprocessor():
    return ColumnTransformer(transformers=[
        ('rule_level', StandardScaler(), ['rule_level']),
        ('hour', StandardScaler(), ['hour']),
        ('primary_group', OneHotEncoder(handle_unknown='ignore'), ['primary_group']),
        ('decoder', OneHotEncoder(handle_unknown='ignore'), ['decoder']),
        ('full_log', TfidfVectorizer(max_features=300, ngram_range=(1, 2), min_df=1), 'full_log'),
    ], remainder='drop')

train_df = df[~r4_mask].dropna(subset=['is_true_positive']).copy()
test_df = df[r4_mask].dropna(subset=['is_true_positive']).copy()

# accumulation_score() sorts by timestamp (needed for a correct trailing window), so derive
# y_train/y_test AFTER sorting to keep X and y aligned by position, not before.
train_df = accumulation_score(train_df)
test_df = accumulation_score(test_df)
y_train = train_df['is_true_positive'].astype(bool)
y_test = test_df['is_true_positive'].astype(bool)

X_train = prep(train_df)
X_test = prep(test_df)

# --- Base model: content classifier (the FIXED version from the leakage experiment) ---
content_pipe = Pipeline([
    ('features', build_preprocessor()),
    ('clf', RandomForestClassifier(n_estimators=300, max_depth=12, class_weight='balanced', random_state=RANDOM_STATE))
])
content_pipe.fit(X_train, y_train)

content_prob_train = content_pipe.predict_proba(X_train)[:, 1]
content_prob_test = content_pipe.predict_proba(X_test)[:, 1]
content_pred_test = content_pipe.predict(X_test)

print("=== Content classifier alone (baseline, same as leakage experiment FIXED version) ===")
print(classification_report(y_test, content_pred_test, target_names=['False Positive', 'True Positive']))

# --- Build the three-signal feature matrix for the ensemble meta-classifier ---
rule_level_train = pd.to_numeric(train_df['rule_level'], errors='coerce').fillna(0).values
rule_level_test = pd.to_numeric(test_df['rule_level'], errors='coerce').fillna(0).values
# log1p compresses the dynamic range so automated-tool traffic (hundreds of alerts/IP) doesn't
# land far outside anything the meta-classifier calibrated on during training (manual attacks,
# accumulation scores an order of magnitude smaller -- see diagnose_accumulation.py findings).
accum_train = np.log1p(train_df['accumulation'].values)
accum_test = np.log1p(test_df['accumulation'].values)

meta_X_train = np.column_stack([content_prob_train, accum_train, rule_level_train])
meta_X_test = np.column_stack([content_prob_test, accum_test, rule_level_test])

# Normalize accumulation and rule_level for the meta-classifier (content_prob is already 0-1)
from sklearn.preprocessing import StandardScaler as SS
scaler = SS()
meta_X_train_scaled = meta_X_train.copy()
meta_X_test_scaled = meta_X_test.copy()
meta_X_train_scaled[:, 1:] = scaler.fit_transform(meta_X_train[:, 1:])
meta_X_test_scaled[:, 1:] = scaler.transform(meta_X_test[:, 1:])

meta_clf = LogisticRegression(class_weight='balanced', random_state=RANDOM_STATE)
meta_clf.fit(meta_X_train_scaled, y_train)
ensemble_pred_test = meta_clf.predict(meta_X_test_scaled)

print("\n=== Ensemble (content classifier + accumulation + rule_level, learned weights) ===")
print(classification_report(y_test, ensemble_pred_test, target_names=['False Positive', 'True Positive']))

print("\nLearned meta-classifier weights (content_prob, accumulation, rule_level):")
print(meta_clf.coef_[0])

# --- Summary ---
f1_content = f1_score(y_test, content_pred_test)
f1_ensemble = f1_score(y_test, ensemble_pred_test)
rec_content = recall_score(y_test, content_pred_test)
rec_ensemble = recall_score(y_test, ensemble_pred_test)
prec_content = precision_score(y_test, content_pred_test)
prec_ensemble = precision_score(y_test, ensemble_pred_test)

print("\n=== SUMMARY (test = round 4, unseen IP + real pentest tools) ===")
print(f"{'Model':35s} {'F1':>8s} {'Precision':>10s} {'Recall':>8s}")
print(f"{'Content classifier alone':35s} {f1_content:8.3f} {prec_content:10.3f} {rec_content:8.3f}")
print(f"{'Ensemble (content+accum+level)':35s} {f1_ensemble:8.3f} {prec_ensemble:10.3f} {rec_ensemble:8.3f}")

# --- McNemar's test: is the ensemble's improvement statistically significant? ---
content_correct = (content_pred_test == y_test.values)
ensemble_correct = (ensemble_pred_test == y_test.values)
# contingency table: [both correct, content correct only], [ensemble correct only, both wrong]
both_correct = np.sum(content_correct & ensemble_correct)
content_only = np.sum(content_correct & ~ensemble_correct)
ensemble_only = np.sum(~content_correct & ensemble_correct)
both_wrong = np.sum(~content_correct & ~ensemble_correct)
table = [[both_correct, content_only], [ensemble_only, both_wrong]]
result = mcnemar(table, exact=(content_only + ensemble_only < 25))
print(f"\nMcNemar's test contingency table: both_correct={both_correct}, content_only_correct={content_only}, "
      f"ensemble_only_correct={ensemble_only}, both_wrong={both_wrong}")
print(f"McNemar's test statistic={result.statistic:.3f}, p-value={result.pvalue:.5f}")
