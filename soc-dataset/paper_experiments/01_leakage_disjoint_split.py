"""Quantified leakage experiment for the paper: train on rounds 1-3 (hand-crafted attacks,
6 source IPs), test on round 4 (real pentest-tool traffic: hydra/gobuster/nikto/sqlmap, 1
source IP never seen in training). Compares the ORIGINAL leaky feature pipeline (raw full_log,
no text cleaning) against the FIXED pipeline (clean_log_text strips IPs/timestamps) on this
genuinely disjoint split, to produce real, defensible numbers instead of an anecdote.
"""
import re
import pandas as pd
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score

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

def prep(frame, clean):
    work = frame.copy()
    work['rule_groups'] = work['rule_groups'].fillna('')
    raw_log = work['full_log'].fillna('')
    work['full_log'] = raw_log.apply(clean_log_text) if clean else raw_log
    work['decoder'] = work['decoder'].fillna('unknown')
    work['rule_level'] = pd.to_numeric(work['rule_level'], errors='coerce').fillna(0)
    work['hour'] = work['timestamp'].dt.hour.fillna(-1)
    work['primary_group'] = work['rule_groups'].apply(lambda g: g.split('|')[0] if g else 'none')
    return work[['rule_level', 'hour', 'primary_group', 'decoder', 'full_log']]

def build_preprocessor():
    return ColumnTransformer(transformers=[
        ('rule_level', StandardScaler(), ['rule_level']),
        ('hour', StandardScaler(), ['hour']),
        ('primary_group', OneHotEncoder(handle_unknown='ignore'), ['primary_group']),
        ('decoder', OneHotEncoder(handle_unknown='ignore'), ['decoder']),
        ('full_log', TfidfVectorizer(max_features=300, ngram_range=(1, 2), min_df=1), 'full_log'),
    ], remainder='drop')

train_df = df[~r4_mask].dropna(subset=['is_true_positive'])
test_df = df[r4_mask].dropna(subset=['is_true_positive'])
y_train = train_df['is_true_positive'].astype(bool)
y_test = test_df['is_true_positive'].astype(bool)

print(f"Train (rounds 1-3): {len(train_df)} rows, {y_train.sum()} TP / {(~y_train).sum()} FP")
print(f"Test  (round 4, unseen IP + real tools): {len(test_df)} rows, {y_test.sum()} TP / {(~y_test).sum()} FP")
print()

results = {}
for label, clean in [('LEAKY (no text cleaning)', False), ('FIXED (clean_log_text)', True)]:
    X_train = prep(train_df, clean)
    X_test = prep(test_df, clean)

    pipe = Pipeline([
        ('features', build_preprocessor()),
        ('clf', RandomForestClassifier(n_estimators=300, max_depth=12, class_weight='balanced', random_state=RANDOM_STATE))
    ])
    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)

    f1 = f1_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    results[label] = (f1, prec, rec)

    print(f"=== {label} ===")
    print(classification_report(y_test, y_pred, target_names=['False Positive', 'True Positive']))
    print()

print("=== SUMMARY (test = round 4, genuinely unseen IP + real pentest tools) ===")
print(f"{'Model':35s} {'F1':>8s} {'Precision':>10s} {'Recall':>8s}")
for label, (f1, prec, rec) in results.items():
    print(f"{label:35s} {f1:8.3f} {prec:10.3f} {rec:8.3f}")
