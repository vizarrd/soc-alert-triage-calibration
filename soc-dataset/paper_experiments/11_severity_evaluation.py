"""The paper discusses severity classification throughout but never quantitatively
evaluates it -- a real gap. This trains the 4-class severity classifier on the same
disjoint split, evaluates it (macro F1, per-class accuracy, confusion matrix), and scores
the LLM's already-collected severity judgments (from experiment 03) against ground truth
for a direct comparison.
"""
import re
import json
import pandas as pd
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score, confusion_matrix

RANDOM_STATE = 42
SEV_ORDER = ['low', 'medium', 'high', 'critical']

df = pd.read_csv('../wazuh_soc_dataset.csv')
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

def build_preprocessor():
    return ColumnTransformer(transformers=[
        ('rule_level', StandardScaler(), ['rule_level']),
        ('hour', StandardScaler(), ['hour']),
        ('primary_group', OneHotEncoder(handle_unknown='ignore'), ['primary_group']),
        ('decoder', OneHotEncoder(handle_unknown='ignore'), ['decoder']),
        ('full_log', TfidfVectorizer(max_features=300, ngram_range=(1, 2), min_df=1), 'full_log'),
    ], remainder='drop')

train_df = df[~r4_mask].dropna(subset=['severity']).copy()
test_df = df[r4_mask].dropna(subset=['severity']).copy()
y_train = train_df['severity']
y_test = test_df['severity']
X_train = prep(train_df)
X_test = prep(test_df)

sev_pipe = Pipeline([('features', build_preprocessor()),
                      ('clf', RandomForestClassifier(n_estimators=300, max_depth=12, class_weight='balanced', random_state=RANDOM_STATE))])
sev_pipe.fit(X_train, y_train)
sev_pred = sev_pipe.predict(X_test)

print("=" * 70)
print("SEVERITY CLASSIFICATION (our trained model, 4-class)")
print("=" * 70)
print(classification_report(y_test, sev_pred, labels=SEV_ORDER))
macro_f1 = f1_score(y_test, sev_pred, labels=SEV_ORDER, average='macro')
print(f"Macro F1: {macro_f1:.3f}")

cm = confusion_matrix(y_test, sev_pred, labels=SEV_ORDER)
print("\nConfusion matrix (rows=true, cols=predicted), order:", SEV_ORDER)
print(cm)

# --- Score the LLM's severity judgments (already collected in experiment 03) ---
print("\n" + "=" * 70)
print("SEVERITY CLASSIFICATION (LLM, zero-shot, from experiment 03)")
print("=" * 70)

test_df_reset = test_df.reset_index(drop=True)
test_df_reset['row_id'] = test_df_reset.index
llm = pd.read_json('03c_llm_raw_classifications.jsonl', lines=True)
llm_merged = test_df_reset[['row_id', 'severity']].merge(llm, on='row_id', how='left', suffixes=('_true', '_llm'))
llm_merged = llm_merged.dropna(subset=['severity_llm'])
# normalize to the same 4 labels; LLM might occasionally emit an unexpected label
llm_merged = llm_merged[llm_merged['severity_llm'].isin(SEV_ORDER)]

print(f"LLM severity predictions scored: {len(llm_merged)}/{len(test_df_reset)}")
print(classification_report(llm_merged['severity_true'], llm_merged['severity_llm'], labels=SEV_ORDER))
llm_macro_f1 = f1_score(llm_merged['severity_true'], llm_merged['severity_llm'], labels=SEV_ORDER, average='macro')
print(f"LLM Macro F1: {llm_macro_f1:.3f}")

cm_llm = confusion_matrix(llm_merged['severity_true'], llm_merged['severity_llm'], labels=SEV_ORDER)
print("\nLLM confusion matrix (rows=true, cols=predicted), order:", SEV_ORDER)
print(cm_llm)

print("\n" + "=" * 70)
print(f"SUMMARY: Our classifier macro F1 = {macro_f1:.3f} | LLM macro F1 = {llm_macro_f1:.3f}")
print("=" * 70)

# Save confusion matrix data for the paper figure
np.savetxt('11_confusion_matrix_ours.csv', cm, delimiter=',', fmt='%d', header=','.join(SEV_ORDER), comments='')
np.savetxt('11_confusion_matrix_llm.csv', cm_llm, delimiter=',', fmt='%d', header=','.join(SEV_ORDER), comments='')
