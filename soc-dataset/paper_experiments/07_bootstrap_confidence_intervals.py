"""Bootstrap 95% confidence intervals on F1 and recall for the four headline models, all on
the identical round-4 test set (696 alerts, unseen IP, real pentest-tool traffic). Point
estimates alone aren't enough for a journal submission -- this quantifies how much the
numbers could plausibly vary under resampling.
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
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, recall_score, roc_curve

RANDOM_STATE = 42
N_BOOTSTRAP = 2000

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

def accumulation_score(frame, window_minutes=10):
    frame = frame.sort_values('timestamp').copy()
    scores = []
    ips = frame['src_ip'].fillna('unknown').values
    times = frame['timestamp'].values
    window = np.timedelta64(window_minutes, 'm')
    for i in range(len(frame)):
        t0 = times[i]
        ip = ips[i]
        mask = (ips[:i+1] == ip) & (times[:i+1] > t0 - window) & (times[:i+1] <= t0)
        scores.append(mask.sum())
    frame['accumulation'] = scores
    return frame

train_df = df[~r4_mask].dropna(subset=['is_true_positive']).copy()
test_df = df[r4_mask].dropna(subset=['is_true_positive']).copy()

train_df = accumulation_score(train_df)
test_df = accumulation_score(test_df)
y_train = train_df['is_true_positive'].astype(bool)
y_test = test_df['is_true_positive'].astype(bool).values

X_train = prep(train_df)
X_test = prep(test_df)

# --- RandomForest classifier ---
rf_pipe = Pipeline([('features', build_preprocessor()),
                     ('clf', RandomForestClassifier(n_estimators=300, max_depth=12, class_weight='balanced', random_state=RANDOM_STATE))])
rf_pipe.fit(X_train, y_train)
rf_pred = rf_pipe.predict(X_test)
rf_prob_train = rf_pipe.predict_proba(X_train)[:, 1]
rf_prob_test = rf_pipe.predict_proba(X_test)[:, 1]

# --- Ensemble (content + accumulation + rule_level) ---
accum_train = np.log1p(train_df['accumulation'].values)
accum_test = np.log1p(test_df['accumulation'].values)
rl_train = X_train['rule_level'].values
rl_test = X_test['rule_level'].values

from sklearn.preprocessing import StandardScaler as SS
meta_X_train = np.column_stack([rf_prob_train, accum_train, rl_train])
meta_X_test = np.column_stack([rf_prob_test, accum_test, rl_test])
scaler = SS()
meta_X_train_s = meta_X_train.copy()
meta_X_test_s = meta_X_test.copy()
meta_X_train_s[:, 1:] = scaler.fit_transform(meta_X_train[:, 1:])
meta_X_test_s[:, 1:] = scaler.transform(meta_X_test[:, 1:])
meta_clf = LogisticRegression(class_weight='balanced', random_state=RANDOM_STATE)
meta_clf.fit(meta_X_train_s, y_train)
ensemble_pred = meta_clf.predict(meta_X_test_s)

# --- rule_level baseline ---
fpr, tpr, thresholds = roc_curve(y_train, rl_train)
best_threshold = thresholds[np.argmax(tpr - fpr)]
baseline_pred = (rl_test >= best_threshold)

# --- LLM ---
test_df_reset = test_df.reset_index(drop=True)
test_df_reset['row_id'] = test_df_reset.index
llm = pd.read_json('03c_llm_raw_classifications.jsonl', lines=True)
llm_merged = test_df_reset[['row_id']].merge(llm, on='row_id', how='left')
llm_pred = llm_merged['is_true_positive'].astype(bool).values

def bootstrap_ci(y_true, y_pred, metric_fn, n=N_BOOTSTRAP, seed=RANDOM_STATE):
    rng = np.random.RandomState(seed)
    n_samples = len(y_true)
    scores = []
    for _ in range(n):
        idx = rng.randint(0, n_samples, n_samples)
        scores.append(metric_fn(y_true[idx], y_pred[idx]))
    scores = np.array(scores)
    return np.percentile(scores, 2.5), np.percentile(scores, 50), np.percentile(scores, 97.5)

models = {
    'rule_level_baseline': baseline_pred,
    'RandomForest_classifier': rf_pred,
    'Ensemble': ensemble_pred,
    'LLM_Claude': llm_pred,
}

print(f"Bootstrap 95% CIs ({N_BOOTSTRAP} resamples), test = round 4 (696 alerts, unseen IP + real pentest tools)\n")
print(f"{'Model':30s} {'F1 (95% CI)':30s} {'Recall (95% CI)':30s}")
for name, pred in models.items():
    f1_lo, f1_mid, f1_hi = bootstrap_ci(y_test, pred, f1_score)
    rec_lo, rec_mid, rec_hi = bootstrap_ci(y_test, pred, recall_score)
    print(f"{name:30s} {f1_mid:.3f} [{f1_lo:.3f}, {f1_hi:.3f}]         {rec_mid:.3f} [{rec_lo:.3f}, {rec_hi:.3f}]")
