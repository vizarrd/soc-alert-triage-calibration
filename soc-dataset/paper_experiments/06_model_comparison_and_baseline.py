"""Two things the paper needs that aren't covered yet:
1. Explicit baseline: does the trained classifier actually beat just thresholding on
   Wazuh's own rule_level score? (The obvious reviewer objection: "why not just use
   severity?")
2. Model comparison: RandomForest vs Logistic Regression vs XGBoost vs MLP, same features,
   same disjoint split (round 1-3 train / round 4 test) -- is RandomForest actually the
   right choice, or did we just pick it without justification?
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
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score, roc_curve
try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

RANDOM_STATE = 42

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

train_df = df[~r4_mask].dropna(subset=['is_true_positive']).copy()
test_df = df[r4_mask].dropna(subset=['is_true_positive']).copy()
y_train = train_df['is_true_positive'].astype(bool)
y_test = test_df['is_true_positive'].astype(bool)
X_train = prep(train_df)
X_test = prep(test_df)

results = {}

# ============================================================
# BASELINE: rule_level-only thresholding
# ============================================================
print("=" * 70)
print("BASELINE: rule_level-only thresholding (the obvious naive approach)")
print("=" * 70)

rl_train = X_train['rule_level'].values
rl_test = X_test['rule_level'].values

# Find the best threshold on TRAIN only (never peek at test), via ROC
fpr, tpr, thresholds = roc_curve(y_train, rl_train)
youden = tpr - fpr
best_idx = np.argmax(youden)
best_threshold = thresholds[best_idx]
print(f"Best rule_level threshold found on train set (Youden's J): {best_threshold:.1f}")

baseline_pred = (rl_test >= best_threshold)
print(classification_report(y_test, baseline_pred, target_names=['False Positive', 'True Positive']))
results['rule_level_baseline'] = (
    f1_score(y_test, baseline_pred), precision_score(y_test, baseline_pred), recall_score(y_test, baseline_pred)
)

# ============================================================
# MODEL COMPARISON: same features, different classifiers
# ============================================================
print("\n" + "=" * 70)
print("MODEL COMPARISON: same feature pipeline, different classifiers")
print("=" * 70)

models = {
    'RandomForest': RandomForestClassifier(n_estimators=300, max_depth=12, class_weight='balanced', random_state=RANDOM_STATE),
    'LogisticRegression': LogisticRegression(class_weight='balanced', random_state=RANDOM_STATE, max_iter=1000),
    'MLP': MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=500, random_state=RANDOM_STATE, early_stopping=True),
}
if HAS_XGB:
    models['XGBoost'] = XGBClassifier(n_estimators=300, max_depth=6, random_state=RANDOM_STATE, eval_metric='logloss')
else:
    print("(xgboost not installed -- skipping)")

for name, clf in models.items():
    pipe = Pipeline([('features', build_preprocessor()), ('clf', clf)])
    pipe.fit(X_train, y_train)
    pred = pipe.predict(X_test)
    f1 = f1_score(y_test, pred)
    prec = precision_score(y_test, pred)
    rec = recall_score(y_test, pred)
    results[name] = (f1, prec, rec)
    print(f"\n--- {name} ---")
    print(classification_report(y_test, pred, target_names=['False Positive', 'True Positive']))

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 70)
print("SUMMARY (test = round 4, unseen IP + real pentest tools)")
print("=" * 70)
print(f"{'Model':30s} {'F1':>8s} {'Precision':>10s} {'Recall':>8s}")
for name, (f1, prec, rec) in results.items():
    print(f"{name:30s} {f1:8.3f} {prec:10.3f} {rec:8.3f}")
