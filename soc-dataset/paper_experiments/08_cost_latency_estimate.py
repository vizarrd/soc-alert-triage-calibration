"""Cost/latency comparison: trained classifier vs LLM-based triage, at realistic SOC alert
volumes. Our classifier's inference time is directly measured (real, metered). The LLM side
uses published API pricing and typical latency, since the actual classification in this
project was done via Claude directly (see README) rather than a per-call-billed API -- that
substitution is disclosed here rather than presented as a live-metered number.
"""
import re
import time
import pandas as pd
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

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
X_train = prep(train_df)
X_test = prep(test_df)

pipe = Pipeline([('features', build_preprocessor()),
                  ('clf', RandomForestClassifier(n_estimators=300, max_depth=12, class_weight='balanced', random_state=RANDOM_STATE))])
pipe.fit(X_train, y_train)

# --- Measure REAL inference latency: classify the 696 test alerts one at a time ---
n_runs = 696
start = time.time()
for i in range(len(X_test)):
    pipe.predict(X_test.iloc[[i]])
elapsed = time.time() - start
per_alert_ms = (elapsed / n_runs) * 1000

print(f"=== Our classifier: REAL measured inference time ===")
print(f"Total time for {n_runs} alerts: {elapsed:.3f}s")
print(f"Per-alert latency: {per_alert_ms:.2f} ms")
print(f"Marginal cost per alert: $0.00 (no API call, runs on existing hardware)")

# --- LLM side: published pricing, typical latency (disclosed estimate, not live-metered) ---
# Based on typical small/fast LLM API pricing as of model release (e.g. Claude Haiku /
# GPT-4o-mini tier): ~$0.25-1.00 per 1M input tokens, ~$1.25-4.00 per 1M output tokens.
# Our actual prompt (system instructions + alert fields) is ~150-250 input tokens;
# response (~30-50 tokens for the JSON verdict).
AVG_INPUT_TOKENS = 200
AVG_OUTPUT_TOKENS = 40
PRICE_PER_1M_INPUT = 0.80   # mid-range estimate across small/fast model tiers
PRICE_PER_1M_OUTPUT = 4.00
TYPICAL_API_LATENCY_MS = 800  # typical round-trip for a small/fast LLM API call, network + inference

cost_per_alert = (AVG_INPUT_TOKENS / 1_000_000 * PRICE_PER_1M_INPUT) + (AVG_OUTPUT_TOKENS / 1_000_000 * PRICE_PER_1M_OUTPUT)

print(f"\n=== LLM baseline: ESTIMATED from published pricing (not live-metered -- see README) ===")
print(f"Assumed ~{AVG_INPUT_TOKENS} input + {AVG_OUTPUT_TOKENS} output tokens per alert")
print(f"Estimated cost per alert: ${cost_per_alert:.6f}")
print(f"Typical API latency: ~{TYPICAL_API_LATENCY_MS} ms per alert (network round-trip + inference)")

print(f"\n=== Scaled to realistic SOC alert volumes ===")
for daily_volume in [1000, 10000, 100000]:
    our_cost = 0.0
    our_time_s = daily_volume * per_alert_ms / 1000
    llm_cost = daily_volume * cost_per_alert
    llm_time_s = daily_volume * TYPICAL_API_LATENCY_MS / 1000
    print(f"\n{daily_volume:,} alerts/day:")
    print(f"  Our classifier : ${our_cost:.2f}/day, {our_time_s:.1f}s total processing time")
    print(f"  LLM baseline   : ${llm_cost:.2f}/day, {llm_time_s:.1f}s total processing time (~{llm_time_s/60:.1f} min)")
    print(f"  Speedup: {llm_time_s/max(our_time_s,0.001):.0f}x faster, cost difference: ${llm_cost - our_cost:.2f}/day")
