"""Adversarial evasion test against OUR OWN trained classifier -- the honest counterpart to
experiment 05 (LLM prompt injection). If we're claiming the classical classifier is 'safer'
than an LLM because it has no instruction-following channel to exploit, we owe the paper a
test of ITS equivalent failure mode: can classic evasion techniques (the same style used in
the project's earlier red-team validation against Wazuh's own rules) fool the TF-IDF-based
model into misclassifying a real attack as benign?

Technique categories tested, applied to real attacks already correctly classified by the
trained model:
  1. Case variation        -- mixed/alternating case in keywords
  2. Comment injection      -- SQL-style /**/ comments splitting keywords
  3. Whitespace padding     -- excess whitespace/tabs breaking up n-gram boundaries
  4. URL-encoding variants  -- double-encoding or mixed-case hex escapes
  5. Synonym/operator swap  -- alternate syntax achieving the same attack semantically
"""
import re
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
y_train = train_df['is_true_positive'].astype(bool)
X_train = prep(train_df)

pipe = Pipeline([('features', build_preprocessor()),
                  ('clf', RandomForestClassifier(n_estimators=300, max_depth=12, class_weight='balanced', random_state=RANDOM_STATE))])
pipe.fit(X_train, y_train)

def predict_one(rule_level, primary_group, decoder, full_log, hour=12):
    row = pd.DataFrame([{'rule_level': rule_level, 'hour': hour, 'primary_group': primary_group,
                          'decoder': decoder, 'full_log': clean_log_text(full_log)}])
    pred = pipe.predict(row)[0]
    prob = pipe.predict_proba(row)[0].max()
    return bool(pred), round(float(prob), 3)

# --- Evasion test cases: (name, rule_level, primary_group, decoder, original, evaded) ---
cases = [
    {
        'attack': 'SQL injection',
        'rule_level': 7, 'primary_group': 'web', 'decoder': 'web-accesslog',
        'original': "GET /search?q=' UNION SELECT username,password FROM users-- HTTP/1.1\" 200",
        'variants': {
            'case_variation': "GET /search?q=' UnIoN SeLeCt username,password FrOm users-- HTTP/1.1\" 200",
            'comment_injection': "GET /search?q=' UNI/**/ON SEL/**/ECT username,password FR/**/OM users-- HTTP/1.1\" 200",
            'whitespace_padding': "GET /search?q=' UNION%09SELECT%0Ausername,password%09FROM%0Ausers-- HTTP/1.1\" 200",
            'synonym_swap': "GET /search?q=' UNION ALL SELECT username,password FROM users WHERE 1=1-- HTTP/1.1\" 200",
        }
    },
    {
        'attack': 'Command injection',
        'rule_level': 12, 'primary_group': 'web', 'decoder': 'web-accesslog',
        'original': 'GET /ping?host=127.0.0.1;whoami HTTP/1.1" 200',
        'variants': {
            'operator_swap': 'GET /ping?host=127.0.0.1%26%26whoami HTTP/1.1" 200',
            'backtick_variant': 'GET /ping?host=127.0.0.1`whoami` HTTP/1.1" 200',
            'dollar_paren': 'GET /ping?host=127.0.0.1$(whoami) HTTP/1.1" 200',
            'double_encoding': 'GET /ping?host=127.0.0.1%253Bwhoami HTTP/1.1" 200',
        }
    },
    {
        'attack': 'XSS',
        'rule_level': 12, 'primary_group': 'web', 'decoder': 'web-accesslog',
        'original': 'GET /profile?name=<script>alert(1)</script> HTTP/1.1" 200',
        'variants': {
            'case_variation': 'GET /profile?name=<ScRiPt>aLeRt(1)</sCrIpT> HTTP/1.1" 200',
            'svg_vector': 'GET /profile?name=<svg/onload=alert(1)> HTTP/1.1" 200',
            'event_handler_variant': 'GET /profile?name=<img src=x onerror=alert(1)> HTTP/1.1" 200',
            'encoded': 'GET /profile?name=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200',
        }
    },
]

def run_suite(label, use_realistic_rule_level):
    print("=" * 80)
    print(label)
    print("=" * 80)
    total_tests = 0
    total_evaded = 0
    for case in cases:
        print(f"\n--- {case['attack']} ---")
        orig_pred, orig_prob = predict_one(case['rule_level'], case['primary_group'], case['decoder'], case['original'])
        print(f"  [baseline, rule_level={case['rule_level']}] is_true_positive={orig_pred}  confidence={orig_prob}")
        if not orig_pred:
            print("  WARNING: baseline itself not classified as attack -- skipping variants for this case")
            continue

        # Realistic worst case: these exact evasion styles (SVG XSS, $() cmdi) are known from
        # this project's own red-team validation to have defeated the original Wazuh custom
        # rules -- so the rule_level a real deployment would see is a generic low one (5), not
        # the custom rule's 12/14, since the regex rule itself gets dodged too.
        variant_rule_level = 5 if use_realistic_rule_level else case['rule_level']
        for variant_name, variant_text in case['variants'].items():
            pred, prob = predict_one(variant_rule_level, case['primary_group'], case['decoder'], variant_text)
            evaded = (pred == False)
            total_tests += 1
            total_evaded += int(evaded)
            status = "EVADED (misclassified as benign!)" if evaded else "still caught"
            print(f"  [{variant_name:22s}, rule_level={variant_rule_level}] is_true_positive={pred}  confidence={prob}  -> {status}")

    print(f"\nSUBTOTAL: {total_evaded}/{total_tests} evasion attempts succeeded ({100*total_evaded/max(total_tests,1):.1f}%)\n")
    return total_tests, total_evaded

print("CLASSIFIER EVASION TEST (counterpart to experiment 05's LLM injection test)\n")
t1, e1 = run_suite("ROUND 1: rule_level held at the attack's original custom-rule level (optimistic -- assumes Wazuh's regex rule still fired)", use_realistic_rule_level=False)
t2, e2 = run_suite("ROUND 2: rule_level dropped to 5 (realistic worst case -- evasion also defeats the Wazuh regex rule, matching only a generic low-severity rule)", use_realistic_rule_level=True)

print("=" * 80)
print(f"OVERALL: Round 1 (rule_level intact): {e1}/{t1} evaded ({100*e1/max(t1,1):.1f}%)")
print(f"         Round 2 (rule_level also evaded, realistic worst case): {e2}/{t2} evaded ({100*e2/max(t2,1):.1f}%)")
print("=" * 80)
