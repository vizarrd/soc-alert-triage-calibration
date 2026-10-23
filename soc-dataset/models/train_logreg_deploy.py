"""Trains the deployable true-positive classifier used by the live engine (soc-engine): a
Logistic Regression on the same features as every experiment in the paper (cleaned log text TF-IDF,
rule_level, hour, rule group, decoder). Trained on ALL 969 labelled alerts of our deployment.

Why Logistic Regression: in the paper it is the only deterministic model that ranks well on the
shifted round-4 data (ROC-AUC 0.969) and, unlike the Random Forest (AUC 0.40) and MLP (seed-unstable),
its behaviour does not depend on the random seed. Its score is only meaningful together with a
CALIBRATED THRESHOLD (see soc-engine/calibration.py): at the default 0.5 it flags almost everything
on a shifted distribution.

Output: wazuh_tp_logreg.joblib (sklearn Pipeline; predict_proba[:,1] = attack score)."""
import re
import joblib
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


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


df = pd.read_csv('../wazuh_soc_dataset.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
df = df.dropna(subset=['is_true_positive'])
X = pd.DataFrame({
    'rule_level': pd.to_numeric(df['rule_level'], errors='coerce').fillna(0),
    'hour': df['timestamp'].dt.hour.fillna(-1),
    'primary_group': df['rule_groups'].fillna('').apply(lambda g: g.split('|')[0] if g else 'none'),
    'decoder': df['decoder'].fillna('unknown'),
    'full_log': df['full_log'].fillna('').apply(clean),
})
y = df['is_true_positive'].astype(bool)

pipe = Pipeline([
    ('features', ColumnTransformer([
        ('rule_level', StandardScaler(), ['rule_level']),
        ('hour', StandardScaler(), ['hour']),
        ('primary_group', OneHotEncoder(handle_unknown='ignore'), ['primary_group']),
        ('decoder', OneHotEncoder(handle_unknown='ignore'), ['decoder']),
        ('full_log', TfidfVectorizer(max_features=300, ngram_range=(1, 2)), 'full_log'),
    ])),
    ('clf', LogisticRegression(class_weight='balanced', max_iter=1000, random_state=0)),
]).fit(X, y)
joblib.dump(pipe, 'wazuh_tp_logreg.joblib')
s = pipe.predict_proba(X)[:, 1]
print(f"trained on {len(y)} alerts ({int(y.sum())} attacks); training-set mean score attacks={s[y].mean():.3f} benign={s[~y].mean():.3f}")
