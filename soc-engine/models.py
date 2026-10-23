"""Loads the two trained models and turns a raw parsed alert into an AI verdict.
Feature shape here must exactly match the training notebook (soc-dataset/model_training.ipynb) --
same clean_log_text(), same FEATURE_COLUMNS -- otherwise predictions silently degrade."""
import re
import joblib
import pandas as pd

import config

_tp_pipeline = None
_sev_pipeline = None


def _clean_log_text(text):
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


def load_models():
    """Load both trained pipelines into module-level cache. Call once at engine startup."""
    global _tp_pipeline, _sev_pipeline
    _tp_pipeline = joblib.load(config.TP_MODEL_PATH)
    _sev_pipeline = joblib.load(config.SEV_MODEL_PATH)
    return _tp_pipeline, _sev_pipeline


SEV_TO_PRIORITY = {'low': 2, 'medium': 3, 'high': 4, 'critical': 5}

# Simple, deterministic mapping from attack signal in the log text to a recommended
# response action -- not a third trained model, matches the same "derived, not learned"
# approach used for `priority` in the dataset.
_ACTION_KEYWORDS = [
    (r';|`|\$\(|&&|\bwhoami\b|\bcat /etc', 'block_ip'),          # command injection
    (r'<script|onerror=|onload=|javascript:', 'block_ip'),        # xss
    (r'union\s+select|\bor\s+1=1\b|--\s', 'block_ip'),            # sqli
    (r'authentication failures|brute.?force', 'block_ip'),        # brute force
    (r'\{\{|__class__|__globals__', 'block_ip'),                  # ssti
]


def _recommend_action(full_log, is_tp, severity):
    if not is_tp:
        return 'no_action'
    text = str(full_log).lower()
    for pattern, action in _ACTION_KEYWORDS:
        if re.search(pattern, text, re.I):
            return action
    return 'notify_analyst' if severity in ('high', 'critical') else 'log_only'


def predict_alert(rule_level, primary_group, decoder, full_log, hour=12, threshold=None):
    """Run one raw alert through both trained models. Returns the same shape used
    throughout the project (dataset labels, notebook demo, DB ai_analyses columns).

    The alert is a threat when attack_score >= threshold (threshold defaults to
    config.DEFAULT_THRESHOLD; the engine passes the calibrated one when available)."""
    if _tp_pipeline is None or _sev_pipeline is None:
        load_models()
    if threshold is None:
        threshold = config.DEFAULT_THRESHOLD

    cleaned = _clean_log_text(full_log)
    row = pd.DataFrame([{
        'rule_level': rule_level,
        'hour': hour,
        'primary_group': primary_group,
        'decoder': decoder,
        'full_log': cleaned,
    }])

    classes = list(_tp_pipeline.classes_)
    attack_score = float(_tp_pipeline.predict_proba(row)[0][classes.index(True)])
    is_tp = attack_score >= threshold
    severity = _sev_pipeline.predict(row)[0]
    priority = SEV_TO_PRIORITY[severity] if is_tp else 1
    action = _recommend_action(full_log, is_tp, severity)

    return {
        'is_true_positive': is_tp,
        'attack_score': round(attack_score, 6),
        'confidence': round(attack_score if is_tp else 1 - attack_score, 3),
        'threshold': threshold,
        'severity': severity,
        'priority': priority,
        'recommended_action': action,
    }
