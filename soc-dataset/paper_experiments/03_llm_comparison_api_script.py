"""LLM vs lightweight trained classifier comparison on the SAME held-out test set (round 4:
unseen IP, real pentest-tool traffic) used throughout this project's experiments.

Measures, per alert:
  - LLM verdict (true/false positive) via zero-shot prompting
  - Latency (wall-clock seconds per call)
  - Token usage (for cost calculation)

Compares against our trained classifier's already-known F1/precision/recall on the identical
test set, plus real cost-per-alert and scaled-to-volume cost projections.

Requires GEMINI_API_KEY environment variable.
"""
import os
import re
import time
import json
import pandas as pd
import numpy as np
import urllib.request
import urllib.error

API_KEY = os.environ.get('GEMINI_API_KEY', '')
MODEL = 'gemini-3.5-flash-lite'
API_URL = f'https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent?key={API_KEY}'

# Gemini 2.0 Flash public pricing (per 1M tokens, as of general availability) -- used only to
# project cost at realistic SOC alert volumes; the free tier itself costs $0 for this experiment.
PRICE_PER_1M_INPUT_TOKENS = 0.10
PRICE_PER_1M_OUTPUT_TOKENS = 0.40

SYSTEM_PROMPT = """You are a security analyst triaging a Wazuh SIEM alert. Given the alert details, decide:
1. is_true_positive: true if this represents a genuine security threat, false if it's benign/routine activity
2. severity: one of "low", "medium", "high", "critical"

Respond with ONLY a JSON object, no other text: {"is_true_positive": true/false, "severity": "..."}"""


def classify_with_llm(rule_level, rule_description, decoder, full_log, max_retries=4):
    prompt = (f"{SYSTEM_PROMPT}\n\nAlert:\n"
              f"Rule level: {rule_level}\n"
              f"Rule description: {rule_description}\n"
              f"Decoder: {decoder}\n"
              f"Log: {full_log}")

    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.0, "maxOutputTokens": 100}
    }).encode('utf-8')

    start = time.time()
    result = None
    last_error = None
    for attempt in range(max_retries):
        req = urllib.request.Request(API_URL, data=body, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode('utf-8'))
            break
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8')
            last_error = f'HTTP {e.code}: {err_body[:200]}'
            if e.code in (429, 500, 503):
                time.sleep(2 ** attempt)  # backoff: 1s, 2s, 4s, 8s -- free-tier gets rate-limited/overloaded
                continue
            break
        except Exception as e:
            # Covers socket timeouts, connection resets, DNS hiccups -- a single flaky call
            # must not crash a 696-alert batch run.
            last_error = f'{type(e).__name__}: {e}'
            time.sleep(2 ** attempt)
            continue

    elapsed = time.time() - start
    if result is None:
        return {'error': last_error or 'unknown failure after retries', 'elapsed': elapsed}

    try:
        text = result['candidates'][0]['content']['parts'][0]['text']
        usage = result.get('usageMetadata', {})
        input_tokens = usage.get('promptTokenCount', 0)
        output_tokens = usage.get('candidatesTokenCount', 0)

        match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
        if not match:
            return {'error': f'no JSON found in response: {text[:200]}', 'elapsed': elapsed}
        parsed = json.loads(match.group(0))
        return {
            'is_true_positive': bool(parsed.get('is_true_positive')),
            'severity': parsed.get('severity', 'unknown'),
            'elapsed': elapsed,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
        }
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return {'error': f'{type(e).__name__}: {e} | raw: {json.dumps(result)[:300]}', 'elapsed': elapsed}


def main():
    if not API_KEY:
        print("ERROR: set GEMINI_API_KEY environment variable first.")
        return

    df = pd.read_csv('wazuh_soc_dataset.csv')
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
    r4_mask = df['timestamp'] >= pd.Timestamp('2026-09-14 12:00:00', tz='UTC')
    test_df = df[r4_mask].dropna(subset=['is_true_positive']).reset_index(drop=True)

    print(f"Classifying {len(test_df)} alerts via {MODEL}...")

    results = []
    errors = 0
    for i, row in test_df.iterrows():
        r = classify_with_llm(row['rule_level'], row.get('rule_description', ''), row.get('decoder', ''), row['full_log'])
        r['true_label'] = bool(row['is_true_positive'])
        r['alert_id'] = row.get('alert_id', i)
        results.append(r)
        if 'error' in r:
            errors += 1
        if (i + 1) % 25 == 0:
            print(f"  {i+1}/{len(test_df)} done, {errors} errors so far")
        time.sleep(0.1)  # stay well under free-tier rate limits

    with open('llm_results.jsonl', 'w') as f:
        for r in results:
            f.write(json.dumps(r) + '\n')

    print(f"\nDone. {errors} errors out of {len(results)} calls.")
    print("Saved raw results to llm_results.jsonl")


if __name__ == '__main__':
    main()
