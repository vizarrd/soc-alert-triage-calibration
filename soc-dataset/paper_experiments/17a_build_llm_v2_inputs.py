"""Builds blind input batches + few-shot examples (from TRAIN rounds 1-3 only) for an improved
LLM baseline (experiment 17). Test alerts contain no labels."""
import pandas as pd, json
df = pd.read_csv('../wazuh_soc_dataset.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
r4 = df['timestamp'] >= pd.Timestamp('2026-09-14 12:00:00', tz='UTC')
te = df[r4].dropna(subset=['is_true_positive']).reset_index(drop=True)
cols = ['rule_level', 'rule_description', 'decoder', 'full_log']
for b in range(7):
    chunk = te.iloc[b*100:(b+1)*100]
    with open(f'llm_v2/batch_{b}.jsonl', 'w') as f:
        for i, r in chunk.iterrows():
            f.write(json.dumps({'row_id': int(i), **{c: (None if pd.isna(r[c]) else str(r[c])[:400]) for c in cols}}) + '\n')
tr = df[~r4].dropna(subset=['is_true_positive'])
ex = pd.concat([tr[tr.is_true_positive == False].sample(4, random_state=1), tr[tr.is_true_positive == True].sample(4, random_state=1)])
with open('llm_v2/fewshot_examples.jsonl', 'w') as f:
    for _, r in ex.iterrows():
        f.write(json.dumps({**{c: (None if pd.isna(r[c]) else str(r[c])[:400]) for c in cols}, 'is_true_positive': bool(r.is_true_positive)}) + '\n')
print(len(te), 'test alerts;', len(ex), 'few-shot examples')
