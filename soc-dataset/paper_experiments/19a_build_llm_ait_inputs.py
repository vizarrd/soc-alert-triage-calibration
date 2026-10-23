"""Blind input batches for running the calibrated few-shot LLM baseline on the public AIT-ADS
sample: 150 alerts per scenario (1200 total) + 8 few-shot examples from other rows of the
sample (disjoint from the test rows). Test files carry no labels."""
import pandas as pd, json
df = pd.read_csv('../external_data/ait_ads/ait_sample.csv')
test = df.groupby('scenario', group_keys=False).sample(150, random_state=0).sort_index()
rest = df.drop(test.index)
cols = ['rule_level', 'rule_description', 'decoder', 'full_log']
test = test.reset_index()
test[['index', 'scenario', 'is_true_positive']].rename(columns={'index': 'sample_idx'}).assign(row_id=test.index).to_csv('llm_ait/ground_truth_DO_NOT_READ.csv', index=False)
for b in range(8):
    with open(f'llm_ait/batch_{b}.jsonl', 'w') as f:
        for i, r in test.iloc[b*150:(b+1)*150].iterrows():
            f.write(json.dumps({'row_id': int(i), **{c: (None if pd.isna(r[c]) else str(r[c])[:400]) for c in cols}}) + '\n')
ex = pd.concat([rest[~rest.is_true_positive].sample(4, random_state=1), rest[rest.is_true_positive].sample(4, random_state=1)])
with open('llm_ait/fewshot_examples.jsonl', 'w') as f:
    for _, r in ex.iterrows():
        f.write(json.dumps({**{c: (None if pd.isna(r[c]) else str(r[c])[:400]) for c in cols}, 'is_true_positive': bool(r.is_true_positive)}) + '\n')
print(len(test), 'test alerts', test.is_true_positive.mean())
