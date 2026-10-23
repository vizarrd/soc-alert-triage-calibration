"""Score the LLM (Claude subagent) classifications against ground truth, and report the
same metrics used for the trained classifier/ensemble experiments, on the identical round-4
test set, so all three are directly comparable."""
import json
import pandas as pd
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score

llm = pd.read_json('llm_results_merged.jsonl', lines=True)
labels = pd.read_json('round4_labels.jsonl', lines=True)

merged = labels.merge(llm, on='row_id', how='left', suffixes=('_true', '_llm'))
missing = merged['is_true_positive_llm'].isna().sum()
print(f"Total test alerts: {len(labels)}, LLM predictions received: {len(llm)}, missing/unmatched: {missing}")

merged = merged.dropna(subset=['is_true_positive_llm'])
y_true = merged['is_true_positive_true'].astype(bool)
y_pred = merged['is_true_positive_llm'].astype(bool)

print("\n=== LLM (Claude, zero-shot, blind subagent classification) on round 4 ===")
print(classification_report(y_true, y_pred, target_names=['False Positive', 'True Positive']))

f1 = f1_score(y_true, y_pred)
prec = precision_score(y_true, y_pred)
rec = recall_score(y_true, y_pred)

print("\n=== COMPARISON TABLE (all on identical round-4 test set: unseen IP + real pentest tools) ===")
print(f"{'Model':40s} {'F1':>8s} {'Precision':>10s} {'Recall':>8s}")
print(f"{'Trained classifier alone (fixed)':40s} {0.532:8.3f} {0.968:10.3f} {0.366:8.3f}")
print(f"{'Ensemble (classifier+accum+level)':40s} {0.638:8.3f} {0.978:10.3f} {0.473:8.3f}")
print(f"{'LLM (Claude, zero-shot)':40s} {f1:8.3f} {prec:10.3f} {rec:8.3f}")

merged[['row_id', 'is_true_positive_true', 'is_true_positive_llm', 'severity_true', 'severity_llm']].to_csv(
    'llm_scored_comparison.csv', index=False)
print("\nSaved row-by-row comparison to llm_scored_comparison.csv")
