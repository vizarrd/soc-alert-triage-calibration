"""Generates paper figures (confusion matrix of the final binary classifier, model-comparison
bar chart of F1 vs noise-cleared rate, severity confusion matrices) and the top feature
importances of the final (cleaned-text) RandomForest. Outputs: fig_*.png, 12_feature_importance.txt"""
import re
import pandas as pd, numpy as np
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix

exec(open('10_classifier_evasion_test.py').read().split("train_df =")[0].split("RANDOM_STATE = 42")[1].replace("df = pd.read_csv('../wazuh_soc_dataset.csv')", "df = pd.read_csv('../wazuh_soc_dataset.csv')"))
RANDOM_STATE = 42
train_df = df[~r4_mask].dropna(subset=['is_true_positive']).copy()
test_df = df[r4_mask].dropna(subset=['is_true_positive']).copy()
ytr = train_df['is_true_positive'].astype(bool); yte = test_df['is_true_positive'].astype(bool)
pipe = Pipeline([('features', build_preprocessor()),
                 ('clf', RandomForestClassifier(n_estimators=300, max_depth=12, class_weight='balanced', random_state=RANDOM_STATE))])
pipe.fit(prep(train_df), ytr)
pred = pipe.predict(prep(test_df))
cm = confusion_matrix(yte, pred, labels=[False, True])
print("Binary confusion matrix (rows true F/T, cols pred F/T):\n", cm)

def heat(ax, m, labels, title):
    ax.imshow(m, cmap='Blues')
    ax.set_xticks(range(len(labels))); ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels); ax.set_yticklabels(labels)
    ax.set_xlabel('Predicted'); ax.set_ylabel('True'); ax.set_title(title)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, int(m[i, j]), ha='center', va='center', color='white' if m[i, j] > m.max()/2 else 'black')

fig, ax = plt.subplots(figsize=(3.4, 3)); heat(ax, cm, ['FP', 'TP'], 'Binary triage (round 4)')
fig.tight_layout(); fig.savefig('fig_confusion_binary.png', dpi=300)

sev = ['low', 'medium', 'high', 'critical']
fig, axs = plt.subplots(1, 2, figsize=(7, 3))
heat(axs[0], np.loadtxt('11_confusion_matrix_ours.csv', delimiter=',', skiprows=1), sev, 'Ours (RF)')
heat(axs[1], np.loadtxt('11_confusion_matrix_llm.csv', delimiter=',', skiprows=1), sev, 'LLM zero-shot')
fig.tight_layout(); fig.savefig('fig_confusion_severity.png', dpi=300)

# Model comparison: F1 vs noise-cleared (values from 06_results.txt / README)
names = ['rule_level\nthreshold', 'LogReg', 'RF (ours)', 'MLP', 'XGBoost', 'LLM']
f1 = [0.905, 0.909, 0.539, 0.633, 0.625, 0.905]
fpr = [0.02, 0.07, 0.94, 0.98, 0.08, 0.02]
x = np.arange(len(names)); w = 0.38
fig, ax = plt.subplots(figsize=(7, 3))
ax.bar(x - w/2, f1, w, label='F1 (TP class)'); ax.bar(x + w/2, fpr, w, label='Noise cleared (FP recall)')
ax.set_xticks(x); ax.set_xticklabels(names, fontsize=8); ax.set_ylim(0, 1.05); ax.legend(fontsize=8)
ax.set_title('High F1 does not imply alert-fatigue relief')
fig.tight_layout(); fig.savefig('fig_model_comparison.png', dpi=300)

# Feature importance (aggregate by feature family + top individual features)
names_f = pipe.named_steps['features'].get_feature_names_out()
imp = pipe.named_steps['clf'].feature_importances_
order = np.argsort(imp)[::-1][:15]
with open('12_feature_importance.txt', 'w') as f:
    f.write("Top 15 features (RandomForest, cleaned-text model)\n")
    for i in order: f.write(f"{names_f[i]:50s} {imp[i]:.4f}\n")
    fam = {}
    for n, v in zip(names_f, imp): fam[n.split('__')[0]] = fam.get(n.split('__')[0], 0) + v
    f.write("\nImportance by feature family:\n")
    for k, v in sorted(fam.items(), key=lambda kv: -kv[1]): f.write(f"{k:20s} {v:.4f}\n")
print(open('12_feature_importance.txt').read())
