# Independent label audit

Purpose: our round-4 labels were assigned by rule (by us), with no second annotator. This kit lets a human
label a random stratified sample **blind** (without seeing our labels) so agreement can be measured.

1. Give the annotator ONLY `audit_tool.html` (open it in a browser; works offline; progress is saved in the
   browser; ~70 alerts, ~15-20 min). Do **not** share `private_key/`.
2. The annotator answers two questions per alert: Q1 (fact) is there malicious/unauthorized activity (including
   automated scanning)? Q2 (policy) should it be escalated to an analyst? They are deliberately separate:
   scanner noise can be factually malicious yet not worth escalating.
3. The annotator downloads `my_labels.json` (button at the bottom) and returns it.
4. Score: `python score_audit.py my_labels.json` (needs scikit-learn, numpy; run in this folder).

Sample (seed 1): 16 round-4 attack-labelled, 20 round-4 scanner-noise (our label: benign), all 16 other
round-4 benign, 12 public AIT-ADS alerts (6 in / 6 outside attack windows), plus 6 repeated items for the
annotator's self-consistency. `build_audit.py` regenerates everything.

The scoring script was tested only on a synthetic annotator (never used for any reported result). Ideally the
annotator is someone other than the person who built the dataset; one annotator gives agreement, not a gold standard.
