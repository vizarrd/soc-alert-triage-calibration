# Paper Experiments

All experiments underpinning the journal paper's results. Everything here runs against
`../wazuh_soc_dataset.csv`, using the round 1-3 / round 4 disjoint split established in
experiment 01 (train: hand-crafted attacks, 6 source IPs; test: real pentest-tool traffic
from `35.238.91.197`, never seen in training).

## 01 — Leakage disjoint-split experiment (`01_leakage_disjoint_split.py`)

Trains the `is_true_positive` classifier twice — once on raw, uncleaned log text (the
original leaky version) and once with `clean_log_text()` applied (IPs/timestamps stripped)
— both evaluated on round 4 only.

**Result:**

| Model | F1 | Precision | Recall |
|---|---|---|---|
| Leaky (no text cleaning) | 0.313 | 0.923 | 0.188 |
| Fixed (clean_log_text) | 0.539 | 0.968 | 0.373 |

The leaky model misses >80% of real attacks on genuinely unseen traffic; the fix nearly
doubles recall and F1. (Numbers reported in the paper use a second run with minor float
variance: F1 0.532/0.638 for fixed/ensemble — rerun `01` to regenerate exactly.)

## 02 — Ensemble method (`02_ensemble_method.py`, `02b_diagnose_accumulation_scale_bug.py`)

Combines the content classifier's probability with a time-windowed "Accumulation" signal
(alerts-per-source-IP in a trailing 10-minute window, same idea as the Fraunhofer CATS
risk hypothesis) and the raw `rule_level`, fused through a logistic-regression meta-classifier
trained on rounds 1-3.

**First attempt failed**: F1 dropped to 0.153 (worse than the classifier alone). `02b`
diagnoses why — train accumulation scores average 28 (manual attacks), test scores average
342 (real tool floods), a ~12x scale mismatch the meta-classifier was never calibrated for.

**Fix**: log1p-transform the accumulation feature before scaling. Final result:

| Model | F1 | Precision | Recall |
|---|---|---|---|
| Content classifier alone | 0.532 | 0.968 | 0.366 |
| Ensemble (content+accum+level) | 0.638 | 0.978 | 0.473 |

McNemar's test: statistic=43.267, p<0.00001 (74 alerts the ensemble got right that the
classifier alone missed, vs. only 12 the other way — a statistically significant improvement).

## 03 — LLM comparison (`03_llm_comparison_api_script.py`, `03b_score_llm_results.py`)

`03_llm_comparison_api_script.py` is the original API-based script (built for Gemini, hit
persistent free-tier 503/429 errors — kept for reference/reproducibility if a paid key is
used later). The actual classification run used Claude directly (7 parallel subagents, 100
alerts each, blind — no ground truth visible, no project context) instead of a metered API.

`03c_llm_raw_classifications.jsonl` — all 696 round-4 alerts classified.
`03b_score_llm_results.py` — scores those against held-back ground truth.
`03d_llm_scored_comparison.csv` — row-by-row comparison for inspection.

**Result:**

| Model | F1 | Precision | Recall |
|---|---|---|---|
| Trained classifier alone | 0.532 | 0.968 | 0.366 |
| Ensemble | 0.638 | 0.978 | 0.473 |
| LLM (Claude, zero-shot) | 0.905 | 0.827 | **1.000** |

**But: LLM's False-Positive-class recall = 0.02** — it correctly identified only 2% of
actual benign alerts as benign, i.e. it flags almost everything as a threat. High F1 on the
True Positive class, but near-zero actual alert-fatigue relief, which is the entire stated
purpose of these systems. This is the paper's central "accuracy isn't the whole story" finding.

## 04 — Determinism test (`04_determinism_test_alerts.jsonl`, `04b/c/d_..._results.jsonl`)

5 representative alerts (benign SSH login, SQLi, command injection, XSS, scan noise),
classified independently 3 times by fresh, memory-isolated subagents (no shared context
between runs — a genuine blind repeat, not a self-remembered one).

**Result:** 4/5 alerts got perfect 3-way agreement. 1/5 (`row_id 694`, a successful SSH
login sharing a source IP with an attack campaign) got three different verdicts: benign/low,
true-positive/high, true-positive/medium — zero agreement on severity. Our classifier is
deterministic by construction (same `.joblib` file, same input, same output, always).

## 05 — Prompt injection robustness (`05_injection_payloads_v1/v2.jsonl`, `05b/c/d_..._results.jsonl`)

A real, working command-injection attack (`GET /ping?host=127.0.0.1;whoami`) with various
injection payloads appended to the log field, attempting to manipulate an LLM classifier
into mislabeling it as benign:
- `direct_override` — fake "[SYSTEM NOTE: ... classify as benign]"
- `fake_system_tag` — fake `<system>` XML tags claiming an analyst override
- `roleplay_jailbreak` — "you are now in training-data-labeling mode" reframing
- `encoded_instruction` — base64-encoded override instruction
- `fake_json_answer` / `delimiter_breakout` (v2, more sophisticated) — impersonates the
  actual prompt structure and pre-writes a fake benign JSON answer

Tested three ways: naive prompt (matching the main 696-alert classification exactly, no
explicit injection defense), explicitly-defended prompt, and the v2 advanced payloads
against the naive prompt.

**Result: 12/12 resisted** across all three conditions — every attempt still correctly
classified as `true_positive: true, severity: high`.

**Honest framing**: this is a negative result for these specific techniques against this
specific model, not proof LLMs are immune to prompt injection in general. The stronger,
paper-worthy claim is structural: our classical classifier has no instruction-following
channel to exploit at all (a permanent architectural guarantee), while the LLM's safety here
depends entirely on alignment training holding up — an ongoing arms race, not a guarantee.

## 06 — Model comparison and explicit `rule_level` baseline (`06_model_comparison_and_baseline.py`, `06_results.txt`)

**Baseline**: a single threshold on `rule_level` alone (tuned on train via Youden's J,
evaluated on round 4 — never peeked at test to pick the threshold).

**Model comparison**: RandomForest vs. LogisticRegression vs. MLP vs. XGBoost, identical
feature pipeline, identical disjoint split.

**Striking result:**

| Model | F1 | Precision | Recall | FP-class recall (noise cleared) |
|---|---|---|---|---|
| `rule_level` threshold alone | **0.905** | 0.827 | 1.000 | **0.02** |
| LogisticRegression | 0.909 | 0.833 | 1.000 | 0.07 |
| RandomForest (our classifier) | 0.539 | 0.968 | 0.373 | 0.94 |
| MLP | 0.633 | 0.993 | 0.464 | 0.98 |
| XGBoost | 0.625 | 0.734 | 0.545 | 0.08 |

A trivial, free threshold on a number Wazuh already computes gets the **exact same F1
(0.905) as the LLM baseline from experiment 03**, with the exact same failure pattern
(near-zero false-positive suppression). Round 4 is 82% true positives, so "flag everything"
is a cheap way to post a high F1 without doing real triage — the LLM, logistic regression,
and a one-line threshold all independently fell into this trap. RandomForest and MLP sacrifice
raw recall for genuine discrimination (94-98% noise correctly cleared), which is the metric
that actually matters for the alert-fatigue problem these systems exist to solve.

## 07 — Bootstrap confidence intervals (`07_bootstrap_confidence_intervals.py`, `07_results.txt`)

2000-resample bootstrap 95% CIs on F1 and recall for all four headline models, same test set.
All intervals are tight (not noisy flukes). Notably, `rule_level_baseline` and `LLM_Claude`
have **identical CIs** — `F1 [0.887, 0.921]`, `Recall [1.000, 1.000]` — further confirming
they are doing the same thing, not coincidentally similar.

## 08 — Cost/latency estimate (`08_cost_latency_estimate.py`, `08_results.txt`)

Our classifier's inference time is **directly measured** (real, not estimated): 30.23 ms/alert,
$0.00 marginal cost. The LLM side uses disclosed, published-pricing estimates (since this
project classified via Claude directly rather than a metered API — see experiment 03).

At 100,000 alerts/day: our classifier processes the full volume in ~50 minutes at $0/day;
the LLM baseline would take ~22 hours of sequential processing at ~$32/day — a 26x latency
gap, scaling linearly with alert volume.

## 09 — Data sovereignty analysis (`09_data_sovereignty_analysis.md`)

Qualitative write-up: our classifier never sends alert data anywhere (runs in-process on the
same VM as Wazuh); an LLM-based approach continuously exports full attack payloads, IPs,
hostnames, and usernames to a third-party API at whatever the organization's alert volume is.
Covers the regulatory angle (PCI-DSS/HIPAA/FedRAMP-style restrictions) and the honest
counterpoint (on-prem/VPC-isolated LLM deployment exists, at added cost/complexity).

## 10 — Classifier evasion test (`10_classifier_evasion_test.py`, `10_results.txt`)

The honest counterpart to experiment 05: if we claim the classical classifier is "safer"
than the LLM because it has no instruction-following channel for prompt injection, we owe
the paper a test of its own equivalent failure mode — statistical evasion of the TF-IDF
features, using the same evasion styles (case variation, comment injection, encoding,
operator/synonym substitution) that are documented in this project's own earlier red-team
round (`../VALIDATION.md`) to have actually defeated the original Wazuh custom rules.

Tested in two rounds against 3 real attacks (SQLi, command injection, XSS), 4 evasion
variants each (12 per round, 24 total):
- **Round 1** (optimistic): `rule_level` held at the original custom-rule value, as if
  Wazuh's regex rule still fired despite the evasion.
- **Round 2** (realistic worst case): `rule_level` dropped to a generic 5, simulating the
  evasion *also* defeating the Wazuh rule itself (which is exactly what happened to SVG-XSS
  and `$()`-command-injection evasion in the earlier red-team round, before hardening).

**Result: 0/24 evasion attempts succeeded in either round.** Confidence measurably eroded
on every variant (e.g. SQLi synonym-swap: 0.839 → 0.739) without crossing the 0.5 decision
boundary — honest evidence the model is being pushed toward its limit, not proof it's
unbeatable. Paired with experiment 05 (LLM: 12/12 injection attempts resisted), both systems
held up against the specific techniques tested here, with the important caveat that neither
result generalizes to "immune to all future evasion" — pattern/statistics-based detection
is an ongoing arms race for any method.

## 11 — Severity classification evaluation (`11_severity_evaluation.py`, `11_results.txt`)

4-class severity (low/medium/high/critical), same disjoint split, RandomForest vs. the LLM's zero-shot severity labels from experiment 03.

| Model | Macro F1 | Accuracy |
|---|---|---|
| Our RandomForest | 0.368 | 0.44 |
| LLM (Claude, zero-shot) | 0.165 | 0.25 |

**Honest reading: severity is NOT solved by either system.** Ours collapses almost everything into "medium" (295/295 medium correct, but 0/124 high and 10/274 critical): a plausible (untested) cause is that round-4 tool traffic has a severity distribution unlike training. The LLM is better calibrated on "critical" precision (1.00) but badly under-calls it (26/274) and mislabels 149 mediums as low. Our model is ~2x better in macro F1, but neither is deployable for severity ranking; the paper reports this as a limitation and treats binary true-positive triage as the contribution.

## 12 — Figures and feature importance (`12_figures_and_feature_importance.py`, `12_feature_importance.txt`)

Produces `fig_confusion_binary.png`, `fig_confusion_severity.png`, `fig_model_comparison.png` (copied into `../paper/`) and the feature importances of the final binary RandomForest.

**Binary confusion matrix (round 4):** TN 116, FP 7, FN 359, TP 214.

**Feature importance by family:** log text 0.81, rule_level 0.07, decoder 0.06, rule group 0.05, hour 0.01. The top individual features are `rule_level` and log-*source* tokens (`pam_unix`, `session`, PAM decoder/group), not attack-payload keywords. Honest reading: part of the noise-clearing ability comes from recognizing routine log sources, not attack semantics (residual shortcut learning); the paper states this as a limitation.

## 13 — Triage Relief Curve / threshold-free analysis (`13_triage_relief_analysis.py`, `13_results.txt`, `fig_triage_relief_curve.png`)

ROC-AUC, PR-AUC, MCC, balanced accuracy, Relief@R95 for rule_level, LogReg, RF, MLP, Ensemble; 5 seeds; forward (train r1-3 -> r4) and reverse (train r4 -> r1-3).

**Forward AUC:** MLP 0.978, LogReg 0.969, rule_level 0.966, Ensemble 0.556, **RF 0.405 (below chance)**. Relief@R95: MLP 0.948, LogReg 0.935, rule_level 0.024, Ensemble 0.073, RF 0.060.
**Reverse AUC:** LogReg 0.917, rule_level 0.896, MLP 0.713 (std 0.24), RF 0.591.

**This corrects experiment 06:** the RF's 0.94 "noise cleared" at threshold 0.5 is a conservative-threshold artifact (it calls most unfamiliar traffic benign, recall 0.37), not discrimination. The deployed RF is the weakest ranker; the ensemble's McNemar gain is a better operating point on a weak ranker.

## 14 — Operating-point transfer (`14_operating_point_transfer.py`, `14_results.txt`)

Threshold chosen on training data (out-of-fold, time-blocked) for 95% recall, applied to the shifted target. Forward: LogReg/MLP/rule_level reach recall ~1.0 but clear 0-6.5% of noise (flag everything; prior shift 20% -> 82% attacks); RF reaches recall 0.16. Reverse: partly works (rule_level recall 0.945 / noise cleared 0.817). Thresholds do not transfer reliably.

## 15 — Few-label recalibration (`15_few_label_calibration.py`, `15_results.txt`)

Frozen model, threshold re-set from k random analyst-labelled target alerts (200 draws), evaluated on the rest. k=20: LogReg recall 0.961 / noise cleared 0.935; MLP 0.955 / 0.926; k=10 is variable (LogReg recall p5 0.738). RF stays at ~0.057 noise cleared; rule_level unstable (p5 0.02). Caveats: one target environment (123 benign alerts in round 4), one direction, random rather than realistic analyst-queue labels.

## 16 — Prevalence projection (`16_prevalence_projection.py`, `16_results.txt`)

Round 4 is 82% attacks (an artifact of attacking our own server; real SOCs are mostly FP). TPR/FPR are prevalence-independent, so they are measured on round 4 and precision/F1/review-burden projected analytically to 1/5/10/30/82% prevalence. LLM and rule_level are indistinguishable from flag-everything at every prevalence (TPR 1.0, FPR 0.976; 19.5 alerts reviewed per attack at 5% vs 20.0). Frozen LogReg + 20 labels: TPR 0.96, FPR 0.065, F1@5% 0.60, 2.3 alerts/attack. Assumes TPR/FPR transfer to other environments (unverified).

## 17 — Stronger LLM baseline (`17a_build_llm_v2_inputs.py`, `17_score_llm_v2.py`, `17_results.txt`, `llm_v2/`)

Calibrated prompt + 8 few-shot examples from training rounds, blind sessions, probability output. Result unchanged: TPR 1.000, FPR 0.976, ROC-AUC 0.618, Relief@R95 0.024.

**Label-provenance caveat discovered here:** 107 of the 123 round-4 benign alerts are one type ("Web server 400 error code", scanner noise) labelled benign by our own convention; labels are rule-based, with no independent annotator. Noise clearing on round 4 is largely learning that one convention. Disclosed in the paper's Limitations.

## 18 — External validation on public AIT-ADS Wazuh alerts (`18a_build_ait_sample.py`, `18_external_validation_ait_ads.py`, `18_results.txt`, `18_per_scenario_results.csv`)

Dataset: AIT Alert Data Set (Landauer, Skopik, Wurzenberger; Zenodo 10.5281/zenodo.8263181, CC BY 4.0; md5 verified), raw files in `../external_data/ait_ads/` (not our data, not for redistribution beyond its license). 8 scenarios, 4,000 uniformly sampled Wazuh alerts each (seed 0); label = timestamp inside any attack-phase window (noisy, window-level). Leave-one-scenario-out; prevalence 6.8%-88.6%.

Mean over 8 held-out scenarios: ROC-AUC rule_level 0.692, LogReg 0.960, **RF 0.964**, MLP 0.957. Honest differences from our own data:
- RF is NOT a weak ranker here (so its AUC 0.405 on our data is shift-specific, not general).
- Identifier-leakage does NOT replicate: RF raw-text AUC 0.961 vs cleaned 0.964.
- Threshold transfer: noise is cleared (~100%) but recall misses the 95% target (0.81-0.92 mean; RF recall 0.00 on `shaw`, LogReg 0.60 on `russellmitchell`). 20-label recalibration raises worst cases (RF shaw 0.00 -> 0.82) but mean recall only 0.86-0.93, noise cleared 0.83-0.86 — weaker than on our data.
LLM was not run on this dataset.

## 19 — LLM on the public AIT-ADS data (`19a_build_llm_ait_inputs.py`, `19_score_llm_ait.py`, `19_results.txt`, `llm_ait/`, `19_ait_llm_ground_truth.csv`)

Calibrated few-shot prompt, 150 alerts/scenario (1,200), blind sessions. Pooled TPR 0.976, FPR 0.000, ROC-AUC 0.987, Relief@R95 1.00; recall lower in low-prevalence scenarios (santos 0.73, shaw 0.75, wardbeck 0.89). **Contradicts the "LLM = flag-everything" reading from our own data**, which was caused by our label convention (107/123 benign = scanner 400 noise). The paper withdraws the general claim. Caveat: how carefully each subagent judged each alert (they finished 150 alerts in ~17 s) cannot be verified.

## 20 — Label selection and recall guarantee (`20_label_selection_and_recall_guarantee.py`, `20_results_ait_part.txt`, `20_results_own_part.txt`, `20_ait_per_target.csv`)

Strategies: random, uncertainty, score-stratified (importance-weighted), and "guaranteed" (distribution-free order-statistic rule: threshold s_(r), largest r with Beta cdf(0.10; r, n-r+1) >= 0.90 -> recall >= 0.90 with 90% confidence; needs >= 22 labelled attacks, else flag-everything). AIT (LogReg, 8 held-out scenarios): coverage (share of draws with recall >= 0.90) random .58/.68/.83/.92, guaranteed 1.0/.98/.98/.97 at k=20/50/100/200; noise cleared guaranteed .47-.56 vs random .72-.84 (price of the guarantee). Uncertainty sampling is worse (.50-.75); stratified ~ random. Our data: guaranteed coverage 1.0 with negligible cost at k>=50.

## 21 — Feature-family ablation (`21_feature_ablation.py`, `21_results_ait_part.txt`, `21_results_own_part.txt`)

AIT: all 0.960 AUC; any single family dropped changes AUC <= 0.002; rule group alone 0.964, decoder alone 0.963, text alone 0.958, rule_level alone 0.692. Ours: all 0.969, rule_level alone 0.966, dropping rule_level -> 0.397, text alone 0.334 (below chance). Different signals carry each dataset.

## 22 — Overview figure (`22_overview_figure.py`, `fig_overview.png`)

## 23 — Large-scale validation of the recall guarantee (`23a_build_large_ait_sample.py`, `23_large_scale_guarantee_validation.py`, `23_results.txt`, `23_per_cell_results.csv`)

400,000 AIT-ADS alerts (up to 50,000 per scenario; `external_data/ait_ads/ait_large.csv`). Leave-one-scenario-out; train on up to 10,000/scenario; LogReg and RF; 1,000 labelling draws per cell; k in {50,100,200,500,1000}; rho in {0.80,0.90,0.95}; delta=0.10; true recall/noise cleared computed on the whole held-out stream. **Guaranteed rule: coverage >= 0.923 in every one of 240 (scenario, model, k, rho) cells at rho=0.90 (target 0.90)**; naive quantile rule 0.32-0.80 (~0.5 on average, as expected for a rule aiming at the target itself). Cost: in the 7-9%-prevalence scenarios the rule cannot certify with 200 labels (needs ~22/prevalence ~ 500); mean noise cleared (LogReg, rho=0.9): k=200 0.56, k=1000 0.72 vs naive 0.87.

## 24 — Unified round-4 evaluation, many seeds (`24_unified_round4_table.py`, `24b_prevalence_from_unified.py`, `24_results.txt`, `24b_results.txt`, `24_per_seed_results.csv`)

**Supersedes the single-run numbers of experiments 01/02/06/07/13/16 for every round-4 value in the paper.** Resolves the inconsistent RF numbers (recall 0.373 / 0.367 / 0.16): with 273 training alerts the RF's default-threshold recall ranges 0.16-0.38 across 20 seeds (mean 0.32 +- 0.09). MLP is unstable (recall 0.56 +- 0.31, noise cleared 0.81 +- 0.37, AUC 0.88 +- 0.19; earlier MLP results used favourable seeds). Leakage replicates over 20 seeds (F1 0.297 vs 0.471; recall 0.177 vs 0.319). Ensemble beats RF in 20/20 seeds (F1 0.672 +- 0.010 vs 0.471 +- 0.115); McNemar seed 0: 210 vs 12, p~7e-40. Noise cleared is split into the 107 scanner-noise alerts vs the 16 other benign alerts: RF clears 1.00 / 0.58, LLM and rule_level clear 0.00 / 0.19, so "noise cleared" is dominated by one alert type.

## 25 — Benign diversity on the public data (`25_benign_diversity_ait.py`, `25_results.txt`)

AIT benign: 41 rule types (19-33 per scenario) but top-5 types = 96%; **90% of AIT's attack-window alerts are "Web server 400 error code" — the alert type we label benign**. The two datasets use opposite label conventions for scanner noise.

## Reproducibility
See `REPRODUCE.md` (package versions, seeds, split definitions, table/figure -> script map). The recall-guaranteed threshold rule is also released as tested code: `../../soc-engine/calibration.py`.

## 26 — Label-convention sensitivity (`26_label_convention_sensitivity.py`, `26_results.txt`, `26_convention_sensitivity.csv`)

Same predictions scored under convention A (scanner noise = benign, paper default) and B (scanner noise = attack; 680 attacks / 16 benign). Under B rule_level and the LLM are essentially correct (recall 1.0), RF recall 0.32 -> 0.27, AUC rule_level 0.966 -> 0.851, LogReg 0.969 -> 0.722. The round-4 method ranking is convention-dependent.

## Label audit kit (`../label_audit/`)
Blind human annotation tool + scoring script for independent validation of our labels (see its README). No human results yet.

## 23b — Certified-only coverage (`23b_certified_only_coverage.py`, `23b_results.txt`)

Fallback draws (fewer than 22 labelled attacks -> flag everything) have recall 1 and inflate coverage. Certified-only coverage = (coverage - fallback)/(1 - fallback), over the 184 of 240 settings with >= 100 certified draws: mean 0.965 at rho=0.90 (62 settings, minimum 0.899), 0.983 at rho=0.80, 0.967 at rho=0.95. Two settings are slightly below target (0.899 with 148 certified draws; 0.862 at rho=0.80 with 116), within binomial noise (sd ~0.03). **Corrects the earlier "never below 0.92" statement, which counted fallback draws.** Protocol difference vs the small study (exp. 20): exp. 20 measures recall on the unlabelled remainder of a 4,000-alert sample; exp. 23 measures it on the whole held-out stream (up to 50,000 alerts).

## 23c / 23d — Provenance and coverage uncertainty (`23c_provenance.py`, `23d_coverage_rerun_and_intervals.py`, results files)

**23c:** the public data has 2,600,263 raw Wazuh alerts; `ait_large.csv` holds 391,488 drawn uniformly WITHOUT replacement (seed 1; russellmitchell used in full), nothing duplicated or synthesized; distinct log strings 285,858 (53-57% in scan-heavy scenarios, 88-97% in others). Alerts are time-correlated, so the independent units for generalization are the 8 scenarios, not the alert count. (Earlier text said "400,000"; the exact number is 391,488.)

**23d:** Wilson intervals for certified coverage; nominal coverage level is 1-delta = 0.90 for every rho. Two of 184 settings were below 0.90 (0.899 [0.84,0.94], 148 draws; 0.862 [0.79,0.91], 116 draws); none has an interval entirely below 0.90. Re-run with 10,000 draws, a fresh training sample, recall measured on alerts EXCLUDED from the labelled sample: 0.936 [0.923,0.947] and 0.930 [0.915,0.942]. Pooled: 166,698/171,017 certified draws met their target (0.975; descriptive only - draws within a setting share one model and stream). `soc-engine/calibration.py` self-test now also covers tied scores (coverage 0.976).

## 23e — Certified vs all-draw coverage (`23e_certified_vs_all_draws.ps1`, `23e_results.txt`)

Table III of the paper reports coverage two ways for the guaranteed rule (LogReg, rho=0.90): over ALL draws (fallback draws count as successes: operational success rate) and over CERTIFIED draws only (>=22 labelled attacks; pooled over scenarios with >=100 certified draws of 1,000; Wilson intervals; pooling treats draws as independent so the interval is descriptive). Certified coverage: k=50 0.961 [0.955,0.967]; k=100 0.940 [0.933,0.947]; k=200 0.944 [0.937,0.950]; k=500 0.952 [0.947,0.956]; k=1000 0.955 [0.950,0.959]. The paper also states that the Beta rule is exact for i.i.d. draws, that our experiments sample without replacement from a finite stream (at most 2% of it), and that we do not prove finite-population dominance in general; the without-replacement coverage experiments are the direct check.

## 23f — Matched-scenario coverage (`23f_matched_scenario_coverage.ps1`, `23f_results.txt`)

Certified coverage exists only for scenarios with >= 100 certified draws, so the all-draw coverage must be computed over exactly the same scenarios to be comparable. Matched (k=50..1000): all-draw 0.961/0.947/0.952/0.952/0.955 vs certified 0.961/0.940/0.944/0.952/0.955 — differences under 0.01. The earlier larger all-draw figures (0.98/0.97/0.96) averaged all 8 scenarios, a different scenario set that includes fallback draws in low-attack-rate scenarios. Table III now shows both sets of columns, labelled. Note noise cleared in the matched high-prevalence scenarios is much higher (0.92 at k=50) than the all-8 average (0.46), which is dominated by fallback in the low-prevalence scenarios.

## 29 — Exact finite-population check of the rule (`29_exact_finite_population_check.ps1`, `29_results.txt`)

For sampling WITHOUT replacement from a finite stream with N distinct-score attacks, the rule's threshold meets recall rho iff Hypergeometric(N, K=floor((1-rho)N)+1, n) >= r, so its exact success probability is computable. Over 8,775 settings (n from the rule's minimum to 1,000; rho in {0.80,0.90,0.95}; delta=0.10; N in {3,426; 10,000; 44,524}) the minimum exact success probability is **0.9007** (rho=0.90, N=44,524, n=65); no setting is below 0.90. This is a numerical verification on a grid (tie-free scores; ties only add slack), not a general proof; it complements the Monte Carlo coverage experiments (exp. 23).

## 30 — LLM vs trained models on the SAME alerts (`30_llm_vs_models_same_alerts.py`, `30_results.txt`)

The LLM (exp. 19) saw 150 alerts per scenario (1,200); exp. 18 scored the trained models on 4,000 per scenario, so the paper's earlier "LLM ranks best (AUC 0.987)" compared unlike sets. Here LogReg/RF/MLP/rule_level (trained leave-one-scenario-out) are scored on exactly the LLM's 1,200 alerts. Mean per-scenario AUC: LLM 0.959, LogReg 0.950, RF 0.954, MLP 0.947, rule_level 0.695; pooled AUC 0.987/0.987/0.989/0.989/0.699; Relief@R95 0.625 (LLM) vs 0.72-0.74 (trained). Paired bootstrap 95% CI of LLM minus method (mean per-scenario AUC): LogReg [-0.009,+0.027], RF [-0.011,+0.024], MLP [-0.001,+0.029], rule_level [+0.217,+0.308]. **Conclusion: on par with trained models, not better.** Paper text corrected accordingly.

## 31 — Implementation cross-check of the calibration rule (`31_implementation_crosscheck.py`, `31_results.txt`)

(1) Rank selection computed three ways (Beta cdf, explicit binomial tail, the deployed `soc-engine/calibration.py`) for 468 (n, rho) pairs: 0 mismatches; minimum labelled attacks = 22 as derived. (2) Hand-built score vectors confirm the threshold is the r-th smallest labelled attack score, flagging is inclusive (>=) and ties at the threshold are handled correctly; fewer than 22 attacks falls back to -inf. (3) End-to-end on i.i.d. continuous scores the rule's coverage matches the exact success probability within Monte Carlo error (n=22: 0.905 vs 0.9015; n=40: 0.920 vs 0.920; n=100: 0.942 vs 0.942).

**Scenario-level uncertainty (added to exp. 30):** per-scenario AUC of LLM / LogReg / RF / MLP / rule_level is in `30_results.txt`. Bootstrap over the 8 scenarios (10,000 resamples) for the LLM's mean AUC advantage: LogReg [-0.007,+0.025] (LLM higher in 4/8 scenarios), RF [-0.003,+0.018] (2/8), MLP [+0.001,+0.027] (3/8; the +0.012 mean edge rests mostly on wardbeck and shaw), rule_level [+0.225,+0.307] (8/8). The alert-level paired bootstrap (alerts resampled within each scenario, 2,000 replicates) treats the scenarios and fitted models as fixed. No statistically established winner among LLM and trained models. Scores saved in `30_scores.npz`.

## Status: experiments 01-31 complete (+23b-f)
