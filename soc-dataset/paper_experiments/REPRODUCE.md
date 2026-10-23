# Reproducing the paper's tables and figures

All experiments run in Docker (`python:3.11-slim`, Python 3.11.16) with these package versions
(installed with `pip install scikit-learn pandas numpy scipy xgboost statsmodels matplotlib` at the
time of the runs): scikit-learn 1.9.1, pandas 3.0.6, numpy 2.4.6, scipy 1.17.1, xgboost 3.2.0,
statsmodels 0.15.0, matplotlib 3.11.2. Run from this directory (`paper_experiments/`), e.g.:

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "<path-to>/soc-dataset:/w" -w /w/paper_experiments python:3.11-slim \
  bash -c "pip install -q scikit-learn pandas numpy scipy xgboost statsmodels matplotlib && python -W ignore <script>.py"
```

## Data and splits

| Item | Definition |
|---|---|
| Our dataset | `../wazuh_soc_dataset.csv` (969 labeled alerts). **Train** = timestamp < 2026-09-14 12:00 UTC (rounds 1-3, 273 alerts, 6 source IPs); **test** = timestamp >= 12:00 (round 4, 696 alerts, source IP 35.238.91.197) |
| Public data | AIT Alert Data Set (Landauer, Skopik, Wurzenberger; Zenodo 10.5281/zenodo.8263181, CC BY 4.0). Download `ait_ads.zip` + `labels.csv` to `../external_data/ait_ads/` (md5 of zip: 43db6b1f0996e0024befd617706c50e9), unzip to `raw/`. Label = alert timestamp inside any attack-phase window of `labels.csv` for its scenario |
| AIT samples | `18a_build_ait_sample.py` (4,000 alerts/scenario, seed 0) and `23a_build_large_ait_sample.py` (up to 50,000/scenario, seed 1) |
| Features / model configs | Defined once in `13_triage_relief_analysis.py` (`prep`, `pre`, `make_models`, `accum`): StandardScaler(rule_level, hour) + OneHot(primary rule group, decoder) + TF-IDF(300 features, 1-2 grams) on log text cleaned by `clean()`; RF 300 trees depth 12 balanced; LogReg balanced; MLP (64,32) early stopping; XGBoost 300 trees depth 6 |

## Seeds

Round-4 tables use RF seeds 0-19, MLP seeds 0-9, XGBoost seeds 0-9, ensemble seeds 0-19. Random label draws use
`numpy.random.default_rng(0)` (experiments 15, 16, 18, 20, 23). With only 273 training alerts the RF and MLP are
strongly seed-dependent (RF recall 0.16-0.38, MLP unstable), which is why earlier single-run numbers differ.

## Table / figure -> script

| Paper item | Script | Output |
|---|---|---|
| Tables I-III (leakage, ensemble, model comparison; also LLM rows, scanner/other-benign split), TRC table | `24_unified_round4_table.py` | `24_results.txt`, `24_per_seed_results.csv` |
| Prevalence table | `24b_prevalence_from_unified.py` (+ `16_prevalence_projection.py` for the "+20 labels" row) | `24b_results.txt`, `16_results.txt` |
| LLM rows (zero-shot) | `03b_score_llm_results.py` over `03c_llm_raw_classifications.jsonl` | `03d_llm_scored_comparison.csv` |
| LLM rows (few-shot) | `17a_build_llm_v2_inputs.py` -> blind sessions -> `17_score_llm_v2.py` | `17_results.txt`, `llm_v2/` |
| Triage Relief Curve figure | `13_triage_relief_analysis.py` | `fig_triage_relief_curve.png`, `13_results.txt` |
| Threshold transfer / few-label (our data) | `14_operating_point_transfer.py`, `15_few_label_calibration.py` | `14_results.txt`, `15_results.txt` |
| External validation (AIT, small) | `18a_...`, `18_external_validation_ait_ads.py` | `18_results.txt` |
| LLM on AIT | `19a_build_llm_ait_inputs.py` -> blind sessions -> `19_score_llm_ait.py` | `19_results.txt`, `llm_ait/` |
| Guarantee study (small) | `20_label_selection_and_recall_guarantee.py` | `20_results_*.txt` |
| Large-scale guarantee table (Table IV): raw per-setting results | `23a_build_large_ait_sample.py`, `23_large_scale_guarantee_validation.py` | `23_results.txt`, `23_per_cell_results.csv` (every Table IV number is derived from this file) |
| Table IV: certified coverage, intervals, N_cert | `23e_certified_vs_all_draws.ps1` | `23e_results.txt` |
| Table IV: same-scenario all-trial coverage, uncertified shares, the "at most 0.008" claim | `23f_matched_scenario_coverage.ps1` | `23f_results.txt`, `23f_results_precise.txt` (max difference 0.0076) |
| Minima, below-0.90 settings, Wilson intervals, 10,000-draw reruns (rerun table) | `23b_certified_only_coverage.py`, `23d_coverage_rerun_and_intervals.py` | `23b_results.txt`, `23d_results.txt` |
| Data provenance (2,600,263 raw / 391,488 sampled, distinct strings) | `23c_provenance.py` | `23c_results.txt` |
| Exact finite-population check of the rule (min 0.9007 over 8,775 settings) | `29_exact_finite_population_check.ps1` | `29_results.txt` |
| Live calibration study (labels, corrections, retrain cross-validation) | `../models/train_logreg_v3_with_live_labels.py` (run on the VM) | `live_calibration_export/`, `28_live_retrain_cv_results.txt` |
| Feature ablation | `21_feature_ablation.py` | `21_results_*.txt` |
| Benign diversity (public data) | `25_benign_diversity_ait.py` | `25_results.txt` |
| Overview figure | `22_overview_figure.py` | `fig_overview.png` |
| (not in the paper; kept for the project) Adversarial LLM injection / classifier evasion | `05*` files, `10_classifier_evasion_test.py` | `05*_results.jsonl`, `10_results.txt` |
| (not in the paper; kept for the project) Cost/latency | `08_cost_latency_estimate.py` | `08_results.txt` |

## Known limitations of reproducibility

- **LLM runs** used blind, memory-isolated Claude sessions, not a metered API; exact reruns depend on model version and may
  differ. Raw verdicts are released (`03c_*.jsonl`, `llm_v2/result_*.jsonl`, `llm_ait/result_*.jsonl`).
- Experiments 18/20/21/23 depend on the AIT download above (not redistributed here).
- Experiments 02, 06, 07 (earlier single-run versions) are superseded by 24 for every number that appears in the paper;
  they are kept for the audit trail.

| Guarantee figure (coverage / noise cleared vs k) | `27_guarantee_figure.py` | `fig_guarantee.png` |

Note: the paper is limited to 6 pages; the earlier 9-page version is archived in `../paper_archive/`.

## Additional runs (experiments 30-31)

| Paper item | Script | Output |
|---|---|---|
| LLM vs trained models on the same 1,200 alerts (AIT section) | `30_llm_vs_models_same_alerts.py` | `30_results.txt` |
| Implementation cross-check of the calibration rule | `31_implementation_crosscheck.py` | `31_results.txt` |

Experiments 30 and 31 were run with a local Python 3.12 virtual environment (scikit-learn 1.9.1, pandas 3.0.6, numpy 2.5.4, scipy 1.18.1); earlier experiments used the Docker image listed at the top (numpy 2.4.6, scipy 1.17.1). The versions of scikit-learn and pandas are identical; numpy/scipy differ by a minor version.
