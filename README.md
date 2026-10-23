# Recall-Constrained Alert Triage Across SOCs: Statistical Threshold Calibration

Code, data and experiment scripts for the paper *Recall-Constrained Alert Triage Across SOCs: Statistical Threshold Calibration* (`soc-dataset/paper/`).

Repository: https://github.com/vizarrd/soc-alert-triage-calibration

Archived release: Zenodo DOI **[to be filled after the first release]**.

The paper studies how alert-triage models behave when moved between environments: why F1 on an
attack-heavy test set can hide "flag everything" behaviour, why thresholds do not transfer, and how a
classical order-statistic rule can set a recall-guaranteed threshold from a few analyst-labelled alerts.

## What is here

| Folder | Contents |
|---|---|
| `soc-dataset/` | The labelled Wazuh alert dataset (`wazuh_soc_dataset.csv/.jsonl`, 969 alerts), the raw unlabelled export, the dataset README and `VALIDATION.md` (red-team validation of the custom rules), the attack scripts (`scripts/`), and the original training notebook |
| `soc-dataset/paper/` | `paper.tex`, `paper.pdf` and the four figure files it uses |
| `soc-dataset/paper_figures/` | Scripts and sources of the figures (`fig_sys.tex` for the architecture diagram, `fig_rule.py`/`fig_rule_cols.py` for the threshold-mechanism figure, `fig_data.py` for the guarantee heat map) |
| `soc-dataset/paper_experiments/` | Every experiment behind the paper (numbered scripts, saved result files). Start with `README.md` (what each experiment found) and `REPRODUCE.md` (package versions, seeds, which script produces which table or figure) |
| `soc-dataset/paper_experiments/live_calibration_export/` | Labels and corrections from the live calibration study (two rounds, one analyst), including the audit table of every label we corrected |
| `soc-dataset/label_audit/` | A blind annotation tool (`audit_tool.html`) and scoring script for independent label validation. **No human-validation results exist yet**; the answer key is deliberately withheld |
| `soc-dataset/models/` | Training scripts for the deployed models (trained model files are not included; they are reproducible with these scripts) |
| `soc-engine/` | The live pipeline: Wazuh alert reader, model scoring, PostgreSQL storage, dashboard with the label-and-calibrate tab, and `calibration.py` (the order-statistic threshold rule with a self-test) |
| `soc-db/` | PostgreSQL schema and the calibration migration |

## The calibration rule in one paragraph

Given the frozen model's scores for *n* randomly sampled, analyst-confirmed attacks, pick the largest rank
*r* with `Beta(r, n-r+1).cdf(1-rho) >= 1-delta` and use the *r*-th lowest score as the threshold. If no *r*
exists (fewer than 22 attacks for rho=0.90, delta=0.10) the system falls back to flagging everything.
The guarantee holds when the labelled alerts are a uniform random sample, the labels are correct, and the
model and attack-score distribution do not change afterwards. See `soc-engine/calibration.py` (run
`python calibration.py` for the self-test) and Section VI of the paper.

## Reproducing the results

1. Python 3.11 with `scikit-learn 1.9.1, pandas 3.0.6, numpy 2.4.6, scipy 1.17.1, xgboost 3.2.0,
   statsmodels 0.15.0, matplotlib 3.11.2` (exact versions used; see `REPRODUCE.md`).
2. Round-4 and our-data experiments run directly from `soc-dataset/` (the CSV is included).
3. **Public data is not redistributed.** The cross-environment experiments use the AIT Alert Data Set
   (Landauer, Skopik, Wurzenberger; Zenodo DOI 10.5281/zenodo.8263181, CC BY 4.0). Download `ait_ads.zip` and
   `labels.csv` into `external_data/ait_ads/` (zip md5 `43db6b1f0996e0024befd617706c50e9`), unzip into `raw/`, then run
   `18a_build_ait_sample.py` and `23a_build_large_ait_sample.py`.
4. The LLM experiments used blind Claude sessions, not a metered API. The raw verdicts are saved
   (`03c_*.jsonl`, `llm_v2/`, `llm_ait/`), so every LLM number can be rechecked without rerunning the model.

## Running the live pipeline

Copy `soc-engine/.env.example` to `.env` and fill in your own database password, label token and (optionally)
Twilio credentials. **No credentials are included in this repository.** Apply `soc-db/schema.sql` to a PostgreSQL
database, train the models with the scripts in `soc-dataset/models/`, then see `soc-engine/README.md`.

## Known limitations (also in the paper)

- Labels in our dataset were assigned by the authors from rules and known attack scripts (no independent annotator);
  107 of the 123 benign alerts in the test round are one alert type (scanner "400 error" noise).
- The public data uses attack-window labels, and its attack-window alerts are 90% the same alert type that our
  dataset labels benign.
- The live deployment shows the workflow, not a validated live guarantee: 9 of 71 live labels needed correction.
- The Random Forest and MLP results are seed-dependent with only 273 training alerts; the paper reports means over seeds.

## Privacy note

The alert data comes from our own cloud test deployment. It includes IP addresses of third-party internet hosts that
probed the test server (SSH bots) and our own test hostnames. No personal data beyond that is included.

## License

To be chosen by the authors before publication (suggested: MIT for code, CC BY 4.0 for the dataset).
The AIT Alert Data Set remains under its own CC BY 4.0 license.
