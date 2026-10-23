# AI-SOC Database (step 6)

Tracks the full incident lifecycle: Wazuh alert → AI decision → incident → response action. This is the piece that sits between Wazuh and the AI engine's output on one side, and a dashboard/analyst on the other.

## Schema (`schema.sql`)

| Table | Purpose |
|---|---|
| `assets` | Every host Wazuh monitors (agents), with criticality/ownership context |
| `analysts` | SOC users who can be assigned incidents |
| `wazuh_alerts` | Raw alerts as received from Wazuh — parsed fields match the training dataset's columns exactly, so inference input always matches training input. `full_raw` keeps the complete original JSON for audit. |
| `ai_analyses` | The AI Decision Engine's verdict per alert (`is_true_positive`, confidence, severity, priority, recommended action). One row per `(alert, model_version)`, so retraining and re-scoring never destroys history. |
| `incidents` | The real, analyst-facing unit of work — one incident can group many alerts (e.g. 40 brute-force alerts + 1 successful login = one incident) |
| `incident_alerts` | Join table linking incidents to their underlying alerts |
| `actions` | Full audit trail of response actions (automated or manual): what was done, by what/whom, when, and whether it succeeded |

Verified by actually running the schema against a real PostgreSQL 16 instance (disposable Docker container, discarded after testing) — confirmed all tables/indexes/trigger create cleanly, a full alert → analysis → incident → action chain inserts and links correctly with foreign keys enforced, the `updated_at` trigger fires on incident updates, and invalid data (e.g. a bogus `severity` value) is correctly rejected by the check constraints. Not a dummy schema — this is real, tested SQL.

## Running it

No new GCP resource needed — install PostgreSQL directly on the existing `ctf-bugbounty` VM (it already runs the Wazuh manager). This keeps cost identical to what you already have: the DB only costs anything while that VM is running, same as Wazuh itself.

```bash
sudo apt install -y postgresql
sudo -u postgres createdb socdb
sudo -u postgres psql -d socdb -f schema.sql
```

## Next (step 7)

The integration script that:
1. Pulls new alerts from Wazuh (via its API or by tailing `alerts.json`)
2. Inserts them into `wazuh_alerts`
3. Runs each one through `wazuh_tp_classifier.joblib` / `wazuh_severity_classifier.joblib` (see `../soc-dataset/models/`)
4. Writes the verdict into `ai_analyses`
5. Opens/updates an `incidents` row when a verdict crosses a threshold, and logs the response in `actions`

This is what turns the schema from "empty tables" into the live pipeline for the faculty demo.
