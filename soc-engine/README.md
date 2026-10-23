# AI Decision Engine (step 7)

The live pipeline: Wazuh alert -> trained model -> database -> incident -> (critical severity) phone call.

## Files

| File | Purpose |
|---|---|
| `wazuh_reader.py` | Parses `alerts.json` (Wazuh's own alert log) into a normalized dict. `read_existing()` for batch/backfill, `follow()` for live tailing. |
| `models.py` | Loads the two trained models (`../soc-dataset/models/*.joblib`) and runs `predict_alert()` -- identical feature pipeline to the training notebook, including `clean_log_text()`. |
| `db.py` | All writes to the Postgres schema (`../soc-db/schema.sql`). |
| `notifier.py` | Places a real phone call via Twilio when triggered. Fails soft -- if Twilio isn't configured, it logs and continues instead of crashing. |
| `engine.py` | Orchestrator: ties the above together. `process_alert()` is the core function; `--backfill` and `--follow` are the two run modes. |
| `self_test.py` | End-to-end test: 8 simulated alerts spanning benign traffic, SSH brute force, recon/scanning, SQLi, command injection, XSS (with a payload never seen in training), and SSTI/RCE, run through the real models and a real database. **Already run and passing 8/8** -- see below. |

## Self-test results (already verified, not just written)

Ran the full pipeline against a disposable Postgres container with the real trained models:

- 8/8 simulated alerts got the correct `is_true_positive` verdict, covering every major attack category plus two benign cases (to check for false-alarm-proneness, not just detection).
- Along the way it caught a real bug in the test's own simulated data (wrong `rule_groups` field order made a recon alert look like an unseen category to the model) -- fixed, then re-verified as an 8/8 pass. This is exactly the kind of gap self-testing is supposed to catch before a live demo, not during one.
- Incidents were only opened for genuine true positives, and the logged `actions` matched the AI's recommended response (`block_ip` for command injection/SSTI, `notify_analyst` for XSS/recon, `log_only` for lower-severity true positives).
- One honest caveat: the recon alert's confidence came out to 0.511 -- correctly classified, but close to the 0.55 incident-opening threshold. Worth keeping an eye on with real traffic; not a bug, just a thin margin on one category (consistent with the "thin categories" caveat already in the dataset README).

Re-run it yourself anytime with a throwaway Postgres instance:
```bash
docker run -d --rm --name test-db -e POSTGRES_PASSWORD=test -e POSTGRES_DB=socdb postgres:16-alpine
docker exec -i test-db psql -U postgres -d socdb < ../soc-db/schema.sql
# then run self_test.py with SOC_DB_HOST etc pointed at it
```

## Deploying for real (on the `ctf-bugbounty` VM, when you start it)

```bash
sudo apt install -y postgresql python3-pip
sudo -u postgres createdb socdb
sudo -u postgres psql -d socdb -f ../soc-db/schema.sql

pip install -r requirements.txt
cp .env.example .env   # then fill in DB password + Twilio credentials
python engine.py --backfill /var/ossec/logs/alerts/alerts.json   # process everything so far
python engine.py --follow /var/ossec/logs/alerts/alerts.json     # then run live during the demo
```

## Twilio call: verified working with a real test call

`notifier.py` originally tried passing TwiML inline (`twiml=...`), which Twilio trial accounts
reject with a generic "disallowed parameters" 400 error. Fixed by switching to `url=` pointing
at `twimlets.com` (a free, Twilio-hosted TwiML generator) -- trial accounts accept that. Tested
for real: placed a live call to the admin's verified number and confirmed it actually rang and
played the message correctly.

## Setting up the Twilio phone call (free trial, no card required)

1. Sign up at twilio.com -- free trial gives ~$15 credit, enough for many calls.
2. In the console, verify your own phone number (trial accounts can only call verified numbers -- fine, that's the admin number you want anyway).
3. Get a free Twilio trial phone number (Console -> Phone Numbers -> get a number).
4. Fill into `.env`:
   - `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` -- from the Console dashboard
   - `TWILIO_FROM_NUMBER` -- the Twilio number you got in step 3
   - `TWILIO_TO_NUMBER` -- your own verified phone number
5. That's it -- `notifier.call_admin()` picks these up automatically. Only `critical`-severity true positives trigger a call (configurable via `config.CALL_SEVERITIES`), so trial credit isn't burned on routine noise.

Trial calls include a short Twilio disclaimer before your message plays -- fine for a demo, just don't be surprised by it.

## What's NOT done yet

- The engine hasn't been run against a live Wazuh instance yet (both VMs are stopped) -- only against simulated alerts shaped exactly like real ones. Once you start the `ctf-bugbounty` VM, running `--backfill` against the real `alerts.json` is the natural next real-world test before the live faculty demo.
- No dashboard/UI yet for browsing incidents -- right now it's query-the-database-directly. If you want a simple web view of open incidents for the demo, that's a good next step after this.
