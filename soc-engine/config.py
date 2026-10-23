"""Central config, loaded from environment variables (.env in dev). Never hardcode secrets here."""
import os
from dotenv import load_dotenv

load_dotenv()

# --- Database ---
DB_HOST = os.getenv("SOC_DB_HOST", "localhost")
DB_PORT = os.getenv("SOC_DB_PORT", "5432")
DB_NAME = os.getenv("SOC_DB_NAME", "socdb")
DB_USER = os.getenv("SOC_DB_USER", "postgres")
DB_PASSWORD = os.getenv("SOC_DB_PASSWORD", "")

# --- Wazuh ---
WAZUH_ALERTS_JSON_PATH = os.getenv("WAZUH_ALERTS_JSON_PATH", "/var/ossec/logs/alerts/alerts.json")

# --- Models ---
# True-positive model: Logistic Regression (soc-dataset/models/train_logreg_deploy.py). Its score is only
# actionable together with a calibrated threshold -- see calibration.py and the paper.
TP_MODEL_PATH = os.getenv("TP_MODEL_PATH", "../soc-dataset/models/wazuh_tp_logreg.joblib")
SEV_MODEL_PATH = os.getenv("SEV_MODEL_PATH", "../soc-dataset/models/wazuh_severity_classifier.joblib")
MODEL_VERSION = os.getenv("MODEL_VERSION", "tp_logreg_v2+sev_v1")

# --- Decision thresholds ---
# An alert is a threat when attack_score >= threshold. The threshold is the recall-guaranteed value
# from analyst labels (calibration_state) when certified; until then DEFAULT_THRESHOLD is used and the
# system is explicitly UNCALIBRATED (no recall guarantee; on a shifted distribution it may flag most alerts).
DEFAULT_THRESHOLD = float(os.getenv("DEFAULT_THRESHOLD", "0.5"))
CALIB_RHO = float(os.getenv("CALIB_RHO", "0.90"))        # target recall
CALIB_DELTA = float(os.getenv("CALIB_DELTA", "0.10"))    # allowed failure probability
# Shared secret required to write analyst labels (the dashboard is internet-reachable; without a token
# anyone could poison the calibration). Leave empty to disable label writes entirely.
LABEL_TOKEN = os.getenv("LABEL_TOKEN", "")
# Kept for backwards compatibility with older tests; no longer used to gate incidents.
INCIDENT_MIN_CONFIDENCE = float(os.getenv("INCIDENT_MIN_CONFIDENCE", "0.55"))
CALL_SEVERITIES = {"critical"}  # only phone-call the admin for these severities

# --- Twilio (leave blank to disable calling -- engine still works, just skips the call) ---
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "")
TWILIO_TO_NUMBER = os.getenv("TWILIO_TO_NUMBER", "")

# Only needed when testing notifier.py from somewhere that isn't the VM itself (e.g. local
# Docker) -- on the real VM, notifier.py detects its own public IP automatically.
PUBLIC_HOST = os.getenv("PUBLIC_HOST", "")
