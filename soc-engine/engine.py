"""The AI Decision Engine. Wires together: Wazuh alert -> trained models -> database ->
incident -> (optional) phone call. This is step 7 of the project -- the piece that makes
the whole pipeline live.

Usage:
  python engine.py --backfill /path/to/alerts.json   # process everything in the file once
  python engine.py --follow /path/to/alerts.json      # tail the file and process live
"""
import argparse
import re
import time

import config
import db
import models
import notifier
import wazuh_reader


def _primary_group(rule_groups):
    return rule_groups.split('|')[0] if rule_groups else 'none'


_ACTION_PHRASES = {
    'block_ip': 'block the source I P address',
    'notify_analyst': 'notify a security analyst',
    'log_only': 'log this event for review',
    'no_action': 'no action',
}


def _speakable(text):
    """Light cleanup so Wazuh's rule descriptions read naturally as speech instead of
    sounding like raw log text (slashes, hyphens, acronyms don't read well as-is)."""
    text = text.replace('/', ' or ').replace('-', ' ').replace('_', ' ')
    text = re.sub(r'\bOS\b', 'O S', text)
    text = re.sub(r'\bRCE\b', 'remote code execution', text)
    text = re.sub(r'\bSSTI\b', 'server side template injection', text)
    text = re.sub(r'\bSQL\b', 'S Q L', text)
    text = re.sub(r'\bXSS\b', 'cross site scripting', text)
    return text


def _build_call_message(alert, verdict):
    attack_desc = _speakable(alert.get('rule_description') or 'a security event')
    asset_name = _speakable(alert['agent_name'])
    src_ip = alert.get('src_ip', 'an unknown address')
    action_phrase = _ACTION_PHRASES.get(verdict['recommended_action'], 'immediate review')

    return (
        f"This is an automated alert from your Security Operations Center. "
        f"A {verdict['severity']} severity attack has been detected. "
        f"Attack type: {attack_desc}. "
        f"Affected server: {asset_name}. "
        f"Source I P address: {src_ip}. "
        f"Recommended action: {action_phrase}. "
        f"Please check your dashboard for full details."
    )


def _hour_from_timestamp(ts):
    try:
        from dateutil import parser as dtparser
        return dtparser.isoparse(ts).hour
    except Exception:
        return 12


def process_alert(conn, alert):
    """Runs one normalized Wazuh alert through the full pipeline. Returns a summary dict
    for logging/testing purposes."""
    asset_id = db.get_or_create_asset(conn, alert['agent_id'], alert['agent_name'], alert.get('agent_ip'))

    alert_id = db.insert_alert(conn, asset_id, alert)
    if alert_id is None:
        # Duplicate (same wazuh_alert_uid already processed) -- skip silently.
        return {'skipped': True}

    verdict = models.predict_alert(
        rule_level=alert['rule_level'],
        primary_group=_primary_group(alert['rule_groups']),
        decoder=alert.get('decoder') or 'unknown',
        full_log=alert.get('full_log', ''),
        hour=_hour_from_timestamp(alert.get('event_timestamp')),
        threshold=db.active_threshold(conn),   # recall-guaranteed once analysts have labelled enough alerts
    )

    db.insert_analysis(conn, alert_id, verdict)

    result = {'alert_id': alert_id, 'verdict': verdict, 'incident_id': None, 'called': False}

    # The (calibrated) threshold already decides threat vs benign, so no extra confidence gate here.
    should_open_incident = verdict['is_true_positive']
    if should_open_incident:
        # Correlate repeated alerts from the same asset+rule (e.g. a bot retrying SSH logins
        # every few seconds) into one ongoing incident instead of spawning a new row per alert.
        existing_incident_id = db.find_recent_open_incident(conn, asset_id, alert['rule_id'])
        if existing_incident_id:
            db.link_alert_to_incident(conn, existing_incident_id, alert_id)
            result['incident_id'] = existing_incident_id
        else:
            title = f"{alert.get('rule_description', 'Security event')} on {alert['agent_name']}"
            summary = (f"AI verdict: true positive (confidence {verdict['confidence']}), "
                       f"severity {verdict['severity']}, source IP {alert.get('src_ip', 'unknown')}.")
            incident_id = db.open_incident(conn, asset_id, alert_id, title, verdict['severity'], verdict['priority'], summary)
            result['incident_id'] = incident_id

            db.log_action(conn, incident_id, verdict['recommended_action'],
                           f"AI-recommended action based on verdict: {verdict['recommended_action']}")

            if verdict['severity'] in config.CALL_SEVERITIES:
                reason = _build_call_message(alert, verdict)
                called = notifier.call_admin(reason)
                if called:
                    db.log_action(conn, incident_id, 'phone_call', 'Called admin via Twilio', taken_by='ai_engine')
                result['called'] = called

    return result


def run_backfill(path):
    models.load_models()
    conn = db.get_conn()
    alerts = wazuh_reader.read_existing(path)
    print(f"Processing {len(alerts)} existing alerts...")
    incidents_opened = 0
    for alert in alerts:
        r = process_alert(conn, alert)
        if r.get('incident_id'):
            incidents_opened += 1
    print(f"Done. {incidents_opened} incidents opened.")
    conn.close()


def run_follow(path):
    models.load_models()
    conn = db.get_conn()
    print(f"Watching {path} for new alerts (Ctrl+C to stop)...")
    for alert in wazuh_reader.follow(path):
        r = process_alert(conn, alert)
        if r.get('incident_id'):
            print(f"[engine] Incident #{r['incident_id']} opened -- {r['verdict']}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--backfill', metavar='PATH', help='Process all alerts currently in the file once')
    parser.add_argument('--follow', metavar='PATH', help='Tail the file and process new alerts live')
    args = parser.parse_args()

    if args.backfill:
        run_backfill(args.backfill)
    elif args.follow:
        run_follow(args.follow)
    else:
        parser.print_help()
