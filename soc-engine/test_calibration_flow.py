"""End-to-end test of the calibration loop against a disposable Postgres (schema.sql applied):
  1. stream synthetic alerts (attacks + benign, ground truth known) through the real engine/model;
  2. before any labels the engine must be UNCALIBRATED (default threshold);
  3. label randomly served alerts through the real dashboard API (token required; wrong token rejected);
  4. once >= 22 labelled attacks exist the state becomes CERTIFIED and the engine's threshold changes;
  5. the engine then uses the calibrated threshold for new alerts.
Simulated analyst = the known ground truth of the synthetic alerts (this tests the SYSTEM, not label quality)."""
import os
import random
os.environ['LABEL_TOKEN'] = 'test-token'

import calibration
import config
import dashboard
import db
import engine
import models

random.seed(0)
ATTACKS = [
    ('31103', 8, 'SQL injection attempt.', 'web|attack|accesslog', 'web-accesslog',
     "GET /search?q=%27+UNION+SELECT+username%2Cpassword+FROM+users--+ HTTP/1.1\" 200"),
    ('100100', 12, 'Possible OS command injection attempt in web request.', 'attack|command_injection', 'web-accesslog',
     'GET /ping?host=127.0.0.1;whoami HTTP/1.1" 200'),
    ('100101', 12, 'Possible Cross-Site Scripting (XSS) attempt in web request.', 'attack|xss', 'web-accesslog',
     'GET /profile?name=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200'),
    ('31151', 10, 'Multiple web server 400 error codes from same source IP.', 'web|accesslog|web_scan|recon', 'web-accesslog',
     '198.51.100.99 - - [14/Sep/2026:09:15:00 +0000] "GET /admin/backup.zip HTTP/1.1" 404 207 "-" "gobuster/3.6"'),
]
BENIGN = [
    ('5501', 3, 'PAM: Login session opened', 'pam|syslog', 'pam',
     'pam_unix(sshd:session): session opened for user maro(uid=1000) by (uid=0)'),
    ('31100', 3, 'Web request', 'web|accesslog', 'web-accesslog', 'GET /search?q=laptop HTTP/1.1" 200'),
]
TRUTH = {}


def make(i, template, is_attack):
    rid, lvl, desc, groups, dec, log = template
    uid = f'cal-{i:04d}'
    TRUTH[uid] = is_attack
    return {'wazuh_alert_uid': uid, 'agent_id': '001', 'agent_name': 'soc-target', 'agent_ip': '10.128.0.3',
            'event_timestamp': '2026-10-15T10:00:00.000+0000', 'rule_id': rid, 'rule_level': lvl,
            'rule_description': desc, 'rule_groups': groups, 'mitre_id': None, 'mitre_tactic': None,
            'mitre_technique': None, 'decoder': dec, 'src_ip': f'198.51.100.{i % 200}', 'full_log': log, 'full_raw': {}}


def main():
    models.load_models()
    conn = db.get_conn()
    assert not db.get_calibration_state(conn)['certified']
    thr0 = db.active_threshold(conn)
    assert thr0 == config.DEFAULT_THRESHOLD, "must start uncalibrated at the default threshold"
    print(f"[ok] starts UNCALIBRATED, threshold={thr0}")

    # 1. stream 300 alerts, ~40% attacks
    for i in range(300):
        is_attack = random.random() < 0.4
        tpl = random.choice(ATTACKS if is_attack else BENIGN)
        r = engine.process_alert(conn, make(i, tpl, is_attack))
        assert not r.get('skipped')
    with conn.cursor() as cur:
        cur.execute("SELECT count(*), count(attack_score) FROM ai_analyses")
        n_an, n_sc = cur.fetchone()
    assert n_an == n_sc == 300, "every analysis must store its attack_score"
    print(f"[ok] 300 alerts processed; attack_score stored for all {n_sc}")

    client = dashboard.app.test_client()

    # 2. token enforcement
    q = client.get('/api/label_queue').get_json()['alert']
    assert client.post('/api/label', json={'alert_id': q['alert_id'], 'is_attack': True}).status_code == 403
    assert client.post('/api/label', json={'alert_id': q['alert_id'], 'is_attack': True}, headers={'X-Label-Token': 'wrong'}).status_code == 403
    assert client.post('/api/label', json={'alert_id': 'x', 'is_attack': True}, headers={'X-Label-Token': 'test-token'}).status_code == 400
    print("[ok] label writes rejected without/with wrong token, bad payload rejected")

    # 3. label randomly served alerts via the API until certified (ground truth from TRUTH)
    need = calibration.min_attacks(config.CALIB_RHO, config.CALIB_DELTA)
    labelled, last = 0, None
    seen = set()
    while labelled < 200:
        q = client.get('/api/label_queue').get_json()['alert']
        assert q['alert_id'] not in seen, "queue must not serve an already-labelled alert"
        seen.add(q['alert_id'])
        with conn.cursor() as cur:
            cur.execute("SELECT wazuh_alert_uid FROM wazuh_alerts WHERE alert_id = %s", (q['alert_id'],))
            uid = cur.fetchone()[0]
        res = client.post('/api/label', json={'alert_id': q['alert_id'], 'is_attack': TRUTH[uid]},
                          headers={'X-Label-Token': 'test-token'}).get_json()
        labelled += 1
        last = res
        if res['certified']:
            break
    assert last['certified'], f"should certify once >= {need} attacks labelled (got n_attacks={last['n_attacks']})"
    assert last['n_attacks'] >= need
    print(f"[ok] CERTIFIED after {labelled} labels ({last['n_attacks']} attacks, need {need}); threshold={last['threshold']:.4f}")

    # 4. engine now uses the calibrated threshold
    db._threshold_cache['t'] = 0.0
    thr1 = db.active_threshold(conn)
    assert thr1 == last['threshold'] and thr1 != config.DEFAULT_THRESHOLD
    r = engine.process_alert(conn, make(9999, ATTACKS[1], True))
    assert r['verdict']['threshold'] == thr1
    print(f"[ok] engine now applies the calibrated threshold {thr1:.4f} (attack_score of a new attack = {r['verdict']['attack_score']})")

    # 5. status endpoint
    st = client.get('/api/calibration').get_json()
    assert st['certified'] and st['n_attacks'] == last['n_attacks']
    print("[ok] /api/calibration reports certified state")
    print("\nALL CALIBRATION FLOW CHECKS PASSED")


if __name__ == '__main__':
    main()
