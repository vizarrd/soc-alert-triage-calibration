"""All database access for the engine. Thin wrappers around psycopg2 -- one function per
write the engine needs to make, matching soc-db/schema.sql exactly."""
import psycopg2
import psycopg2.extras
import config


def get_conn():
    return psycopg2.connect(
        host=config.DB_HOST, port=config.DB_PORT, dbname=config.DB_NAME,
        user=config.DB_USER, password=config.DB_PASSWORD,
    )


def get_or_create_asset(conn, wazuh_agent_id, hostname, ip_address=None):
    with conn.cursor() as cur:
        cur.execute("SELECT asset_id FROM assets WHERE wazuh_agent_id = %s", (wazuh_agent_id,))
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute(
            "INSERT INTO assets (wazuh_agent_id, hostname, ip_address) VALUES (%s, %s, %s) RETURNING asset_id",
            (wazuh_agent_id, hostname, ip_address),
        )
        conn.commit()
        return cur.fetchone()[0]


def insert_alert(conn, asset_id, alert):
    """alert: dict with keys matching wazuh_alerts columns (event_timestamp, rule_id, rule_level,
    rule_description, rule_groups, mitre_id, mitre_tactic, mitre_technique, decoder, src_ip,
    full_log, full_raw, wazuh_alert_uid[optional])."""
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO wazuh_alerts
               (wazuh_alert_uid, asset_id, event_timestamp, rule_id, rule_level, rule_description,
                rule_groups, mitre_id, mitre_tactic, mitre_technique, decoder, src_ip, full_log, full_raw)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (wazuh_alert_uid) DO NOTHING
               RETURNING alert_id""",
            (
                alert.get('wazuh_alert_uid'), asset_id, alert['event_timestamp'], alert['rule_id'],
                alert['rule_level'], alert.get('rule_description'), alert.get('rule_groups'),
                alert.get('mitre_id'), alert.get('mitre_tactic'), alert.get('mitre_technique'),
                alert.get('decoder'), alert.get('src_ip'), alert.get('full_log'),
                psycopg2.extras.Json(alert.get('full_raw', {})),
            ),
        )
        row = cur.fetchone()
        conn.commit()
        return row[0] if row else None


def insert_analysis(conn, alert_id, verdict):
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO ai_analyses
               (alert_id, model_version, is_true_positive, tp_confidence, severity, priority,
                recommended_action, attack_score)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING analysis_id""",
            (alert_id, config.MODEL_VERSION, verdict['is_true_positive'], verdict['confidence'],
             verdict['severity'], verdict['priority'], verdict['recommended_action'],
             verdict.get('attack_score')),
        )
        analysis_id = cur.fetchone()[0]
        conn.commit()
        return analysis_id


# ---------------------------------------------------------------------------
# Calibration: analyst labels -> recall-guaranteed threshold (see calibration.py and the paper)
# ---------------------------------------------------------------------------
import time
import calibration

_threshold_cache = {'t': 0.0, 'value': None}


def get_calibration_state(conn):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM calibration_state WHERE id = 1")
        row = cur.fetchone()
        conn.commit()
        return dict(row) if row else None


def active_threshold(conn, max_age_seconds=20):
    """Threshold the engine should use now: the certified, recall-guaranteed one if it was computed for
    the CURRENT model version, else config.DEFAULT_THRESHOLD (uncalibrated). Cached briefly."""
    now = time.time()
    if now - _threshold_cache['t'] < max_age_seconds and _threshold_cache['value'] is not None:
        return _threshold_cache['value']
    value = config.DEFAULT_THRESHOLD
    st = get_calibration_state(conn)
    if st and st['certified'] and st['threshold'] is not None and st['model_version'] == config.MODEL_VERSION:
        value = float(st['threshold'])
    _threshold_cache.update(t=now, value=value)
    return value


def get_random_unlabeled_alert(conn):
    """Uniformly random alert, among those scored by the current model, that has no analyst label yet.
    Uniform random selection is what makes the guarantee's assumption (A1) hold -- the analyst must not
    choose which alerts to label."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """SELECT wa.alert_id, wa.event_timestamp, wa.rule_id, wa.rule_level, wa.rule_description,
                      wa.decoder, wa.src_ip, wa.full_log
               FROM wazuh_alerts wa
               JOIN ai_analyses a ON a.alert_id = wa.alert_id AND a.model_version = %s AND a.attack_score IS NOT NULL
               LEFT JOIN analyst_labels l ON l.alert_id = wa.alert_id
               WHERE l.alert_id IS NULL
               ORDER BY random() LIMIT 1""",
            (config.MODEL_VERSION,),
        )
        row = cur.fetchone()
        conn.commit()
        return dict(row) if row else None


def add_label(conn, alert_id, is_attack, labeled_by='analyst'):
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO analyst_labels (alert_id, is_attack, labeled_by) VALUES (%s, %s, %s)
               ON CONFLICT (alert_id) DO NOTHING""",
            (alert_id, bool(is_attack), labeled_by),
        )
        inserted = cur.rowcount
        conn.commit()
    return inserted


def recalibrate(conn):
    """Recompute the threshold from all analyst labels scored by the current model version and store it.
    Certified only when enough labelled attacks exist (calibration.min_attacks); otherwise stays
    uncertified and the engine keeps using DEFAULT_THRESHOLD."""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT l.is_attack, a.attack_score
               FROM analyst_labels l
               JOIN ai_analyses a ON a.alert_id = l.alert_id AND a.model_version = %s AND a.attack_score IS NOT NULL""",
            (config.MODEL_VERSION,),
        )
        rows = cur.fetchall()
    attack_scores = [float(s) for is_attack, s in rows if is_attack]
    threshold, certified = calibration.guaranteed_threshold(attack_scores, config.CALIB_RHO, config.CALIB_DELTA)
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE calibration_state
               SET model_version = %s, threshold = %s, certified = %s, n_labeled = %s, n_attacks = %s,
                   rho = %s, delta = %s, updated_at = now() WHERE id = 1""",
            (config.MODEL_VERSION, threshold if certified else None, certified, len(rows), len(attack_scores),
             config.CALIB_RHO, config.CALIB_DELTA),
        )
        conn.commit()
    _threshold_cache['t'] = 0.0   # force refresh
    return get_calibration_state(conn)


def find_recent_open_incident(conn, asset_id, rule_id, within_minutes=15):
    """Look for an already-open incident on this asset triggered by the same rule within the
    last `within_minutes`. Used to correlate repeated alerts (e.g. the same bot re-trying SSH
    logins every few seconds) into one incident instead of opening a new one per alert."""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT i.incident_id FROM incidents i
               JOIN incident_alerts ia ON ia.incident_id = i.incident_id
               JOIN wazuh_alerts wa ON wa.alert_id = ia.alert_id
               WHERE i.asset_id = %s AND wa.rule_id = %s AND i.status = 'open'
                 AND i.updated_at > now() - (%s || ' minutes')::interval
               ORDER BY i.updated_at DESC LIMIT 1""",
            (asset_id, rule_id, within_minutes),
        )
        row = cur.fetchone()
        return row[0] if row else None


def link_alert_to_incident(conn, incident_id, alert_id):
    """Attach another alert to an existing incident (correlation) and bump its updated_at
    so the incident reflects it's still an active, ongoing event."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (incident_id, alert_id),
        )
        cur.execute("UPDATE incidents SET updated_at = now() WHERE incident_id = %s", (incident_id,))
        conn.commit()


def open_incident(conn, asset_id, alert_id, title, severity, priority, summary):
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO incidents (title, asset_id, severity, priority, summary)
               VALUES (%s, %s, %s, %s, %s) RETURNING incident_id""",
            (title, asset_id, severity, priority, summary),
        )
        incident_id = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (%s, %s)",
            (incident_id, alert_id),
        )
        conn.commit()
        return incident_id


def log_action(conn, incident_id, action_type, description, taken_by='ai_engine', status='completed'):
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO actions (incident_id, action_type, description, taken_by, status)
               VALUES (%s, %s, %s, %s, %s) RETURNING action_id""",
            (incident_id, action_type, description, taken_by, status),
        )
        conn.commit()
        return cur.fetchone()[0]
