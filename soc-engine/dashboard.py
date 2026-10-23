"""Live incident dashboard -- a read-only web view of the socdb database, styled to resemble
the Wazuh dashboard's dark/teal look. Single-page app: the shell loads once, then polls small
JSON endpoints every few seconds and updates the DOM in place (no full-page reload/flicker).
"""
import hmac
from flask import Flask, render_template_string, jsonify, request
import psycopg2
import psycopg2.extras
import config
import db as soc_db

app = Flask(__name__)


def get_conn():
    return psycopg2.connect(
        host=config.DB_HOST, port=config.DB_PORT, dbname=config.DB_NAME,
        user=config.DB_USER, password=config.DB_PASSWORD,
    )


@app.route('/')
def index():
    return render_template_string(PAGE)


@app.route('/api/stats')
def api_stats():
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT count(*) AS n FROM wazuh_alerts")
        total_alerts = cur.fetchone()['n']

        cur.execute("SELECT count(*) AS n FROM incidents")
        total_incidents = cur.fetchone()['n']

        cur.execute("SELECT count(*) AS n FROM incidents WHERE status = 'open'")
        open_incidents = cur.fetchone()['n']

        cur.execute("SELECT count(*) AS n FROM actions WHERE action_type = 'phone_call'")
        calls_made = cur.fetchone()['n']

        cur.execute("SELECT count(*) AS n FROM actions WHERE action_type = 'block_ip'")
        blocks = cur.fetchone()['n']

        cur.execute("""
            SELECT severity, count(*) AS n FROM incidents GROUP BY severity
        """)
        severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for row in cur.fetchall():
            severity_counts[row['severity']] = row['n']

        cur.execute("""
            SELECT is_true_positive, count(*) AS n FROM ai_analyses GROUP BY is_true_positive
        """)
        tp_counts = {'true_positive': 0, 'false_positive': 0}
        for row in cur.fetchall():
            key = 'true_positive' if row['is_true_positive'] else 'false_positive'
            tp_counts[key] = row['n']

        # Alerts per minute for the last 20 minutes -- drives the activity sparkline.
        cur.execute("""
            SELECT date_trunc('minute', received_at) AS minute, count(*) AS n
            FROM wazuh_alerts
            WHERE received_at > now() - interval '20 minutes'
            GROUP BY minute ORDER BY minute
        """)
        timeseries = [{'t': row['minute'].strftime('%H:%M'), 'n': row['n']} for row in cur.fetchall()]

        cur.execute("SELECT count(DISTINCT src_ip) AS n FROM wazuh_alerts WHERE src_ip IS NOT NULL")
        unique_sources = cur.fetchone()['n']

    conn.close()
    return jsonify({
        'total_alerts': total_alerts, 'total_incidents': total_incidents,
        'open_incidents': open_incidents, 'calls_made': calls_made, 'blocks': blocks,
        'severity_counts': severity_counts, 'tp_counts': tp_counts,
        'timeseries': timeseries, 'unique_sources': unique_sources,
    })


@app.route('/api/incidents')
def api_incidents():
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT i.incident_id, i.title, i.severity, i.status, i.opened_at, i.updated_at,
                   a.hostname, a.criticality,
                   (SELECT count(*) FROM incident_alerts ia WHERE ia.incident_id = i.incident_id) AS alert_count,
                   COALESCE(string_agg(DISTINCT act.action_type, ', '), 'none') AS actions_summary,
                   (SELECT wa.src_ip FROM incident_alerts ia2 JOIN wazuh_alerts wa ON wa.alert_id = ia2.alert_id
                    WHERE ia2.incident_id = i.incident_id ORDER BY wa.received_at DESC LIMIT 1) AS latest_src_ip
            FROM incidents i
            JOIN assets a ON a.asset_id = i.asset_id
            LEFT JOIN actions act ON act.incident_id = i.incident_id
            GROUP BY i.incident_id, i.title, i.severity, i.status, i.opened_at, i.updated_at, a.hostname, a.criticality
            ORDER BY i.updated_at DESC
            LIMIT 100
        """)
        rows = cur.fetchall()
    conn.close()

    incidents = [{
        'incident_id': r['incident_id'], 'title': r['title'], 'severity': r['severity'],
        'status': r['status'], 'opened_at': r['opened_at'].strftime('%H:%M:%S'),
        'updated_at': r['updated_at'].strftime('%H:%M:%S'), 'hostname': r['hostname'],
        'criticality': r['criticality'], 'alert_count': r['alert_count'],
        'actions_summary': r['actions_summary'], 'latest_src_ip': r['latest_src_ip'] or 'n/a',
    } for r in rows]
    return jsonify(incidents)


@app.route('/api/agents')
def api_agents():
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT a.asset_id, a.hostname, a.ip_address, a.asset_type, a.criticality,
                   MAX(wa.received_at) AS last_seen,
                   count(wa.alert_id) AS alert_count
            FROM assets a
            LEFT JOIN wazuh_alerts wa ON wa.asset_id = a.asset_id
            GROUP BY a.asset_id, a.hostname, a.ip_address, a.asset_type, a.criticality
            ORDER BY a.hostname
        """)
        rows = cur.fetchall()
        cur.execute("SELECT now() AS n")
        now = cur.fetchone()['n']
    conn.close()

    agents = []
    for r in rows:
        if r['last_seen'] is None:
            status = 'never'
        elif (now - r['last_seen']).total_seconds() < 120:
            status = 'active'
        else:
            status = 'idle'
        agents.append({
            'hostname': r['hostname'], 'ip_address': r['ip_address'], 'asset_type': r['asset_type'],
            'criticality': r['criticality'], 'alert_count': r['alert_count'], 'status': status,
            'last_seen': r['last_seen'].strftime('%H:%M:%S') if r['last_seen'] else 'never',
        })
    return jsonify(agents)


@app.route('/api/top_rules')
def api_top_rules():
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT rule_id, rule_description, count(*) AS n
            FROM wazuh_alerts GROUP BY rule_id, rule_description
            ORDER BY n DESC LIMIT 6
        """)
        rows = cur.fetchall()
    conn.close()
    return jsonify([{'label': f"{r['rule_id']}: {r['rule_description'] or ''}", 'n': r['n']} for r in rows])


@app.route('/api/top_sources')
def api_top_sources():
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT src_ip, count(*) AS n FROM wazuh_alerts
            WHERE src_ip IS NOT NULL GROUP BY src_ip
            ORDER BY n DESC LIMIT 6
        """)
        rows = cur.fetchall()
    conn.close()
    return jsonify([{'label': r['src_ip'], 'n': r['n']} for r in rows])


@app.route('/api/recent_alerts')
def api_recent_alerts():
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT wa.alert_id, wa.rule_id, wa.rule_description, wa.rule_level, wa.src_ip,
                   wa.received_at, a.hostname, an.is_true_positive, an.severity, an.confidence_note
            FROM wazuh_alerts wa
            JOIN assets a ON a.asset_id = wa.asset_id
            LEFT JOIN LATERAL (
                SELECT is_true_positive, severity, tp_confidence AS confidence_note
                FROM ai_analyses WHERE alert_id = wa.alert_id ORDER BY analyzed_at DESC LIMIT 1
            ) an ON true
            ORDER BY wa.received_at DESC
            LIMIT 30
        """)
        rows = cur.fetchall()
    conn.close()

    alerts = [{
        'alert_id': r['alert_id'], 'rule_id': r['rule_id'], 'rule_description': r['rule_description'],
        'rule_level': r['rule_level'], 'src_ip': r['src_ip'] or 'n/a', 'hostname': r['hostname'],
        'received_at': r['received_at'].strftime('%H:%M:%S'),
        'is_true_positive': r['is_true_positive'], 'severity': r['severity'] or 'n/a',
    } for r in rows]
    return jsonify(alerts)


@app.route('/api/calibration')
def api_calibration():
    """Current calibration state: is the live threshold recall-guaranteed, and how many more labelled
    attacks are needed? (Read-only; no secrets.)"""
    import calibration
    conn = get_conn()
    st = soc_db.get_calibration_state(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM analyst_labels")
        total_labels = cur.fetchone()[0]
    conn.close()
    need = calibration.min_attacks(config.CALIB_RHO, config.CALIB_DELTA)
    st = st or {}
    return jsonify({
        'certified': bool(st.get('certified')) and st.get('model_version') == config.MODEL_VERSION,
        'threshold': st.get('threshold'), 'default_threshold': config.DEFAULT_THRESHOLD,
        'n_labeled': st.get('n_labeled', 0), 'n_attacks': st.get('n_attacks', 0), 'total_labels': total_labels,
        'attacks_needed': need, 'rho': config.CALIB_RHO, 'delta': config.CALIB_DELTA,
        'model_version': config.MODEL_VERSION, 'labels_enabled': bool(config.LABEL_TOKEN),
        'updated_at': st['updated_at'].strftime('%Y-%m-%d %H:%M:%S') if st.get('updated_at') else None,
    })


@app.route('/api/label_queue')
def api_label_queue():
    """One UNIFORMLY RANDOM unlabelled alert for the analyst to label. The analyst cannot choose which
    alert to label -- random sampling is the assumption behind the recall guarantee."""
    conn = get_conn()
    row = soc_db.get_random_unlabeled_alert(conn)
    conn.close()
    if not row:
        return jsonify({'alert': None})
    row['event_timestamp'] = row['event_timestamp'].strftime('%Y-%m-%d %H:%M:%S')
    row['full_log'] = (row.get('full_log') or '')[:600]
    return jsonify({'alert': row})


@app.route('/api/label', methods=['POST'])
def api_label():
    """Record an analyst label (attack / benign) for an alert and recompute the threshold.
    Requires header X-Label-Token == LABEL_TOKEN (the dashboard is internet-reachable)."""
    if not config.LABEL_TOKEN:
        return jsonify({'error': 'label writes are disabled (LABEL_TOKEN not set)'}), 403
    if not hmac.compare_digest(request.headers.get('X-Label-Token', ''), config.LABEL_TOKEN):
        return jsonify({'error': 'invalid token'}), 403
    body = request.get_json(silent=True) or {}
    if not isinstance(body.get('alert_id'), int) or not isinstance(body.get('is_attack'), bool):
        return jsonify({'error': 'expected {"alert_id": int, "is_attack": bool}'}), 400
    conn = get_conn()
    inserted = soc_db.add_label(conn, body['alert_id'], body['is_attack'], labeled_by='analyst')
    state = soc_db.recalibrate(conn)
    conn.close()
    return jsonify({'inserted': bool(inserted), 'certified': state['certified'],
                    'n_attacks': state['n_attacks'], 'n_labeled': state['n_labeled'],
                    'threshold': state['threshold']})


PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI SOC Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0c0e14; --panel: #14171f; --panel2: #1a1e29; --border: #262b38;
    --teal: #00bfb3; --teal-dim: #0a3a38; --text: #e4e7ee; --muted: #8891a5;
    --red: #f5527c; --orange: #ff9e4a; --yellow: #ffd25a; --green: #3fd68e; --blue: #4ea1ff;
  }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', -apple-system, Arial, sans-serif; background: var(--bg); color: var(--text); margin: 0; font-size: 14px; }
  .shell { display: flex; min-height: 100vh; }

  /* Top global header, Wazuh/OpenSearch-Dashboards style */
  .header { position: fixed; top: 0; left: 0; right: 0; height: 48px; background: #0a0c11; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: 0 16px; z-index: 100; }
  .header-left { display: flex; align-items: center; gap: 10px; }
  .burger { width: 18px; height: 14px; display: flex; flex-direction: column; justify-content: space-between; cursor: pointer; }
  .burger span { height: 2px; background: var(--muted); border-radius: 2px; }
  .logo-mark { width: 26px; height: 26px; border-radius: 6px; background: linear-gradient(135deg, var(--teal), #0a7d76); display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 13px; color: #06231f; }
  .breadcrumb { font-size: 13px; color: var(--muted); display: flex; align-items: center; gap: 6px; }
  .breadcrumb b { color: var(--text); font-weight: 600; }
  .header-right { display: flex; align-items: center; gap: 10px; }
  .time-range { display: flex; align-items: center; gap: 6px; background: var(--panel2); border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; font-size: 12px; color: var(--text); }
  .refresh-btn { background: var(--teal-dim); border: 1px solid var(--teal); color: var(--teal); border-radius: 6px; padding: 6px 10px; font-size: 12px; cursor: pointer; display: flex; align-items: center; gap: 6px; }
  .refresh-btn svg { animation: spin 2.5s linear infinite; }
  @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  .avatar { width: 26px; height: 26px; border-radius: 50%; background: #3a4256; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; color: var(--text); }

  /* Sidebar */
  .sidebar { width: 210px; background: var(--panel); border-right: 1px solid var(--border); padding: 12px 0; flex-shrink: 0; margin-top: 48px; position: fixed; top: 0; bottom: 0; overflow-y: auto; }
  .brand { display: flex; align-items: center; gap: 10px; padding: 8px 20px 16px 20px; border-bottom: 1px solid var(--border); margin-bottom: 8px; }
  .brand .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 8px var(--green); animation: pulse 1.5s infinite; }
  .brand .name { font-weight: 700; font-size: 13px; letter-spacing: 0.02em; }
  .brand .sub { font-size: 10px; color: var(--muted); margin-top: 1px; }
  .nav-section-label { padding: 14px 20px 6px 20px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: #565f75; font-weight: 700; }
  .nav-item { display: flex; align-items: center; gap: 11px; padding: 9px 20px; color: var(--muted); cursor: pointer; font-size: 13px; border-left: 3px solid transparent; }
  .nav-item:hover { color: var(--text); background: var(--panel2); }
  .nav-item.active { color: var(--teal); background: var(--teal-dim); border-left-color: var(--teal); font-weight: 600; }
  .nav-icon { width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .nav-icon svg { width: 16px; height: 16px; }

  /* Main */
  .main { flex: 1; margin-left: 210px; margin-top: 48px; padding: 20px 26px; overflow-x: hidden; }
  .topbar { display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 18px; }
  .topbar h1 { font-size: 19px; margin: 0; }
  .topbar .subtitle { color: var(--muted); font-size: 12px; margin-top: 3px; }
  .live-badge { display: flex; align-items: center; gap: 6px; background: var(--panel2); padding: 6px 12px; border-radius: 999px; font-size: 12px; color: var(--green); border: 1px solid var(--border); }
  .live-badge .pulse { width: 7px; height: 7px; border-radius: 50%; background: var(--green); animation: pulse 1.5s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }

  /* Agent strip */
  .agent-strip { display: flex; gap: 10px; margin-bottom: 18px; flex-wrap: wrap; }
  .agent-card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 10px 14px; display: flex; align-items: center; gap: 10px; min-width: 200px; flex: 1; }
  .agent-dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
  .agent-dot.active { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .agent-dot.idle { background: var(--yellow); }
  .agent-dot.never { background: #4a5266; }
  .agent-name { font-weight: 600; font-size: 13px; }
  .agent-meta { font-size: 11px; color: var(--muted); margin-top: 1px; }

  /* KPI cards */
  .kpi-row { display: grid; grid-template-columns: repeat(6, 1fr); gap: 14px; margin-bottom: 18px; }
  .kpi { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; position: relative; overflow: hidden; }
  .kpi::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--accent, var(--teal)); }
  .kpi-top { display: flex; align-items: center; justify-content: space-between; }
  .kpi .icon { opacity: 0.5; }
  .kpi .num { font-size: 25px; font-weight: 700; line-height: 1; margin-top: 8px; }
  .kpi .label { color: var(--muted); font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 5px; }

  /* Panels */
  .panel-row { display: grid; grid-template-columns: 1.6fr 1fr; gap: 14px; margin-bottom: 14px; }
  .panel-row.thirds { grid-template-columns: 1fr 1fr; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; }
  .panel h2 { font-size: 12.5px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); margin: 0 0 14px 0; display: flex; align-items: center; gap: 6px; }
  .chart-wrap { height: 190px; }
  .chart-wrap.small { height: 160px; }

  /* Table */
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 9px 12px; font-size: 12.5px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); text-transform: uppercase; font-size: 10.5px; letter-spacing: 0.04em; font-weight: 600; position: sticky; top: 0; background: var(--panel); }
  tr:last-child td { border-bottom: none; }
  tr.alert-row:hover, tr.incident-row:hover { background: var(--panel2); }
  .mono { font-family: 'SF Mono', Consolas, monospace; color: var(--muted); }

  .chip { padding: 3px 9px; border-radius: 999px; font-size: 10.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.02em; display: inline-block; }
  .sev-critical { background: rgba(245,82,124,0.15); color: var(--red); }
  .sev-high { background: rgba(255,158,74,0.15); color: var(--orange); }
  .sev-medium { background: rgba(255,210,90,0.15); color: var(--yellow); }
  .sev-low { background: rgba(63,214,142,0.15); color: var(--green); }
  .sev-n\\/a { background: rgba(136,145,165,0.15); color: var(--muted); }
  .status-open { background: rgba(78,161,255,0.15); color: var(--blue); }
  .status-investigating { background: rgba(255,210,90,0.15); color: var(--yellow); }
  .status-resolved, .status-closed { background: rgba(63,214,142,0.15); color: var(--green); }
  .tp-yes { color: var(--red); font-weight: 700; }
  .tp-no { color: var(--muted); }

  .tab-panel { display: none; }
  .tab-panel.active { display: block; }
  .empty { color: var(--muted); padding: 40px; text-align: center; font-size: 13px; }
  .scroll-table { max-height: 420px; overflow-y: auto; }

  /* Horizontal bar list (top rules / top sources) */
  .bar-list { display: flex; flex-direction: column; gap: 10px; }
  .bar-item { }
  .bar-item .bar-label { display: flex; justify-content: space-between; font-size: 11.5px; margin-bottom: 4px; }
  .bar-item .bar-label .name { color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 260px; }
  .bar-item .bar-label .count { color: var(--muted); font-family: monospace; }
  .bar-track { height: 6px; background: var(--panel2); border-radius: 4px; overflow: hidden; }
  .bar-fill { height: 100%; background: linear-gradient(90deg, var(--teal), #4ea1ff); border-radius: 4px; }

  @media (max-width: 900px) {
    .kpi-row { grid-template-columns: repeat(2, 1fr); }
    .panel-row, .panel-row.thirds { grid-template-columns: 1fr; }
    .sidebar { display: none; }
    .main { margin-left: 0; }
  }
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <div class="burger"><span></span><span></span><span></span></div>
    <div class="logo-mark">AI</div>
    <div class="breadcrumb"><b>AI SOC Engine</b> &nbsp;/&nbsp; Threat Hunting &nbsp;/&nbsp; <span id="crumb-tab">Overview</span></div>
  </div>
  <div class="header-right">
    <div class="time-range">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
      Last 24 hours
    </div>
    <div class="refresh-btn" id="refresh-btn">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 3v6h-6"/></svg>
      Live
    </div>
    <div class="avatar">SOC</div>
  </div>
</div>

<div class="shell">
<div class="sidebar">
  <div class="brand">
    <div class="dot"></div>
    <div>
      <div class="name">AI SOC ENGINE</div>
      <div class="sub">Wazuh + ML Decision Layer</div>
    </div>
  </div>
  <div class="nav-section-label">Threat Hunting</div>
  <div class="nav-item active" data-tab="overview" data-label="Overview">
    <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg></span> Overview
  </div>
  <div class="nav-item" data-tab="incidents" data-label="Incidents">
    <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg></span> Incidents
  </div>
  <div class="nav-item" data-tab="alerts" data-label="Alert Stream">
    <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg></span> Alert Stream
  </div>
  <div class="nav-section-label">Model</div>
  <div class="nav-item" data-tab="calibration" data-label="Calibration">
    <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3"/><path d="M1 14h6M9 8h6M17 16h6"/></svg></span> Calibration
  </div>
  <div class="nav-section-label">Infrastructure</div>
  <div class="nav-item" data-tab="agents" data-label="Agents">
    <span class="nav-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg></span> Agents
  </div>
</div>

<div class="main">
  <div class="topbar">
    <div>
      <h1>Security Operations Overview</h1>
      <div class="subtitle">Wazuh alert &rarr; trained model &rarr; database &rarr; incident &rarr; response</div>
    </div>
    <div class="live-badge"><span class="pulse"></span> LIVE</div>
  </div>

  <div class="agent-strip" id="agent-strip"></div>

  <div class="kpi-row">
    <div class="kpi" style="--accent:#4ea1ff"><div class="kpi-top"><span></span></div><div class="num" id="kpi-alerts">-</div><div class="label">Alerts Processed</div></div>
    <div class="kpi" style="--accent:#00bfb3"><div class="num" id="kpi-incidents">-</div><div class="label">Incidents</div></div>
    <div class="kpi" style="--accent:#4ea1ff"><div class="num" id="kpi-open">-</div><div class="label">Open</div></div>
    <div class="kpi" style="--accent:#f5527c"><div class="num" id="kpi-critical">-</div><div class="label">Critical</div></div>
    <div class="kpi" style="--accent:#ff9e4a"><div class="num" id="kpi-calls">-</div><div class="label">Calls Placed</div></div>
    <div class="kpi" style="--accent:#3fd68e"><div class="num" id="kpi-sources">-</div><div class="label">Unique Sources</div></div>
  </div>

  <div class="panel-row">
    <div class="panel">
      <h2>Alert Activity (last 20 min)</h2>
      <div class="chart-wrap"><canvas id="chart-timeseries"></canvas></div>
    </div>
    <div class="panel">
      <h2>Incidents by Severity</h2>
      <div class="chart-wrap"><canvas id="chart-severity"></canvas></div>
    </div>
  </div>

  <div class="panel-row thirds">
    <div class="panel">
      <h2>Top 6 Rules Triggered</h2>
      <div class="bar-list" id="top-rules"></div>
    </div>
    <div class="panel">
      <h2>Top 6 Source IPs</h2>
      <div class="bar-list" id="top-sources"></div>
    </div>
  </div>

  <div id="tab-overview" class="tab-panel active">
    <div class="panel">
      <h2>Recent Incidents</h2>
      <div id="incidents-table"></div>
    </div>
  </div>

  <div id="tab-incidents" class="tab-panel">
    <div class="panel">
      <h2>All Incidents</h2>
      <div class="scroll-table" id="incidents-table-full"></div>
    </div>
  </div>

  <div id="tab-alerts" class="tab-panel">
    <div class="panel">
      <h2>Live Alert Stream (AI-scored)</h2>
      <div class="scroll-table" id="alerts-table"></div>
    </div>
  </div>

  <div id="tab-calibration" class="tab-panel">
    <div class="panel" style="margin-bottom:14px">
      <h2>Threshold calibration (recall guarantee)</h2>
      <div id="calib-status" style="line-height:1.7"></div>
      <div style="color:var(--muted);font-size:12px;margin-top:8px">
        The model's score is only actionable with a calibrated threshold. Label randomly selected alerts below; once enough
        <b>attacks</b> are labelled, the threshold is set so that attack recall is at least the target with the stated confidence
        (valid while labels are correct, were sampled at random, and the alert population does not drift).
      </div>
    </div>
    <div class="panel">
      <h2>Label a random alert</h2>
      <div style="margin-bottom:10px">
        <input id="label-token" type="password" placeholder="label token" style="background:var(--panel2);border:1px solid var(--border);color:var(--text);padding:6px 8px;border-radius:6px;width:220px">
        <span style="color:var(--muted);font-size:12px;margin-left:8px">required to save labels</span>
      </div>
      <div id="label-card"></div>
    </div>
  </div>

  <div id="tab-agents" class="tab-panel">
    <div class="panel">
      <h2>Monitored Assets</h2>
      <div id="agents-table"></div>
    </div>
  </div>
</div>
</div>

<script>
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('tab-' + item.dataset.tab).classList.add('active');
    document.getElementById('crumb-tab').textContent = item.dataset.label;
  });
});

function incidentRows(incidents, limit) {
  if (!incidents.length) return '<div class="empty">No incidents yet -- waiting for alerts.</div>';
  const rows = incidents.slice(0, limit || incidents.length).map(i => `
    <tr class="incident-row">
      <td class="mono">#${i.incident_id}</td>
      <td>${i.title}</td>
      <td><span class="chip sev-${i.severity}">${i.severity}</span></td>
      <td><span class="chip status-${i.status}">${i.status}</span></td>
      <td>${i.hostname}</td>
      <td class="mono">${i.latest_src_ip}</td>
      <td>${i.alert_count}</td>
      <td>${i.actions_summary}</td>
      <td class="mono">${i.updated_at}</td>
    </tr>`).join('');
  return `<table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Asset</th><th>Source IP</th><th>Alerts</th><th>Actions</th><th>Updated</th></tr>${rows}</table>`;
}

function alertRows(alerts) {
  if (!alerts.length) return '<div class="empty">No alerts yet.</div>';
  const rows = alerts.map(a => `
    <tr class="alert-row">
      <td class="mono">${a.received_at}</td>
      <td class="mono">${a.rule_id}</td>
      <td>${a.rule_description || ''}</td>
      <td>${a.rule_level}</td>
      <td class="mono">${a.src_ip}</td>
      <td>${a.hostname}</td>
      <td class="${a.is_true_positive ? 'tp-yes' : 'tp-no'}">${a.is_true_positive ? 'THREAT' : 'benign'}</td>
      <td><span class="chip sev-${a.severity}">${a.severity}</span></td>
    </tr>`).join('');
  return `<table><tr><th>Time</th><th>Rule</th><th>Description</th><th>Level</th><th>Source IP</th><th>Asset</th><th>AI Verdict</th><th>Severity</th></tr>${rows}</table>`;
}

function agentStrip(agents) {
  if (!agents.length) return '<div class="empty">No assets registered.</div>';
  return agents.map(a => `
    <div class="agent-card">
      <span class="agent-dot ${a.status}"></span>
      <div>
        <div class="agent-name">${a.hostname}</div>
        <div class="agent-meta">${a.ip_address || 'n/a'} &middot; ${a.alert_count} alerts &middot; last seen ${a.last_seen}</div>
      </div>
    </div>`).join('');
}

function agentTable(agents) {
  if (!agents.length) return '<div class="empty">No assets registered.</div>';
  const rows = agents.map(a => `
    <tr class="incident-row">
      <td><span class="agent-dot ${a.status}" style="display:inline-block;margin-right:8px;"></span>${a.hostname}</td>
      <td class="mono">${a.ip_address || 'n/a'}</td>
      <td>${a.asset_type}</td>
      <td><span class="chip sev-${a.criticality}">${a.criticality}</span></td>
      <td>${a.alert_count}</td>
      <td class="mono">${a.last_seen}</td>
      <td>${a.status}</td>
    </tr>`).join('');
  return `<table><tr><th>Hostname</th><th>IP Address</th><th>Type</th><th>Criticality</th><th>Alerts</th><th>Last Seen</th><th>Status</th></tr>${rows}</table>`;
}

function barList(items, elId) {
  const el = document.getElementById(elId);
  if (!items.length) { el.innerHTML = '<div class="empty">No data yet.</div>'; return; }
  const max = Math.max(...items.map(i => i.n));
  el.innerHTML = items.map(i => `
    <div class="bar-item">
      <div class="bar-label"><span class="name">${i.label}</span><span class="count">${i.n}</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${(i.n / max * 100).toFixed(0)}%"></div></div>
    </div>`).join('');
}

let tsChart, sevChart;

function initCharts() {
  const tsCtx = document.getElementById('chart-timeseries').getContext('2d');
  tsChart = new Chart(tsCtx, {
    type: 'line',
    data: { labels: [], datasets: [{ data: [], borderColor: '#00bfb3', backgroundColor: 'rgba(0,191,179,0.12)', fill: true, tension: 0.3, pointRadius: 2 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8891a5', font: { size: 10 } }, grid: { color: '#262b38' } },
        y: { ticks: { color: '#8891a5', font: { size: 10 } }, grid: { color: '#262b38' }, beginAtZero: true }
      }
    }
  });

  const sevCtx = document.getElementById('chart-severity').getContext('2d');
  sevChart = new Chart(sevCtx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{ data: [0,0,0,0], backgroundColor: ['#f5527c', '#ff9e4a', '#ffd25a', '#3fd68e'], borderColor: '#14171f', borderWidth: 2 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#8891a5', font: { size: 10 }, boxWidth: 10, padding: 10 } } }
    }
  });
}

async function refresh() {
  try {
    const [stats, incidents, alerts, agents, topRules, topSources] = await Promise.all([
      fetch('/api/stats').then(r => r.json()),
      fetch('/api/incidents').then(r => r.json()),
      fetch('/api/recent_alerts').then(r => r.json()),
      fetch('/api/agents').then(r => r.json()),
      fetch('/api/top_rules').then(r => r.json()),
      fetch('/api/top_sources').then(r => r.json()),
    ]);

    document.getElementById('kpi-alerts').textContent = stats.total_alerts;
    document.getElementById('kpi-incidents').textContent = stats.total_incidents;
    document.getElementById('kpi-open').textContent = stats.open_incidents;
    document.getElementById('kpi-critical').textContent = stats.severity_counts.critical;
    document.getElementById('kpi-calls').textContent = stats.calls_made;
    document.getElementById('kpi-sources').textContent = stats.unique_sources;

    tsChart.data.labels = stats.timeseries.map(p => p.t);
    tsChart.data.datasets[0].data = stats.timeseries.map(p => p.n);
    tsChart.update('none');

    sevChart.data.datasets[0].data = [
      stats.severity_counts.critical, stats.severity_counts.high,
      stats.severity_counts.medium, stats.severity_counts.low
    ];
    sevChart.update('none');

    document.getElementById('incidents-table').innerHTML = incidentRows(incidents, 8);
    document.getElementById('incidents-table-full').innerHTML = incidentRows(incidents);
    document.getElementById('alerts-table').innerHTML = alertRows(alerts);
    document.getElementById('agent-strip').innerHTML = agentStrip(agents);
    document.getElementById('agents-table').innerHTML = agentTable(agents);
    barList(topRules, 'top-rules');
    barList(topSources, 'top-sources');
  } catch (e) {
    console.error('refresh failed', e);
  }
}

function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

let currentLabelAlert = null;
async function loadCalibration() {
  try {
    const c = await fetch('/api/calibration').then(r => r.json());
    const badge = c.certified
      ? `<span class="chip sev-low">CALIBRATED</span> threshold <b>${Number(c.threshold).toFixed(4)}</b> &mdash; attack recall &ge; ${c.rho} with probability &ge; ${(1 - c.delta).toFixed(2)}`
      : `<span class="chip sev-high">UNCALIBRATED</span> using default threshold ${c.default_threshold} (no recall guarantee)`;
    document.getElementById('calib-status').innerHTML =
      `${badge}<br>Labelled alerts: <b>${c.n_labeled}</b> &middot; labelled attacks: <b>${c.n_attacks}</b> / ${c.attacks_needed} needed ` +
      `&middot; model <span class="mono">${esc(c.model_version)}</span>` +
      (c.labels_enabled ? '' : '<br><span style="color:var(--orange)">Label writes are disabled on this server (LABEL_TOKEN not set).</span>');
  } catch (e) { console.error(e); }
}

async function nextLabelAlert() {
  const r = await fetch('/api/label_queue').then(r => r.json());
  currentLabelAlert = r.alert;
  const el = document.getElementById('label-card');
  if (!r.alert) { el.innerHTML = '<div class="empty">No unlabelled alerts available.</div>'; return; }
  const a = r.alert;
  el.innerHTML = `
    <table>
      <tr><th>Time</th><td class="mono">${esc(a.event_timestamp)}</td></tr>
      <tr><th>Rule</th><td>${esc(a.rule_id)} &mdash; ${esc(a.rule_description)} (level ${esc(a.rule_level)})</td></tr>
      <tr><th>Source</th><td class="mono">${esc(a.src_ip)}</td></tr>
      <tr><th>Log</th><td class="mono" style="white-space:pre-wrap;word-break:break-all">${esc(a.full_log)}</td></tr>
    </table>
    <div style="margin-top:12px;display:flex;gap:10px;align-items:center">
      <button class="refresh-btn" style="border-color:var(--red);color:var(--red);background:transparent" onclick="submitLabel(true)">Real attack</button>
      <button class="refresh-btn" style="border-color:var(--green);color:var(--green);background:transparent" onclick="submitLabel(false)">Benign / routine</button>
      <span id="label-msg" style="color:var(--muted);font-size:12px"></span>
    </div>`;
}

async function submitLabel(isAttack) {
  const token = document.getElementById('label-token').value;
  const msg = document.getElementById('label-msg');
  if (!currentLabelAlert) return;
  const res = await fetch('/api/label', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Label-Token': token },
    body: JSON.stringify({ alert_id: currentLabelAlert.alert_id, is_attack: isAttack }) });
  const j = await res.json();
  if (!res.ok) { msg.textContent = j.error || 'failed'; msg.style.color = 'var(--red)'; return; }
  await loadCalibration();
  await nextLabelAlert();
}

document.querySelector('[data-tab="calibration"]').addEventListener('click', () => { loadCalibration(); nextLabelAlert(); });

initCharts();
refresh();
setInterval(refresh, 4000);
</script>
</body>
</html>
"""


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
