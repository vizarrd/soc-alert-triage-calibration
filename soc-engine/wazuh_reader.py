"""Reads Wazuh's own alerts.json (one JSON object per line) and normalizes each alert into
the flat shape the rest of the engine (models.py, db.py) expects. Two modes:
 - read_existing(path): parse a whole file at once (batch / backfill / testing)
 - follow(path): tail -f style generator for live processing
"""
import json
import time


def _parse_line(line):
    line = line.strip()
    if not line:
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None

    rule = raw.get('rule', {}) or {}
    agent = raw.get('agent', {}) or {}
    data = raw.get('data', {}) or {}
    mitre = rule.get('mitre', {}) or {}

    return {
        'wazuh_alert_uid': raw.get('id'),
        'agent_id': agent.get('id', '000'),
        'agent_name': agent.get('name', 'unknown'),
        'agent_ip': agent.get('ip'),
        'event_timestamp': raw.get('timestamp'),
        'rule_id': str(rule.get('id', '')),
        'rule_level': int(rule.get('level', 0)),
        'rule_description': rule.get('description'),
        'rule_groups': '|'.join(rule.get('groups', []) or []),
        'mitre_id': '|'.join(mitre.get('id', []) or []) if isinstance(mitre.get('id'), list) else mitre.get('id'),
        'mitre_tactic': '|'.join(mitre.get('tactic', []) or []) if isinstance(mitre.get('tactic'), list) else mitre.get('tactic'),
        'mitre_technique': '|'.join(mitre.get('technique', []) or []) if isinstance(mitre.get('technique'), list) else mitre.get('technique'),
        'decoder': (raw.get('decoder', {}) or {}).get('name'),
        'src_ip': data.get('srcip'),
        'full_log': raw.get('full_log', ''),
        'full_raw': raw,
    }


def read_existing(path):
    """Parse every alert currently in the file. Returns a list of normalized dicts."""
    alerts = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            parsed = _parse_line(line)
            if parsed:
                alerts.append(parsed)
    return alerts


def follow(path, poll_interval=2):
    """Generator: yields new normalized alerts as they're appended to the file (tail -f style).
    Starts from the current end of file -- doesn't replay history."""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(0, 2)  # seek to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            parsed = _parse_line(line)
            if parsed:
                yield parsed
