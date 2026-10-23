const fs = require('fs');

const raw = fs.readFileSync('alerts_export5.json', 'utf8');
const lines = raw.split('\n').filter(l => l.trim().length > 0);

const WINDOWS = [
  [new Date('2026-09-14T10:43:00Z'), new Date('2026-09-14T11:05:00Z')], // round 1
  [new Date('2026-09-14T11:19:00Z'), new Date('2026-09-14T11:28:00Z')], // round 2
  [new Date('2026-09-14T11:43:00Z'), new Date('2026-09-14T11:46:00Z')], // round 3
  [new Date('2026-09-14T12:54:00Z'), new Date('2026-09-14T13:00:00Z')], // round 4 (real tools) + benign padding
];

function inWindow(t) {
  return WINDOWS.some(([s, e]) => t >= s && t <= e);
}

let allRecords = [];
for (const line of lines) {
  try {
    const obj = JSON.parse(line);
    if (obj.agent && obj.agent.name === 'soc-target') allRecords.push(obj);
  } catch (e) {}
}

let records = allRecords.filter(r => inWindow(new Date(r.timestamp)));
console.log('Total soc-target alerts (all time):', allRecords.length);
console.log('Alerts within scenario windows (pre-downsample):', records.length);

const DECOY_ACCOUNTS = ['svc_backup', 'svc_reports'];

function classify(r) {
  const desc = (r.rule && r.rule.description || '').toLowerCase();
  const groups = (r.rule && r.rule.groups || []).join(',').toLowerCase();
  const fullLog = (r.full_log || '').toLowerCase();
  const level = r.rule ? Number(r.rule.level) : 0;
  const ruleId = r.rule ? String(r.rule.id) : '';

  let category = 'other';
  let isTruePositive = false;

  // --- Native Wazuh correlation rules (round 4 - real tool traffic) ---
  if (ruleId === '40112' || desc.includes('multiple authentication failures followed by a success')) {
    category = 'ssh_bruteforce_success_correlated'; // Wazuh's OWN correlation engine caught this
    isTruePositive = true;
  } else if (['5763', '40111', '5551', '5758'].includes(ruleId) || desc.includes('brute force') || desc.includes('multiple authentication failures') || desc.includes('multiple failed logins')) {
    category = 'ssh_bruteforce_correlated';
    isTruePositive = true;
  } else if (['31151', '31516'].includes(ruleId) || groups.includes('recon') || groups.includes('web_scan') || desc.includes('suspicious url')) {
    category = 'web_recon_scanning'; // native Wazuh recon/scan detection
    isTruePositive = true;
  } else if (['31166', '31168'].includes(ruleId) || desc.includes('shellshock')) {
    category = 'web_attack_shellshock';
    isTruePositive = true;
  } else if (['31171', '31103'].includes(ruleId) || groups.includes('sql_injection') || groups.includes('sqlinjection') || desc.includes('sql injection')) {
    category = 'web_attack_sqli';
    isTruePositive = true;
  } else if (['31105', '31154'].includes(ruleId) || groups.includes('xss')) {
    category = 'web_attack_xss';
    isTruePositive = true;
  } else if (ruleId === '31153' || desc.includes('multiple common web attacks')) {
    category = 'web_attack_chain_correlated'; // Wazuh's own attack-chain aggregation
    isTruePositive = true;
  } else if (ruleId === '100102' || groups.includes('ssti') || groups.includes('rce')) {
    category = 'web_attack_ssti_rce';
    isTruePositive = true;
  } else if (ruleId === '100100' || groups.includes('command_injection')) {
    category = 'web_attack_command_injection';
    isTruePositive = true;
  } else if (['31104', '31106', '31110'].includes(ruleId) || desc.includes('common web attack') || desc.includes('php cgi-bin')) {
    category = 'web_attack_generic';
    isTruePositive = true;
  } else if (ruleId === '31101' || desc.includes('web server 400 error code')) {
    category = 'web_scan_noise_400'; // high-volume, mostly automated scanner noise
    isTruePositive = false; // a single 404 alone is low-value noise; the *pattern* (31151/31153) is what matters
  }
  // --- Round 2/3 categories ---
  else if (DECOY_ACCOUNTS.some(u => fullLog.includes(u)) && desc.includes('authentication success')) {
    category = 'ssh_bruteforce_success';
    isTruePositive = true;
  } else if (DECOY_ACCOUNTS.some(u => fullLog.includes(u)) && (desc.includes('authentication failed') || desc.includes('failed password'))) {
    category = 'ssh_bruteforce_wrong_password';
    isTruePositive = true;
  } else if (desc.includes('file added') && fullLog.includes('authorized_keys')) {
    category = 'persistence_ssh_key';
    isTruePositive = true;
  } else if (desc.includes('integrity checksum changed') && fullLog.includes('authorized_keys')) {
    category = 'persistence_ssh_key';
    isTruePositive = true;
  } else if (desc.includes('file added') && fullLog.includes('.bash_history') && fullLog.includes('testuser')) {
    category = 'anti_forensics_log_tampering';
    isTruePositive = true;
  } else if (groups.includes('sudo') && fullLog.includes('testuser :')) {
    category = 'privilege_escalation_success';
    isTruePositive = true;
  } else if (fullLog.includes('written permissions to anyone') || desc.includes('world-writable')) {
    category = 'insecure_file_permissions';
    isTruePositive = true;
  }
  // --- Round 1 categories ---
  else if (desc.includes('non-existent user') || desc.includes('invalid user') || fullLog.includes('invalid user')) {
    category = 'ssh_bruteforce_invalid_user';
    isTruePositive = true;
  } else if (groups.includes('sshd') && (groups.includes('authentication_failed') || desc.includes('failed password'))) {
    category = 'ssh_bruteforce_wrong_password';
    isTruePositive = true;
  } else if (groups.includes('sshd') && desc.includes('connection reset')) {
    category = 'ssh_bruteforce_wrong_password';
    isTruePositive = true;
  } else if (groups.includes('sshd') && groups.includes('authentication_success')) {
    category = 'benign_ssh_login';
    isTruePositive = false;
  } else if (desc.includes('successful sudo') || desc.includes('first time user executed sudo')) {
    category = 'benign_sudo';
    isTruePositive = false;
  } else if (groups.includes('sudo') && (groups.includes('authentication_failed') || fullLog.includes('incorrect password'))) {
    category = 'privilege_escalation_attempt';
    isTruePositive = true;
  } else if (groups.includes('web') || groups.includes('accesslog')) {
    category = 'benign_web_request';
    isTruePositive = false;
  } else if (desc.includes('login session opened') || desc.includes('login session closed')) {
    category = 'benign_login_session';
    isTruePositive = false;
  } else if (desc.includes('file added') || desc.includes('file deleted') || groups.includes('syscheck')) {
    category = 'file_integrity_change';
    isTruePositive = level >= 5;
  } else if (groups.includes('rootcheck') || desc.includes('anomaly detection')) {
    category = 'host_anomaly';
    isTruePositive = true;
  } else if (desc.includes('listened ports') || desc.includes('port opened')) {
    category = 'network_change';
    isTruePositive = true;
  } else if (desc.includes('new user added') || desc.includes('new group added')) {
    category = 'system_account_change';
    isTruePositive = true;
  } else if (desc.includes('log file rotated') || groups.includes('dpkg') || desc.includes('agent started') || desc.includes('agent stopped') || desc.includes('password changed')) {
    category = 'benign_system_noise';
    isTruePositive = false;
  } else if (groups.includes('journald')) {
    category = 'benign_system_noise';
    isTruePositive = false;
  } else if (groups.includes('agent_flooding')) {
    category = 'benign_system_noise';
    isTruePositive = false;
  } else {
    category = 'other';
    isTruePositive = level >= 7;
  }

  let severityLabel = 'low';
  if (level >= 12) severityLabel = 'critical';
  else if (level >= 9) severityLabel = 'high';
  else if (level >= 5) severityLabel = 'medium';

  const forceCritical = [
    'ssh_bruteforce_success', 'ssh_bruteforce_success_correlated', 'persistence_ssh_key',
    'privilege_escalation_success', 'web_attack_command_injection', 'web_attack_ssti_rce',
    'web_attack_xss', 'web_attack_shellshock', 'web_attack_chain_correlated'
  ];
  if (forceCritical.includes(category)) severityLabel = 'critical';

  let priority = 1;
  if (isTruePositive) {
    if (severityLabel === 'critical') priority = 5;
    else if (severityLabel === 'high') priority = 4;
    else if (severityLabel === 'medium') priority = 3;
    else priority = 2;
  }

  return { category, isTruePositive, severityLabel, priority };
}

// Apply a general per-category cap so no single high-volume category (mostly automated
// scanner noise from nikto/gobuster) drowns out the rarer, higher-value categories.
// True raw volume per category is documented in the README; this is a representative sample.
const CATEGORY_CAP = 120;
const seenCount = {};
const finalRecords = [];
for (const r of records) {
  const cls = classify(r);
  seenCount[cls.category] = (seenCount[cls.category] || 0) + 1;
  if (seenCount[cls.category] > CATEGORY_CAP) continue;
  finalRecords.push(r);
}
records = finalRecords;
console.log('Alerts after per-category capping (max', CATEGORY_CAP, 'each):', records.length);

function csvEscape(s) {
  if (s === null || s === undefined) return '';
  s = String(s).replace(/"/g, '""').replace(/\r?\n/g, ' ');
  return `"${s}"`;
}

const rows = [];
const header = [
  'alert_id', 'timestamp', 'agent_name', 'rule_id', 'rule_level', 'rule_description',
  'rule_groups', 'mitre_id', 'mitre_tactic', 'mitre_technique', 'decoder', 'src_ip',
  'full_log', 'attack_category', 'is_true_positive', 'severity', 'priority'
];
rows.push(header.join(','));
const jsonlOut = [];

for (const r of records) {
  const cls = classify(r);
  const mitre = (r.rule && r.rule.mitre) || {};
  const srcip = (r.data && r.data.srcip) || '';
  const row = [
    r.id || '', r.timestamp || '', (r.agent && r.agent.name) || '',
    (r.rule && r.rule.id) || '', (r.rule && r.rule.level) || '', (r.rule && r.rule.description) || '',
    ((r.rule && r.rule.groups) || []).join('|'), (mitre.id || []).join('|'),
    (mitre.tactic || []).join('|'), (mitre.technique || []).join('|'),
    (r.decoder && r.decoder.name) || '', srcip, (r.full_log || '').slice(0, 300),
    cls.category, cls.isTruePositive, cls.severityLabel, cls.priority
  ].map(csvEscape);
  rows.push(row.join(','));

  jsonlOut.push(JSON.stringify({
    alert_id: r.id, timestamp: r.timestamp, agent_name: r.agent && r.agent.name,
    rule: r.rule, decoder: r.decoder, data: r.data, full_log: r.full_log, location: r.location,
    labels: {
      attack_category: cls.category, is_true_positive: cls.isTruePositive,
      severity: cls.severityLabel, priority: cls.priority
    }
  }));
}

fs.writeFileSync('wazuh_soc_dataset.csv', rows.join('\n'), 'utf8');
fs.writeFileSync('wazuh_soc_dataset.jsonl', jsonlOut.join('\n'), 'utf8');

const catCounts = {};
const tpCount = { true: 0, false: 0 };
const sevCounts = {};
for (const r of records) {
  const cls = classify(r);
  catCounts[cls.category] = (catCounts[cls.category] || 0) + 1;
  tpCount[cls.isTruePositive] = (tpCount[cls.isTruePositive] || 0) + 1;
  sevCounts[cls.severityLabel] = (sevCounts[cls.severityLabel] || 0) + 1;
}
console.log('\n--- Category breakdown ---');
for (const [k, v] of Object.entries(catCounts).sort((a,b)=>b[1]-a[1])) console.log(k, ':', v);
console.log('\n--- Severity breakdown ---');
for (const [k, v] of Object.entries(sevCounts).sort((a,b)=>b[1]-a[1])) console.log(k, ':', v);
console.log('\n--- TP/FP breakdown ---');
console.log('True Positive (real security event):', tpCount.true);
console.log('False Positive / benign:', tpCount.false);
console.log('\nWrote', records.length, 'rows to wazuh_soc_dataset.csv and .jsonl');
