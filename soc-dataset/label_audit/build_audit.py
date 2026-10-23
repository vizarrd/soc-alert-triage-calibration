"""Builds a BLIND label-audit tool: a random stratified sample of alerts shown WITHOUT our labels so
a human can label them independently. Produces
  audit_tool.html            -- self-contained, offline; give this to the annotator
  private_key/audit_key.json -- our labels/strata for scoring; the annotator must NOT see this

Strata (seed 1): 16 round-4 attack-labelled, 20 round-4 scanner-noise (labelled benign by us), all 16
other round-4 benign, 12 public AIT-ADS alerts (6 inside / 6 outside attack windows), plus 6 repeated
items (to measure the annotator's own consistency). Items are shuffled and shown as 'Alert i of N'.
Questions per alert:
  Q1 (fact)   Does this log line show malicious or unauthorized activity (incl. automated scanning / attack tools)?  yes / no / unsure
  Q2 (policy) Should this alert be sent to a human analyst?  yes / no"""
import json, random
import pandas as pd

rng = random.Random(1)
df = pd.read_csv('../wazuh_soc_dataset.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
r4 = df[df['timestamp'] >= pd.Timestamp('2026-09-14 12:00:00', tz='UTC')].dropna(subset=['is_true_positive']).reset_index(drop=True)
ait = pd.read_csv('../external_data/ait_ads/ait_sample.csv', keep_default_na=False)
ait['is_true_positive'] = ait['is_true_positive'].astype(str).str.lower().eq('true')

def pick(frame, n):
    idx = list(frame.index); rng.shuffle(idx); return frame.loc[idx[:n]]

attack = pick(r4[r4.is_true_positive == True], 16)
scan = pick(r4[(r4.is_true_positive == False) & (r4.attack_category == 'web_scan_noise_400')], 20)
other = r4[(r4.is_true_positive == False) & (r4.attack_category != 'web_scan_noise_400')]
ait_in, ait_out = pick(ait[ait.is_true_positive], 6), pick(ait[~ait.is_true_positive], 6)

def item(row, stratum, ours):
    return {'rule_level': str(row['rule_level']), 'rule_description': str(row['rule_description']),
            'decoder': str(row['decoder']), 'full_log': str(row['full_log'])[:600], '_stratum': stratum, '_ours': bool(ours), '_repeat_of': None}

items = ([item(r, 'r4_attack', True) for _, r in attack.iterrows()] +
         [item(r, 'r4_scanner_noise', False) for _, r in scan.iterrows()] +
         [item(r, 'r4_other_benign', False) for _, r in other.iterrows()] +
         [item(r, 'ait_in_window', True) for _, r in ait_in.iterrows()] +
         [item(r, 'ait_outside_window', False) for _, r in ait_out.iterrows()])
repeats = rng.sample(items, 6)
items += [dict(x) for x in repeats]
for i, x in enumerate(items): x['_id'] = i
# mark repeats: the last 6 are duplicates of earlier items
for k, x in enumerate(items[-6:]):
    src = repeats[k]; x['_repeat_of'] = [j for j, y in enumerate(items[:-6]) if y is src][0]
rng.shuffle(items)
order = {x['_id']: n for n, x in enumerate(items)}   # display position

public = [{'id': x['_id'], 'rule_level': x['rule_level'], 'rule_description': x['rule_description'],
           'decoder': x['decoder'], 'full_log': x['full_log']} for x in items]
key = [{'id': x['_id'], 'stratum': x['_stratum'], 'ours_attack': x['_ours'], 'repeat_of': x['_repeat_of']} for x in items]
import os
os.makedirs('private_key', exist_ok=True)
json.dump(key, open('private_key/audit_key.json', 'w'), indent=1)

HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Alert label audit</title>
<style>
:root{--bg:#0f1117;--panel:#171a23;--line:#2a2f3d;--text:#e6e8ee;--muted:#8b93a7;--teal:#00bfb3;--red:#f5527c;--green:#3fd68e;--amber:#ffb454}
@media (prefers-color-scheme: light){:root{--bg:#f6f7fb;--panel:#fff;--line:#dfe3ec;--text:#1b2030;--muted:#5d667c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:20px 16px 60px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--muted);font-size:13px;margin-bottom:14px}
.bar{height:6px;background:var(--line);border-radius:4px;margin:10px 0 18px}.bar>div{height:100%;background:var(--teal);border-radius:4px;width:0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.row{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0}.k{color:var(--muted);min-width:110px;font-size:13px}
pre{white-space:pre-wrap;word-break:break-all;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;font:13px/1.45 ui-monospace,Consolas,monospace;margin:8px 0}
.q{margin:16px 0 6px;font-weight:600}.hint{color:var(--muted);font-size:12.5px;margin:-2px 0 8px}
button{font:inherit;border:1px solid var(--line);background:var(--panel);color:var(--text);padding:9px 16px;border-radius:8px;cursor:pointer}
button.sel{border-color:var(--teal);box-shadow:0 0 0 2px rgba(0,191,179,.25)}button.primary{background:var(--teal);color:#05201e;border-color:var(--teal);font-weight:600}
button:disabled{opacity:.4;cursor:not-allowed}.nav{display:flex;justify-content:space-between;margin-top:18px;gap:10px;flex-wrap:wrap}
.guide{font-size:13px;color:var(--muted);margin-bottom:14px}.guide b{color:var(--text)}.small{font-size:12px;color:var(--muted)}
</style></head><body><div class="wrap">
<h1>Alert label audit</h1>
<div class="sub">Label each alert on your own judgement. You are not shown any earlier labels. Takes about 15-20 minutes; progress is saved in this browser; you can stop and resume.</div>
<div class="guide"><b>Q1 (fact):</b> does this log line show malicious or unauthorized activity, including automated scanning or attack tools? Answer from the log alone.<br>
<b>Q2 (policy):</b> in a real SOC, should this alert be escalated to a human analyst? These two can differ (e.g. real but low-value scanner noise).</div>
<div class="bar"><div id="prog"></div></div>
<div class="card" id="card"></div>
<div class="nav"><button id="prev">&larr; Back</button><span class="small" id="count"></span><button id="next" class="primary">Next &rarr;</button></div>
<div class="nav"><button id="export">Download my labels (.json)</button><span class="small">Send the downloaded file back; you can download at any time.</span></div>
</div>
<script>
const ITEMS = __ITEMS__;
const KEY = 'alert-label-audit-v1';
let ans = {}; try { ans = JSON.parse(localStorage.getItem(KEY) || '{}'); } catch(e) {}
let i = 0;
const esc = s => String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function save(){ try{ localStorage.setItem(KEY, JSON.stringify(ans)); }catch(e){} }
function firstOpen(){ const n = ITEMS.findIndex(x => !(ans[x.id] && ans[x.id].q1 && ans[x.id].q2)); return n < 0 ? 0 : n; }
function render(){
  const it = ITEMS[i], a = ans[it.id] || {};
  const done = ITEMS.filter(x => ans[x.id] && ans[x.id].q1 && ans[x.id].q2).length;
  document.getElementById('prog').style.width = (100*done/ITEMS.length)+'%';
  document.getElementById('count').textContent = `Alert ${i+1} of ${ITEMS.length} · ${done} answered`;
  const btn = (q,v,l) => `<button data-q="${q}" data-v="${v}" class="${a[q]===v?'sel':''}">${l}</button>`;
  document.getElementById('card').innerHTML = `
    <div class="row"><span class="k">Rule level</span><span>${esc(it.rule_level)}</span></div>
    <div class="row"><span class="k">Rule description</span><span>${esc(it.rule_description)}</span></div>
    <div class="row"><span class="k">Decoder</span><span>${esc(it.decoder)}</span></div>
    <pre>${esc(it.full_log)}</pre>
    <div class="q">Q1. Malicious or unauthorized activity (including automated scanning / attack tools)?</div>
    <div class="row">${btn('q1','yes','Yes')}${btn('q1','no','No')}${btn('q1','unsure','Unsure')}</div>
    <div class="q">Q2. Should this alert be escalated to a human analyst?</div>
    <div class="row">${btn('q2','yes','Yes')}${btn('q2','no','No')}</div>`;
  document.querySelectorAll('#card button').forEach(b => b.onclick = () => {
    ans[it.id] = Object.assign(ans[it.id] || {}, {[b.dataset.q]: b.dataset.v}); save(); render(); });
  document.getElementById('prev').disabled = i === 0;
  document.getElementById('next').disabled = i === ITEMS.length-1;
}
document.getElementById('prev').onclick = () => { if (i>0){ i--; render(); } };
document.getElementById('next').onclick = () => { if (i<ITEMS.length-1){ i++; render(); } };
document.addEventListener('keydown', e => {
  if (e.key==='ArrowRight') document.getElementById('next').click();
  if (e.key==='ArrowLeft') document.getElementById('prev').click();
});
document.getElementById('export').onclick = () => {
  const out = ITEMS.map(x => ({id:x.id, q1:(ans[x.id]||{}).q1||null, q2:(ans[x.id]||{}).q2||null}));
  const blob = new Blob([JSON.stringify(out,null,1)], {type:'application/json'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'my_labels.json'; a.click();
};
i = firstOpen(); render();
</script></body></html>"""
open('audit_tool.html', 'w', encoding='utf-8').write(HTML.replace('__ITEMS__', json.dumps(public)))
print(len(public), 'items;', 'strata:', pd.Series([k['stratum'] for k in key]).value_counts().to_dict())
