const $ = id => document.getElementById(id);
const rank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const state = { findings: [], reports: [], events: [], aiAnalysis: null, reviews: {}, selected: null, selectedKeys: new Set(), activePane: 'summary', templates: [], lastStatusSignature: '', refreshTimer: null, eventSource: null, reportFindingKey: '' };

function esc(value){ const d=document.createElement('div'); d.textContent=value ?? ''; return d.innerHTML; }
function isURL(value){ return /^https?:\/\//i.test(value || ''); }
function link(value){ return isURL(value) ? `<a class="link" href="${esc(value)}" target="_blank" rel="noreferrer">${esc(value)}</a>` : esc(value); }
function toast(message){ $('toast').textContent=message; $('toast').classList.remove('hide'); setTimeout(()=>$('toast').classList.add('hide'), 2200); }
function reviewKey(f){ return f.finding_id || f.fingerprint || `${f.template_id}|${f.matched_url}|${f.name}`; }
function reviewOf(f){ return state.reviews[reviewKey(f)] || {}; }
function targetList(){ return [$('target').value, $('targetList').value].join('\n').split(/[\n,;]/).map(x=>x.trim()).filter(Boolean); }
function visibleFindings(){ return filteredFindings(); }

const views = {
  overview: ['Overview','Command center for scan status, triage, and reports.'],
  scan: ['Scan setup','Targets, profile, authorization, and scan policy.'],
  findings: ['Findings','Analyst queue with evidence, triage state, notes, and exports.'],
  reporting: ['Reports','HackerOne-style and Bugcrowd-style disclosure report builder.'],
  history: ['History','Recent scan runs and generated report artifacts.'],
  templates: ['Template inventory','Template health, severity, tags, CWE/CVE, and validation state.'],
  config: ['Runtime config','Current scanner configuration loaded by the GUI.']
};

function activateView(id){
  if(!views[id]) id='overview';
  document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active', v.id===id));
  document.querySelectorAll('.nav button').forEach(b=>b.classList.toggle('active', b.dataset.view===id));
  $('viewTitle').textContent = views[id][0];
  $('viewSubtitle').textContent = views[id][1];
  localStorage.setItem('neoscanner.appView', id);
}

function metrics(){
  const counts={critical:0,high:0,medium:0,low:0,info:0};
  state.findings.forEach(f=>counts[f.severity]=(counts[f.severity]||0)+1);
  $('metrics').innerHTML = [['Findings',state.findings.length,''],['Critical',counts.critical,'critical'],['High',counts.high,'high'],['Medium',counts.medium,'medium'],['Low',counts.low,'low'],['Info',counts.info,'info']]
    .map(([label,count,sev])=>`<div class="metric" data-severity="${sev}"><b>${count}</b><span class="muted">${label}</span></div>`).join('');
  document.querySelectorAll('#metrics .metric').forEach(card=>card.onclick=()=>{ if(card.dataset.severity){ $('severityFilter').value=card.dataset.severity; activateView('findings'); renderFindings(); }});
}

function reviewMetrics(){
  const counts={unreviewed:0,reviewed:0,false_positive:0};
  state.findings.forEach(f=>counts[reviewOf(f).status || 'unreviewed']++);
  $('reviewMetrics').innerHTML = [['Unreviewed',counts.unreviewed,'unreviewed'],['Reviewed',counts.reviewed,'reviewed'],['False positives',counts.false_positive,'false_positive']]
    .map(([label,count,status])=>`<div class="metric" data-review="${status}"><b>${count}</b><span class="muted">${label}</span></div>`).join('');
  document.querySelectorAll('#reviewMetrics .metric').forEach(card=>card.onclick=()=>{ $('reviewFilter').value=card.dataset.review; activateView('findings'); renderFindings(); });
}

function renderAI(){
  const ai=state.aiAnalysis;
  if(!ai){ $('aiSummary').innerHTML='<div class="empty">Enable AI analysis in Scan setup to generate an analyst summary after a scan.</div>'; return; }
  const priorities=(ai.priority_findings||[]).map(x=>`<li>${esc(x)}</li>`).join('');
  const steps=(ai.recommended_steps||[]).map(x=>`<li>${esc(x)}</li>`).join('');
  const notes=(ai.notes||[]).map(x=>`<li>${esc(x)}</li>`).join('');
  $('aiSummary').innerHTML=`<p><b>${esc(ai.risk_level||'unknown')} risk</b> via ${esc(ai.provider||'local')}${ai.model?' / '+esc(ai.model):''}</p><p>${esc(ai.executive_summary||'No summary returned.')}</p>${priorities?'<h3>Priorities</h3><ul>'+priorities+'</ul>':''}${steps?'<h3>Next steps</h3><ul>'+steps+'</ul>':''}${notes?'<h3>Notes</h3><ul>'+notes+'</ul>':''}${ai.error?'<p class="warning">'+esc(ai.error)+'</p>':''}`;
}

function filteredFindings(){
  const q=$('search').value.toLowerCase(), sev=$('severityFilter').value, con=$('confidenceFilter').value, review=$('reviewFilter').value, sort=$('sort').value;
  return state.findings.filter(f=>{
    const r=reviewOf(f), status=r.status || 'unreviewed', hasNotes=!!(r.notes||'').trim();
    const text=[f.name,f.template_id,f.matched_url,f.parameter,(f.cwe||[]).join(' '),(f.cves||[]).join(' '),(f.evidence||[]).join(' '),r.notes||''].join(' ').toLowerCase();
    const reviewMatch=!review || status===review || (review==='has_notes'&&hasNotes) || (review==='missing_notes'&&!hasNotes);
    return (!q||text.includes(q)) && (!sev||f.severity===sev) && (!con||f.confidence===con) && reviewMatch;
  }).sort((a,b)=>sort==='name'?a.name.localeCompare(b.name):sort==='url'?(a.matched_url||'').localeCompare(b.matched_url||''):(rank[b.severity]||0)-(rank[a.severity]||0)||a.name.localeCompare(b.name));
}

function renderFindings(){
  const list=filteredFindings();
  $('count').textContent = `${list.length} of ${state.findings.length} findings`;
  $('selectedCount').textContent = `${state.selectedKeys.size} selected`;
  if(!list.length){ $('findingList').innerHTML='<div class="empty">No findings match these filters.</div>'; return; }
  $('findingList').innerHTML = `<table><tr><th><input id="toggleVisible" type="checkbox"></th><th>Severity</th><th>Finding</th><th>Location</th><th>Review</th><th>Proof</th></tr>${list.map(f=>{
    const key=reviewKey(f), r=reviewOf(f), selected=state.selected && reviewKey(state.selected)===key;
    return `<tr class="finding ${selected?'selected':''}" data-key="${esc(key)}"><td><input class="selectFinding" data-key="${esc(key)}" type="checkbox" ${state.selectedKeys.has(key)?'checked':''}></td><td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td><td><b>${esc(f.name)}</b><br><span class="muted">${esc(f.template_id)}</span></td><td>${link(f.matched_url)}<br><span class="muted">${esc(f.method||'GET')} ${esc(f.parameter||'')}</span></td><td>${esc(r.status||'unreviewed')}${r.notes?'<br><span class="badge info">notes</span>':''}</td><td>${esc((f.evidence||[])[0]||'Evidence captured')}</td></tr>`;
  }).join('')}</table>`;
  document.querySelectorAll('tr.finding').forEach(row=>row.onclick=e=>{ if(e.target.classList.contains('selectFinding')) return; showDetail(state.findings.find(f=>reviewKey(f)===row.dataset.key)); });
  document.querySelectorAll('.selectFinding').forEach(box=>box.onchange=()=>{ box.checked?state.selectedKeys.add(box.dataset.key):state.selectedKeys.delete(box.dataset.key); renderFindings(); });
  $('toggleVisible').onchange=e=>{ list.forEach(f=>e.target.checked?state.selectedKeys.add(reviewKey(f)):state.selectedKeys.delete(reviewKey(f))); renderFindings(); };
}

function facts(items){ return `<div class="facts">${items.map(([k,v])=>`<div class="fact"><span>${esc(k)}</span>${esc(v || 'not recorded')}</div>`).join('')}</div>`; }
function transcript(t, kind){
  if(!t) return '<p class="muted">No transcript captured.</p>';
  const headers=Object.keys(t.headers||{}).map(k=>`${k}: ${(t.headers[k]||[]).join(', ')}`).join('\n');
  const body=String(t.body||'').replace(/^\s+/, '');
  const bodyLabel=kind==='response'?'Response body':kind==='baseline'?'Baseline body':'Request body';
  const rows=[['Method',t.method],['URL',t.url],['Final URL',t.final_url||'same as requested']];
  if(t.status_code) rows.push(['Status',t.status_code],['Duration',`${t.duration_ms ?? 'not recorded'} ms`],['Captured body',`${t.body_size ?? 'not recorded'} bytes${t.truncated?' (truncated)':''}`]);
  else rows.push(['Request body',`${t.body_size ?? 0} bytes`]);
  return `${facts(rows)}<div class="transcript-head"><h3>Headers${t.redacted?' (sensitive values redacted)':''}</h3><button class="secondary copy-mini copy-next">Copy headers</button></div><pre class="transcript-headers">${esc(headers||'No headers captured')}</pre><div class="transcript-head"><h3>${bodyLabel}</h3><button class="secondary copy-mini copy-next">Copy body</button></div><pre class="transcript-body">${esc(body||'No body captured')}</pre>`;
}
function curl(f){ const r=f.request||{}, h=r.headers||{}; let out=`curl -i -X ${r.method||f.method||'GET'} ${JSON.stringify(r.url||f.matched_url||'')}`; Object.keys(h).forEach(k=>out+=` -H ${JSON.stringify(k+': '+h[k].join(', '))}`); if(r.body) out+=` --data-raw ${JSON.stringify(r.body)}`; return out; }

function selectedReportFinding(){
  const key=state.reportFindingKey || (state.selected?reviewKey(state.selected):'');
  return state.findings.find(f=>reviewKey(f)===key) || state.selected || state.findings[0] || null;
}
function cweFromTemplate(f){
  const id=(f.template_id||'').toLowerCase();
  if(id.includes('xss')) return 'CWE-79 Cross-Site Scripting';
  if(id.includes('sql')) return 'CWE-89 SQL Injection';
  if(id.includes('ssrf')) return 'CWE-918 Server-Side Request Forgery';
  if(id.includes('redirect')) return 'CWE-601 Open Redirect';
  if(id.includes('traversal')||id.includes('file-inclusion')) return 'CWE-22 Path Traversal';
  if(id.includes('csrf')) return 'CWE-352 Cross-Site Request Forgery';
  if(id.includes('command')) return 'CWE-78 OS Command Injection';
  return '';
}
function reportCWE(f){ return (f.cwe||[]).join(', ') || cweFromTemplate(f) || 'Not mapped'; }
function impactFor(f){
  const id=(f.template_id||f.name||'').toLowerCase();
  if(id.includes('xss')) return 'An attacker may execute JavaScript in a victim browser, steal session context, or perform actions as the victim.';
  if(id.includes('sql')) return 'An attacker may read or modify database records depending on the vulnerable query and database permissions.';
  if(id.includes('ssrf')) return 'An attacker may force the server to access internal services, cloud metadata, or restricted network resources.';
  if(id.includes('redirect')) return 'An attacker may redirect users to a malicious site and increase phishing or account-takeover risk.';
  if(id.includes('traversal')||id.includes('file')) return 'An attacker may read files outside the intended directory and expose secrets or source code.';
  return 'The impact depends on exposed data, affected user roles, and the reachable application behavior.';
}
function reportStepsFor(f){
  const lines=['1. Navigate to the affected asset: '+(f.matched_url||f.target||'not recorded')];
  if(f.parameter) lines.push('2. Send the payload to the `'+f.parameter+'` parameter.');
  else lines.push('2. Send the captured request shown in the evidence section.');
  if(f.payload) lines.push('3. Use payload: `'+f.payload+'`');
  lines.push('4. Observe the response evidence that confirms the issue.');
  return lines.join('\n');
}
function reportEvidenceFor(f){
  const evidence=(f.evidence||[]).map(x=>'- '+x).join('\n')||'- Evidence was captured by Kneoscanner.';
  const request=f.request&&f.request.url?'\n\nRequest URL:\n`'+f.request.url+'`':'';
  const status=f.status_code?'\n\nHTTP status: '+f.status_code:'';
  const payload=f.payload?'\n\nPayload:\n`'+f.payload+'`':'';
  return [evidence,request,status,payload].filter(Boolean).join('');
}
function renderReportFindingOptions(){
  const select=$('reportFinding');
  if(!select) return;
  const current=state.reportFindingKey || (state.selected?reviewKey(state.selected):'');
  select.innerHTML=state.findings.length?state.findings.map(f=>`<option value="${esc(reviewKey(f))}" ${reviewKey(f)===current?'selected':''}>${esc((f.severity||'').toUpperCase())} - ${esc(f.name||'Finding')} - ${esc(f.matched_url||'')}</option>`).join(''):'<option value="">No findings available</option>';
}
function populateReportFromFinding(f=selectedReportFinding()){
  if(!f){ toast('Run a scan or select a finding first'); return; }
  state.reportFindingKey=reviewKey(f);
  $('reportTitle').value=(f.severity?f.severity.toUpperCase()+' - ':'')+(f.name||'Security finding');
  $('reportAsset').value=f.matched_url||f.final_url||f.target||'';
  $('reportWeakness').value=reportCWE(f);
  $('reportSeverity').value=(f.severity||'medium').toLowerCase();
  $('reportSummary').value=f.description||`${f.name||'A vulnerability'} was detected on the affected asset.`;
  $('reportSteps').value=reportStepsFor(f);
  $('reportImpact').value=f.impact||impactFor(f);
  $('reportEvidence').value=reportEvidenceFor(f);
  $('reportFix').value=f.remediation||'Validate the finding, patch the affected code path, and add a regression test.';
  renderReportFindingOptions();
  generateDisclosureReport();
}
function reportField(id){ return ($(id).value||'').trim(); }
function disclosureMarkdown(){
  const platform=$('reportPlatform').value;
  const title=reportField('reportTitle')||'Security vulnerability report';
  const asset=reportField('reportAsset')||'Not recorded';
  const weakness=reportField('reportWeakness')||'Not mapped';
  const severity=reportField('reportSeverity')||'medium';
  const summary=reportField('reportSummary')||'No summary provided.';
  const steps=reportField('reportSteps')||'No reproduction steps provided.';
  const impact=reportField('reportImpact')||'Impact requires analyst validation.';
  const evidence=reportField('reportEvidence')||'No evidence provided.';
  const fix=reportField('reportFix')||'No fix guidance provided.';
  const f=selectedReportFinding();
  const references=f&&f.references&&f.references.length?f.references.map(x=>'- '+x).join('\n'):'- No external references recorded';
  if(platform==='bugcrowd'){
    return ['# '+title,'','## Summary',summary,'','## Target / Asset',asset,'','## Vulnerability Type',weakness,'','## Severity',severity,'','## Steps to Reproduce',steps,'','## Proof of Concept / Evidence',evidence,'','## Security Impact',impact,'','## Suggested Remediation',fix,'','## References',references].join('\n');
  }
  if(platform==='standard'){
    return ['# '+title,'','**Severity:** '+severity,'**Weakness:** '+weakness,'**Affected asset:** '+asset,'','## Description',summary,'','## Reproduction',steps,'','## Evidence',evidence,'','## Impact',impact,'','## Remediation',fix,'','## References',references].join('\n');
  }
  return ['# '+title,'','## Summary',summary,'','## Affected Asset',asset,'','## Weakness',weakness,'','## Severity',severity,'','## Steps To Reproduce',steps,'','## Supporting Material / References',evidence+'\n\n'+references,'','## Impact',impact,'','## Recommended Remediation',fix].join('\n');
}
function generateDisclosureReport(){
  $('reportMarkdown').textContent=disclosureMarkdown();
}

function showDetail(f){
  if(!f) return;
  state.selected=f;
  const r=reviewOf(f), refs=(f.references||[]).map(link).join('<br>')||'No references recorded';
  $('details').innerHTML = `<div class="section-head"><div><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span> <span class="muted">${esc(f.confidence||'potential')}</span><h3>${esc(f.name)}</h3><p>${esc(f.description||'No description recorded.')}</p></div></div>
    <div class="actions"><button class="secondary" id="copyFindingId">Copy ID</button><button class="secondary" id="copyFindingJson">Copy JSON</button><button class="secondary" id="downloadFindingJson">Download JSON</button>${isURL(f.matched_url)?`<a class="button secondary" href="${esc(f.matched_url)}" target="_blank" rel="noreferrer">Open URL</a>`:''}</div>
    ${facts([['Finding ID',f.finding_id],['CWE',(f.cwe||[]).join(', ')||'Not mapped'],['CVSS',`${f.cvss_score||'Not scored'} ${f.cvss_vector||''}`],['Parameter',f.parameter||'Not applicable'],['Status',f.status_code],['Body size',f.body_size]])}
    <h3>Verification evidence</h3><ul>${(f.evidence||[]).map(x=>`<li>${esc(x)}</li>`).join('')}</ul>
    <h3>Remediation</h3><p>${esc(f.remediation||'Validate the finding, patch the affected component, and add a regression test.')}</p><h3>References</h3><p>${refs}</p>
    <div class="notes"><h3>Analyst notes</h3><textarea id="findingNotes">${esc(r.notes||'')}</textarea><div class="actions"><button class="secondary" id="saveNotes">Save notes</button><button class="secondary" id="markReviewed">Mark reviewed</button><button class="secondary" id="markFalsePositive">False positive</button><button class="secondary" id="clearReview">Clear review</button><span class="muted" id="reviewState">${esc(r.status||'unreviewed')}</span></div></div>
    <div class="tabs"><button class="tab ${state.activePane==='summary'?'active':''}" data-pane="summary">Summary</button><button class="tab ${state.activePane==='request'?'active':''}" data-pane="request">Request</button><button class="tab ${state.activePane==='response'?'active':''}" data-pane="response">Response</button><button class="tab ${state.activePane==='baseline'?'active':''}" data-pane="baseline">Baseline</button><button class="tab ${state.activePane==='curl'?'active':''}" data-pane="curl">cURL</button></div>
    <div id="summary" class="pane ${state.activePane==='summary'?'active':''}">${facts([['Target',f.target],['Template',f.template_id],['Final URL',f.final_url],['Technologies',(f.technologies||[]).join(', ')]])}</div>
    <div id="request" class="pane ${state.activePane==='request'?'active':''}">${transcript(f.request,'request')}</div>
    <div id="response" class="pane ${state.activePane==='response'?'active':''}">${transcript(f.response,'response')}</div>
    <div id="baseline" class="pane ${state.activePane==='baseline'?'active':''}">${transcript(f.baseline,'baseline')}</div>
    <div id="curl" class="pane ${state.activePane==='curl'?'active':''}"><pre>${esc(curl(f))}</pre><button class="secondary" id="copyCurl">Copy cURL</button></div>`;
  document.querySelectorAll('.tab').forEach(tab=>tab.onclick=()=>{ state.activePane=tab.dataset.pane; document.querySelectorAll('.tab,.pane').forEach(x=>x.classList.remove('active')); tab.classList.add('active'); $(state.activePane).classList.add('active'); });
  $('copyFindingId').onclick=()=>copy(f.finding_id||f.fingerprint||'');
  $('copyFindingJson').onclick=()=>copy(JSON.stringify(f,null,2));
  $('downloadFindingJson').onclick=()=>download(`${f.finding_id||'finding'}.json`, JSON.stringify(f,null,2), 'application/json');
  $('saveNotes').onclick=()=>saveReview(f, r.status||'none', $('findingNotes').value);
  $('markReviewed').onclick=()=>saveReview(f,'reviewed',$('findingNotes').value);
  $('markFalsePositive').onclick=()=>saveReview(f,'false_positive',$('findingNotes').value);
  $('clearReview').onclick=()=>saveReview(f,'none','');
  if($('copyCurl')) $('copyCurl').onclick=()=>copy(curl(f));
}

async function copy(text){ await navigator.clipboard.writeText(text); toast('Copied'); }
function download(name,text,type='text/plain'){ const blob=new Blob([text],{type}), a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),1000); }
document.addEventListener('click',e=>{ if(e.target.classList.contains('copy-next')) copy(e.target.parentElement.nextElementSibling.textContent||''); });

async function saveReview(f,status,notes=''){
  const resp=await fetch('/api/reviews/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({finding_id:f.finding_id||'',fingerprint:f.fingerprint||'',status,notes})});
  if(!resp.ok){ toast(await resp.text()); return; }
  state.reviews=await resp.json(); toast('Review saved'); renderAll(); showDetail(f);
}
async function bulkReview(status){ for(const f of state.findings.filter(x=>state.selectedKeys.has(reviewKey(x)))) await saveReview(f,status,reviewOf(f).notes||''); }

function renderAll(){ metrics(); reviewMetrics(); renderAI(); renderFindings(); if(state.selected) showDetail(state.findings.find(f=>reviewKey(f)===reviewKey(state.selected))||state.selected); }
function renderStatus(data){
  state.findings=data.findings||[]; state.reports=data.reports||[]; state.events=data.events||[]; state.aiAnalysis=data.ai_analysis||null;
  $('reports').innerHTML=state.reports.map(r=>`<a class="button secondary" href="${esc(r.URL)}" target="_blank">${esc(r.Name)}</a>`).join('');
  $('cancelScan').classList.toggle('hide', !data.running);
  $('submitScan').disabled=!!data.running;
  $('status').textContent=data.error?`Scan failed: ${data.error}`:data.running?`Scanning since ${new Date(data.started).toLocaleTimeString()}`:data.finished?`Scan completed at ${new Date(data.finished).toLocaleTimeString()} with ${state.findings.length} findings.`:'Ready.';
  $('activity').innerHTML=state.events.slice(-8).reverse().map(e=>`<div>${esc(new Date(e.timestamp).toLocaleTimeString())} · ${esc(e.message)}</div>`).join('');
  renderAll();
  renderReportFindingOptions();
}

async function poll(){ try{ renderStatus(await (await fetch('/api/status')).json()); }catch(e){ $('status').textContent=`Connection error: ${e.message}`; } }
async function loadReviews(){ try{ state.reviews=await (await fetch('/api/reviews')).json(); }catch{ state.reviews={}; } renderAll(); }
async function loadHistory(){ try{ const rows=await (await fetch('/api/history')).json(); $('historyCount').textContent=`${rows.length} recent scans`; $('historyList').innerHTML=rows.length?`<table><tr><th>Started</th><th>Target</th><th>Profile</th><th>Findings</th><th>Report</th></tr>${rows.slice(0,30).map(r=>`<tr><td>${esc(new Date(r.started_at).toLocaleString())}</td><td>${esc((r.targets||[]).join(', '))}</td><td>${esc(r.profile)}</td><td>${esc(r.findings)}</td><td>${r.report?`<a class="link" href="/reports/${esc(String(r.report).split(/[\\\\/]/).pop())}" target="_blank">Open</a>`:'No report'}</td></tr>`).join('')}</table>`:'<div class="empty">No scan history yet.</div>'; }catch(e){ $('historyList').textContent=e.message; } }
async function loadTemplates(){ try{ state.templates=(await (await fetch('/api/templates')).json()).templates||[]; renderTemplates(); }catch(e){ $('templateList').textContent=e.message; } }
function renderTemplates(){ const q=$('templateSearch').value.toLowerCase(), sev=$('templateSeverity').value, status=$('templateStatus').value; const rows=state.templates.filter(t=>(!q||[t.id,t.name,t.path,(t.tags||[]).join(' ')].join(' ').toLowerCase().includes(q))&&(!sev||t.severity===sev)&&(!status||(status==='valid'?t.valid:!t.valid))); $('templateCount').textContent=`${rows.length} of ${state.templates.length} templates`; $('templateList').innerHTML=rows.length?`<table><tr><th>Status</th><th>Name</th><th>Severity</th><th>Risk</th><th>CWE/CVE</th><th>Path</th></tr>${rows.map(t=>`<tr><td>${t.valid?'Valid':esc(t.error||'Invalid')}</td><td><b>${esc(t.name||t.id)}</b><br><span class="muted">${esc(t.id)}</span></td><td><span class="badge ${esc(t.severity)}">${esc(t.severity)}</span></td><td>${esc(t.risk||'safe')}</td><td>${esc([...(t.cwe||[]),...(t.cves||[])].join(', '))}</td><td>${esc(t.path)}</td></tr>`).join('')}</table>`:'<div class="empty">No templates match filters.</div>'; }
async function loadConfig(){ try{ const cfg=await (await fetch('/api/config')).json(); $('configList').innerHTML=`<div class="facts">${Object.entries(cfg).map(([k,v])=>`<div class="fact"><span>${esc(k)}</span>${esc(typeof v==='object'?JSON.stringify(v):v)}</div>`).join('')}</div>`; }catch(e){ $('configList').textContent=e.message; } }

function collectPolicy(){
  const fields={};
  document.querySelectorAll('#scanForm input,#scanForm select,#scanForm textarea').forEach(el=>{
    if(el.id==='authHeader'||el.id==='cookieHeader') return;
    fields[el.id]=el.type==='checkbox'?el.checked:el.value;
  });
  return {version:1,exported_at:new Date().toISOString(),fields};
}
function applyPolicy(policy){ Object.entries(policy.fields||{}).forEach(([id,value])=>{ const el=$(id); if(el) el.type==='checkbox'?el.checked=!!value:el.value=value; }); updateTargetCount(); toast('Policy imported'); }
function saveScanSettings(){ localStorage.setItem('neoscanner.scanSettings', JSON.stringify(collectPolicy())); }
function restoreScanSettings(){ try{ applyPolicy(JSON.parse(localStorage.getItem('neoscanner.scanSettings')||'{}')); }catch{} }
function updateTargetCount(){ $('targetCount').textContent=`${Math.max(1,targetList().length)} target${targetList().length===1?'':'s'} configured`; }

function scanBody(){ return {target:$('target').value,targets:$('targetList').value.split(/[\n,;]/).map(x=>x.trim()).filter(Boolean),profile:$('profile').value,threads:+$('threads').value,severity:$('severity').value,parameters:$('parameters').value,authorization:$('authorization').checked,userAgent:$('userAgent').value,authHeader:$('authHeader').value,cookie:$('cookieHeader').value,crawl:$('crawlEnabled').checked,crawlMaxDepth:+$('crawlMaxDepth').value,crawlMaxPages:+$('crawlMaxPages').value,timeout:+$('timeoutSeconds').value,retries:+$('retries').value,retryDelay:+$('retryDelay').value,requestDelay:+$('requestDelay').value,maxRespBytes:+$('maxRespBytes').value,followRedirects:$('followRedirects').checked,verifySSL:$('verifySSL').checked,allowExternal:$('allowExternal').checked,discoverOpenAPI:$('discoverOpenAPI').checked,discoverSitemap:$('discoverSitemap').checked,discoverScripts:$('discoverScripts').checked,activeParamTesting:$('activeParamTesting').checked,activePostTesting:$('activePostTesting').checked,aiEnabled:$('aiEnabled').checked,aiProvider:$('aiProvider').value,aiModel:$('aiModel').value}; }

function statusSignature(data){
  const findings=(data.findings||[]).map(f=>`${f.finding_id||f.fingerprint||f.name}:${f.timestamp||''}`).join('|');
  const reports=(data.reports||[]).map(r=>`${r.Name}:${r.URL}`).join('|');
  const events=(data.events||[]).slice(-8).map(e=>`${e.timestamp}:${e.type}:${e.message}`).join('|');
  const ai=data.ai_analysis?JSON.stringify(data.ai_analysis):'';
  return [data.running,data.started,data.finished,data.error,findings,reports,events,ai].join('::');
}

renderStatus=function(data){
  const signature=statusSignature(data);
  if(signature===state.lastStatusSignature) return;
  state.lastStatusSignature=signature;
  const selectedKey=state.selected?reviewKey(state.selected):'';
  const detail=$('details');
  const detailTop=detail?detail.scrollTop:0;
  const preScroll=[...document.querySelectorAll('.pane.active pre')].map(pre=>pre.scrollTop);
  state.findings=data.findings||[];
  state.reports=data.reports||[];
  state.events=data.events||[];
  state.aiAnalysis=data.ai_analysis||null;
  $('reports').innerHTML=state.reports.map(r=>`<a class="button secondary" href="${esc(r.URL)}" target="_blank">${esc(r.Name)}</a>`).join('');
  $('cancelScan').classList.toggle('hide', !data.running);
  $('submitScan').disabled=!!data.running;
  $('status').textContent=data.error?`Scan failed: ${data.error}`:data.running?`Scanning since ${new Date(data.started).toLocaleTimeString()}`:data.finished?`Scan completed at ${new Date(data.finished).toLocaleTimeString()} with ${state.findings.length} findings.`:'Ready.';
  $('activity').innerHTML=state.events.slice(-8).reverse().map(e=>`<div>${esc(new Date(e.timestamp).toLocaleTimeString())} · ${esc(e.message)}</div>`).join('');
  renderAll();
  renderReportFindingOptions();
  if(selectedKey){
    requestAnimationFrame(()=>{
      const freshDetail=$('details');
      if(freshDetail) freshDetail.scrollTop=detailTop;
      document.querySelectorAll('.pane.active pre').forEach((pre,index)=>{ if(preScroll[index]!==undefined) pre.scrollTop=preScroll[index]; });
    });
  }
};

poll=async function(){ try{ renderStatus(await (await fetch('/api/status')).json()); }catch(e){ $('status').textContent=`Connection error: ${e.message}`; } };

function scheduleStatusRefresh(delay=120){
  clearTimeout(state.refreshTimer);
  state.refreshTimer=setTimeout(poll, delay);
}

function connectEvents(){
  if(!window.EventSource) return false;
  const source=new EventSource('/api/events');
  state.eventSource=source;
  source.addEventListener('ready',()=>scheduleStatusRefresh(0));
  source.addEventListener('scan',event=>{
    try{
      const scanEvent=JSON.parse(event.data||'{}');
      if(scanEvent.message){
        state.events=[...state.events.slice(-99), scanEvent];
        $('activity').innerHTML=state.events.slice(-8).reverse().map(e=>`<div>${esc(new Date(e.timestamp).toLocaleTimeString())} · ${esc(e.message)}</div>`).join('');
      }
    }catch{}
    scheduleStatusRefresh(120);
  });
  source.onerror=()=>scheduleStatusRefresh(1000);
  return true;
}

function init(){
  document.querySelectorAll('.nav button').forEach(b=>b.onclick=()=>activateView(b.dataset.view));
  $('quickScan').onclick=()=>activateView('scan');
  $('cancelScan').onclick=async()=>{ const r=await fetch('/api/scans/cancel',{method:'POST'}); toast(r.ok?'Cancel requested':await r.text()); };
  $('scanForm').onsubmit=async e=>{ e.preventDefault(); saveScanSettings(); const r=await fetch('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(scanBody())}); toast(r.ok?'Scan queued':await r.text()); poll(); };
  $('preset').onchange=()=>{ const p={passive_recon:['passive',15,'info',''],safe_web:['safe',25,'low',''],active_params:['active',20,'medium','id,search,q,page'],intrusive_lab:['intrusive',10,'medium','id,search,q,page,file,path,url']}[$('preset').value]; if(p){$('profile').value=p[0];$('threads').value=p[1];$('severity').value=p[2];$('parameters').value=p[3];} };
  ['search','severityFilter','confidenceFilter','reviewFilter','sort'].forEach(id=>$(id).oninput=renderFindings);
  ['templateSearch','templateSeverity','templateStatus'].forEach(id=>$(id).oninput=renderTemplates);
  $('selectVisible').onclick=()=>{ visibleFindings().forEach(f=>state.selectedKeys.add(reviewKey(f))); renderFindings(); };
  $('clearSelection').onclick=()=>{ state.selectedKeys.clear(); renderFindings(); };
  $('bulkReviewed').onclick=()=>bulkReview('reviewed');
  $('bulkFalsePositive').onclick=()=>bulkReview('false_positive');
  $('exportSelected').onclick=()=>download('selected-findings.json', JSON.stringify(state.findings.filter(f=>state.selectedKeys.has(reviewKey(f))),null,2), 'application/json');
  $('exportVisibleCsv').onclick=()=>download('visible-findings.csv', csv(visibleFindings()), 'text/csv');
  $('refreshHistory').onclick=loadHistory; $('refreshTemplates').onclick=loadTemplates; $('refreshConfig').onclick=loadConfig;
  $('reportFinding').onchange=()=>{ state.reportFindingKey=$('reportFinding').value; populateReportFromFinding(selectedReportFinding()); };
  $('reportPlatform').onchange=generateDisclosureReport;
  ['reportTitle','reportAsset','reportWeakness','reportSeverity','reportSummary','reportSteps','reportImpact','reportEvidence','reportFix'].forEach(id=>$(id).oninput=generateDisclosureReport);
  $('populateReport').onclick=()=>populateReportFromFinding();
  $('generateReport').onclick=generateDisclosureReport;
  $('copyReport').onclick=()=>copy($('reportMarkdown').textContent||'');
  $('downloadReport').onclick=()=>download('kneoscanner-disclosure-report.md', $('reportMarkdown').textContent||'', 'text/markdown');
  $('exportPolicy').onclick=()=>download('kneoscanner-policy.json', JSON.stringify(collectPolicy(),null,2), 'application/json');
  $('importPolicyButton').onclick=()=>$('importPolicyFile').click();
  $('importPolicyFile').onchange=async e=>{ const file=e.target.files[0]; if(file) applyPolicy(JSON.parse(await file.text())); };
  ['target','targetList'].forEach(id=>$(id).oninput=updateTargetCount);
  restoreScanSettings(); activateView(localStorage.getItem('neoscanner.appView')||'overview'); updateTargetCount(); renderReportFindingOptions(); loadReviews(); loadHistory(); loadTemplates(); loadConfig(); poll(); connectEvents(); setInterval(poll, 15000);
}
function csv(items){ const cols=['severity','confidence','name','matched_url','method','parameter','template_id','remediation']; return cols.join(',')+'\n'+items.map(f=>cols.map(c=>`"${String(f[c]??'').replaceAll('"','""')}"`).join(',')).join('\n'); }
init();
