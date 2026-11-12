const $ = id => document.getElementById(id);
let rows = [];
let configured = false, busy = false, serverMode;
const completed = new Map();
function text(tag, value, className) {
  const node = document.createElement(tag); node.textContent = value;
  if (className) node.className = className;
  return node;
}
function safeIssueLink(issue) {
  if (!issue?.url || !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/issues\/\d+$/.test(issue.url)) return null;
  const link = text('a', `Issue #${issue.number}`); link.href = issue.url; link.target = '_blank'; link.rel = 'noopener noreferrer'; return link;
}
async function refresh() {
  const response = await fetch('/api/events');
  if (!response.ok) throw new Error('Unavailable');
  const data = await response.json(); rows = data.events;
  if (!['MOCK', 'REAL'].includes(data.mode)) throw new Error('Invalid mode');
  if (configured && serverMode !== data.mode) { location.reload(); return; }
  serverMode = data.mode;
  const live = data.mode === 'REAL';
  $('mode-label').textContent = `${data.mode} GITHUB · LOCAL CREDENTIALS`;
  $('form-mode').textContent = data.mode;
  $('environment-title').textContent = live ? 'Live GitHub environment' : 'Simulation environment';
  $('environment-description').textContent = live
    ? `Allowed requests create real issues in ${data.repository}. Agent credentials last up to 60 seconds and are locally issued. SpaceComputer integration is pending.`
    : 'Local credentials and simulated issues. No GitHub API calls. SpaceComputer integration is pending.';
  $('created-label').textContent = live ? 'GITHUB ISSUES CREATED' : 'SIMULATED ISSUES';
  $('live-confirm-label').hidden = !live;
  $('confirm-live').required = live;
  if (!configured) { $('repository').value = data.repository; configured = true; }
  $('submit').disabled = busy;
  $('connection').textContent = '● Local demo connected';
  $('total').textContent = rows.length;
  $('allowed').textContent = rows.filter(r => r.decision === 'ALLOW').length;
  $('denied').textContent = rows.filter(r => r.decision === 'DENY').length;
  $('created').textContent = rows.filter(r => ['MOCK_CREATED', 'CREATED'].includes(r.result)).length;
  $('empty').hidden = rows.length > 0;
  $('events').replaceChildren();
  for (const row of rows) {
    const tr = document.createElement('tr');
    const time = text('td', new Date(row.timestamp).toLocaleTimeString());
    const detail = text('button', row.requestId.slice(0, 8), 'link-button'); detail.type = 'button'; detail.title = 'View audit metadata';
    detail.onclick = () => { $('detail').hidden = false; $('metadata').textContent = JSON.stringify(row, null, 2); $('detail').scrollIntoView({ behavior: 'smooth', block: 'nearest' }); };
    time.append(document.createElement('br'), detail);
    const agent = text('td', row.agentId); agent.append(text('small', row.resource));
    const decision = document.createElement('td'); decision.append(text('span', row.decision, `badge ${row.decision}`));
    const result = text('td', row.result.replaceAll('_', ' '));
    result.append(text('small', row.githubCalled ? (row.mode === 'REAL' ? 'GitHub adapter invoked' : 'Simulated adapter invoked') : 'No GitHub operation'));
    const operation = completed.get(row.requestId) || data.operations?.[row.requestId];
    if (operation?.mode === 'MOCK' && operation.issue) result.append(text('small', `Simulated issue #${operation.issue.number}`));
    const link = safeIssueLink(operation?.issue); if (link) result.append(link);
    tr.append(time, agent, decision, result); $('events').append(tr);
  }
}
$('close').onclick = () => { $('detail').hidden = true; };
$('request-form').onsubmit = async event => {
  event.preventDefault(); if (!configured || busy) return;
  busy = true; $('submit').disabled = true; $('outcome').textContent = 'Evaluating request…';
  try {
    const input = { ...Object.fromEntries(new FormData(event.target)), confirmLive: $('confirm-live').checked };
    const response = await fetch('/api/operator/requests', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Request failed');
    completed.set(result.requestId, result); if (completed.size > 500) completed.delete(completed.keys().next().value);
    $('outcome').textContent = `${result.decision} · ${result.result.replaceAll('_', ' ')}${result.issue ? ` #${result.issue.number}` : ''}${result.mode === 'MOCK' ? ' · No real issue created.' : ''}`;
    const link = safeIssueLink(result.issue); if (link) $('outcome').append(document.createElement('br'), link);
    $('confirm-live').checked = false;
    await refresh();
  } catch { $('outcome').textContent = 'Could not complete the request. Check the server before submitting again.'; }
  finally { busy = false; $('submit').disabled = false; }
};
refresh().catch(() => { $('connection').textContent = '● Local demo unavailable'; });
setInterval(() => refresh().catch(() => { $('connection').textContent = '● Connection interrupted'; }), 5000);
