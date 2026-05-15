// Universal VAPT Scanner — Dashboard Application
let socket = null;
let currentScanId = null;
let currentFindings = [];
let currentTechStack = 'Unknown';
let activeFilter = 'all';
let showIgnored = false;

// Initialize Socket.IO
function initSocket() {
  socket = io();
  socket.on('connect', () => console.log('[WS] Connected'));
  socket.on('disconnect', () => console.log('[WS] Disconnected'));
}

// Toggle module selection
function toggleModule(el) {
  el.classList.toggle('selected');
}

// Get selected modules
function getSelectedModules() {
  const cards = document.querySelectorAll('.module-card.selected');
  if (cards.length === document.querySelectorAll('.module-card').length) return 'all';
  return Array.from(cards).map(c => c.dataset.module);
}

// Start scan
async function startScan() {
  const urlInput = document.getElementById('target-url');
  const targetUrl = urlInput.value.trim();
  if (!targetUrl) { showToast('Please enter a target URL', 'error'); return; }
  try { new URL(targetUrl); } catch { showToast('Invalid URL format', 'error'); return; }

  const modules = getSelectedModules();
  
  // Parse custom headers
  const customHeadersText = (document.getElementById('custom-headers')?.value || '').trim();
  const customHeaders = {};
  if (customHeadersText) {
    const lines = customHeadersText.split('\n');
    for (const line of lines) {
      const parts = line.split(':');
      if (parts.length >= 2) {
        const key = parts[0].trim();
        const val = parts.slice(1).join(':').trim();
        if (key && val) customHeaders[key] = val;
      }
    }
  }

  const btnScan = document.getElementById('btn-scan');
  btnScan.disabled = true;
  btnScan.innerHTML = '<span class="spinner"></span> Starting...';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        targetUrl, 
        modules,
        options: { headers: customHeaders }
      })
    });
    const data = await res.json();
    if (data.error) { showToast(data.error, 'error'); resetScanBtn(); return; }

    currentScanId = data.scanId;
    currentFindings = [];
    currentTechStack = 'Unknown';
    showProgress(targetUrl);
    listenToScan(data.scanId);
  } catch (err) {
    showToast('Failed to start scan: ' + err.message, 'error');
    resetScanBtn();
  }
}

function resetScanBtn() {
  const btn = document.getElementById('btn-scan');
  btn.disabled = false;
  btn.innerHTML = '<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg><span>Start Scan</span>';
}

// Listen to scan events
function listenToScan(scanId) {
  socket.on(`scan:${scanId}`, (event) => {
    switch (event.type) {
      case 'scan_started': handleScanStarted(event.data); break;
      case 'module_started': handleModuleStarted(event.data); break;
      case 'module_complete': handleModuleComplete(event.data); break;
      case 'module_error': handleModuleError(event.data); break;
      case 'progress': handleProgress(event.data); break;
      case 'complete': handleComplete(event.data); break;
      case 'tech_detection_started': handleTechDetectionStarted(event.data); break;
      case 'tech_detection_complete': handleTechDetectionComplete(event.data); break;
    }
  });
}

function handleTechDetectionStarted(data) {
  showToast(data.message, 'info');
}

function handleTechDetectionComplete(data) {
  currentTechStack = data.techStack;
  showToast(`Detected Tech Stack: ${data.techStack}`, 'info');
}

function showProgress(targetUrl) {
  document.getElementById('scan-config').classList.add('hidden');
  document.getElementById('scan-progress').classList.remove('hidden');
  document.getElementById('results').classList.add('hidden');
  document.getElementById('progress-target').textContent = targetUrl;
  document.getElementById('progress-bar').style.width = '0%';
  document.getElementById('progress-percent').textContent = '0%';
  document.getElementById('progress-modules').innerHTML = '';
}

function handleScanStarted(data) {
  const container = document.getElementById('progress-modules');
  container.innerHTML = data.modules.map(m =>
    `<div class="progress-module" id="pm-${m.key}"><span>${m.icon}</span><span>${m.name}</span></div>`
  ).join('');
}

function handleModuleStarted(data) {
  const el = document.getElementById(`pm-${data.key}`);
  if (el) { el.classList.add('active'); el.classList.remove('done', 'error'); }
}

function handleModuleComplete(data) {
  const el = document.getElementById(`pm-${data.key}`);
  if (el) {
    el.classList.remove('active');
    el.classList.add('done');
    el.innerHTML = `<span>${data.icon}</span><span>${data.module} (${data.findingsCount})</span>`;
  }
  if (data.findings) currentFindings.push(...data.findings);
}

function handleModuleError(data) {
  const el = document.getElementById(`pm-${data.key}`);
  if (el) { el.classList.remove('active'); el.classList.add('error'); }
}

function handleProgress(data) {
  document.getElementById('progress-bar').style.width = data.percent + '%';
  document.getElementById('progress-percent').textContent = data.percent + '%';
}

function handleComplete(summary) {
  showToast(`Scan complete — ${summary.totalFindings} findings`, 'success');
  document.getElementById('scan-progress').classList.add('hidden');
  showResults(summary);
  resetScanBtn();
}

function handleError(data) {
  showToast('Scan error: ' + data.message, 'error');
  resetScanBtn();
}

// Show results
function showResults(summary) {
  const resultsEl = document.getElementById('results');
  resultsEl.classList.remove('hidden');

  // Risk score animation
  const score = summary.riskScore;
  const arc = document.getElementById('risk-arc');
  const maxDash = 251.33;
  setTimeout(() => { arc.setAttribute('stroke-dasharray', `${(score / 100) * maxDash} ${maxDash}`); }, 100);

  const valueEl = document.getElementById('risk-value');
  animateNumber(valueEl, 0, score, 1000);

  const labelEl = document.getElementById('risk-label');
  labelEl.textContent = summary.riskLevel + ' Risk';
  labelEl.style.color = score >= 75 ? 'var(--critical)' : score >= 50 ? 'var(--high)' : score >= 25 ? 'var(--medium)' : 'var(--success)';
  valueEl.style.color = labelEl.style.color;
  valueEl.style.webkitTextFillColor = 'unset';

  // Severity counts
  const s = summary.severityCounts;
  ['critical','high','medium','low','info'].forEach(sev => {
    const el = document.getElementById(`count-${sev}`);
    animateNumber(el, 0, s[sev] || 0, 800);
  });

  // Category filter
  renderCategoryFilter(summary.categoryCounts);
  // Findings
  renderFindings(currentFindings, summary.techStack || currentTechStack);
}

function renderCategoryFilter(categoryCounts) {
  const container = document.getElementById('category-filter');
  const total = Object.values(categoryCounts).reduce((a, b) => a + b, 0);
  let html = `<div class="filter-toggles" style="display:flex; justify-content:space-between; align-items:center; width:100%; margin-bottom: 10px;">
    <div class="filter-buttons">
      <button class="filter-btn active" onclick="filterFindings('all')">All<span class="filter-count">(${total})</span></button>`;
  for (const [cat, count] of Object.entries(categoryCounts).sort((a, b) => b[1] - a[1])) {
    html += `<button class="filter-btn" onclick="filterFindings('${cat}')">${cat}<span class="filter-count">(${count})</span></button>`;
  }
  html += `</div>
    <div class="ignore-toggle">
      <label style="display:flex; align-items:center; gap:8px; color:var(--text-muted); cursor:pointer; font-size:14px;">
        <input type="checkbox" id="show-ignored-cb" onchange="toggleShowIgnored(this.checked)" ${showIgnored ? 'checked' : ''}>
        Show False Positives
      </label>
    </div>
  </div>`;
  container.innerHTML = html;
}

function toggleShowIgnored(checked) {
  showIgnored = checked;
  filterFindings(activeFilter);
}

function filterFindings(category) {
  activeFilter = category;
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.textContent.includes(category === 'all' ? 'All' : category));
  });
  const filtered = category === 'all' ? currentFindings : currentFindings.filter(f => f.category === category);
  renderFindings(filtered, currentTechStack);
}

function renderFindings(findings, techStack) {
  const container = document.getElementById('findings-list');
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const filteredByIgnore = showIgnored ? findings : findings.filter(f => !f.ignored);
  const sorted = [...filteredByIgnore].sort((a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5));

  if (sorted.length === 0) {
    container.innerHTML = '<div style="padding: 40px; text-align: center; color: var(--text-muted);">No findings to display.</div>';
    return;
  }

  container.innerHTML = sorted.map((f, i) => {
    // Build the "How to Fix" section using the remediation guide
    let fixHtml = '';
    if (typeof renderRemediationHTML === 'function') {
      fixHtml = renderRemediationHTML(f, techStack);
    } else {
      fixHtml = `<div class="detail-text">${escHtml(f.remediation)}</div>`;
    }

    return `
    <div class="finding-card ${f.ignored ? 'ignored' : ''}" id="finding-${i}">
      <div class="finding-header" onclick="toggleFinding(${i})" style="cursor: pointer;">
        <span class="finding-severity ${f.severity}">${f.severity}</span>
        <span class="finding-title">${f.ignored ? '<span style="text-decoration:line-through;opacity:0.6;">' : ''}${escHtml(f.title)}${f.ignored ? '</span> <span style="font-size:12px;color:var(--text-muted);">(False Positive)</span>' : ''}</span>
        <span style="flex:1"></span>
        <span class="finding-category" style="margin-right:16px;">${escHtml(f.category)}</span>
        <button class="btn btn-ghost btn-sm" style="margin-right:16px; font-size:12px; padding: 4px 8px;" onclick="toggleIgnoreFinding('${f.id}', event)">
          ${f.ignored ? 'Restore' : 'Mark False Positive'}
        </button>
        <svg class="finding-expand" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>
      </div>
      <div class="finding-details">
        <div class="detail-section"><div class="detail-label">Description</div><div class="detail-text">${escHtml(f.description)}</div></div>
        <div class="detail-section"><div class="detail-label">Evidence</div><div class="detail-code">${escHtml(f.evidence)}</div></div>
        <div class="detail-section">
          <div class="detail-label">How to Replicate</div>
          <div class="detail-text">${generateReplicationSteps(f)}</div>
        </div>
        <div class="detail-section">
          <div class="detail-label">Quick Fix</div>
          <div class="detail-text">${escHtml(f.remediation)}</div>
        </div>
        <div class="detail-section">
          <div class="fix-label">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>
            How to Fix in ${techStack === 'Unknown' ? 'Your App' : techStack} — Step by Step
          </div>
          ${fixHtml}
        </div>
        ${f.reference ? `<div class="detail-section"><div class="detail-label">OWASP Reference</div><a class="detail-link" href="${escHtml(f.reference)}" target="_blank" rel="noopener">${escHtml(f.reference)}</a></div>` : ''}
      </div>
    </div>
  `}).join('');
}

function toggleFinding(idx) {
  document.getElementById(`finding-${idx}`).classList.toggle('expanded');
}

async function toggleIgnoreFinding(findingId, event) {
  event.stopPropagation();
  const finding = currentFindings.find(f => f.id === findingId);
  if (!finding) return;
  
  const newIgnored = !finding.ignored;
  
  try {
    const res = await fetch(`/api/scan/${currentScanId}/ignore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findingId, ignored: newIgnored })
    });
    const data = await res.json();
    if (data.success) {
      finding.ignored = newIgnored;
      showResults(data.summary);
      showToast(newIgnored ? 'Finding ignored as false positive' : 'Finding restored', 'success');
    }
  } catch(e) {
    showToast('Failed to update finding status', 'error');
  }
}

// Export
async function exportReport() {
  if (!currentScanId) return;
  window.open(`/api/scan/${currentScanId}/export`, '_blank');
}

async function exportExcel() {
  if (!currentScanId) return;
  showToast('Generating Excel report...', 'info');
  window.open(`/api/scan/${currentScanId}/export-excel`, '_blank');
}

function newScan() {
  document.getElementById('results').classList.add('hidden');
  document.getElementById('scan-progress').classList.add('hidden');
  document.getElementById('scan-config').classList.remove('hidden');
  currentScanId = null;
  currentFindings = [];
  currentTechStack = 'Unknown';
  resetScanBtn();
}

function stopScan() { newScan(); showToast('Scan stopped', 'error'); }

// History
async function toggleHistory() {
  const historyEl = document.getElementById('scan-history');
  const isHidden = historyEl.classList.contains('hidden');
  document.querySelectorAll('.main > section').forEach(s => s.classList.add('hidden'));
  if (isHidden) {
    historyEl.classList.remove('hidden');
    try {
      const res = await fetch('/api/scans');
      const scans = await res.json();
      const list = document.getElementById('history-list');
      if (scans.length === 0) { list.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:40px">No scan history yet</p>'; return; }
      list.innerHTML = scans.reverse().map(s => `
        <div class="history-item" onclick="loadScan('${s.id}')">
          <div><div class="history-url">${escHtml(s.targetUrl)}</div><div style="font-size:12px;color:var(--text-muted);margin-top:4px">${new Date(s.startedAt).toLocaleString()}</div></div>
          <div class="history-meta"><span>${s.findingsCount} findings</span><span class="history-badge ${s.status}">${s.status}</span></div>
        </div>
      `).join('');
    } catch (err) { showToast('Failed to load history', 'error'); }
  } else {
    document.getElementById('scan-config').classList.remove('hidden');
  }
}

async function loadScan(scanId) {
  try {
    const res = await fetch(`/api/scan/${scanId}`);
    const scan = await res.json();
    currentScanId = scan.id;
    currentFindings = scan.findings;
    currentTechStack = scan.techStack || 'Unknown';
    document.getElementById('scan-history').classList.add('hidden');
    if (scan.summary) showResults(scan.summary);
  } catch (err) { showToast('Failed to load scan', 'error'); }
}

// Utilities
function escHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function animateNumber(el, from, to, duration) {
  const start = Date.now();
  const tick = () => {
    const elapsed = Date.now() - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(from + (to - from) * eased);
    if (progress < 1) requestAnimationFrame(tick);
  };
  tick();
}

function generateReplicationSteps(finding) {
  const cat = (finding.category || '').toLowerCase();
  const evidence = finding.evidence || '';
  const targetUrl = document.getElementById('target-url')?.value || 'http://localhost:8080';
  
  if (cat.includes('header') || cat.includes('cookie') || cat.includes('cors')) {
    return `
      <ol style="margin-left: 20px; list-style-type: decimal; padding-left: 10px; display: flex; flex-direction: column; gap: 8px;">
        <li>Open your terminal or command prompt.</li>
        <li>Execute the following cURL command to fetch the raw HTTP response headers:<br>
          <code style="display:block; margin-top:4px; padding:8px; background:var(--bg-darker); border-radius:4px; color:var(--success);">curl -I -k "${escHtml(targetUrl)}"</code>
        </li>
        <li>Review the printed output. You will notice that the specific attribute mentioned in the evidence (e.g., <code>Secure</code>, <code>HttpOnly</code>, or <code>Strict-Transport-Security</code>) is entirely missing or incorrectly configured.</li>
      </ol>`;
  }
  
  if (cat.includes('xss') || cat.includes('injection') || cat.includes('sqli')) {
    return `
      <ol style="margin-left: 20px; list-style-type: decimal; padding-left: 10px; display: flex; flex-direction: column; gap: 8px;">
        <li>Open the application in your browser and navigate to the exact vulnerable input field or URL parameter highlighted above.</li>
        <li>Copy the following test payload:<br>
          <code style="display:block; margin-top:4px; padding:8px; background:var(--bg-darker); border-radius:4px; color:var(--warning); word-break: break-all;">${escHtml(evidence.substring(0, 80))}${evidence.length > 80 ? '...' : ''}</code>
        </li>
        <li>Paste the payload into the input and submit the form/request.</li>
        <li><b>Verification:</b> If the application is vulnerable, the payload will execute (e.g., an alert box will pop up for XSS, or the database will throw a syntax error or delay the response for SQLi).</li>
      </ol>`;
  }
  
  if (cat.includes('mendix')) {
    return `
      <ol style="margin-left: 20px; list-style-type: decimal; padding-left: 10px; display: flex; flex-direction: column; gap: 8px;">
        <li>Open your web browser and navigate to the application.</li>
        <li>Press <b>F12</b> to open the Developer Tools and switch to the <b>Network</b> tab.</li>
        <li>Ensure the "Fetch/XHR" filter is enabled so you only see API calls.</li>
        <li>Perform an action in the app to trigger a Mendix microflow or data retrieval. Look for requests going to <code>/xas/</code> or <code>/p/</code>.</li>
        <li>Click on the request and inspect the <b>Payload</b> and <b>Response</b> tabs. You will see the overly permissive data exposure or misconfiguration referenced in the evidence.</li>
      </ol>`;
  }

  if (cat.includes('csrf') || cat.includes('ssrf')) {
    return `
      <ol style="margin-left: 20px; list-style-type: decimal; padding-left: 10px; display: flex; flex-direction: column; gap: 8px;">
        <li>Open Postman (or Burp Suite) and create a new HTTP request targeting the affected endpoint.</li>
        <li>Set the HTTP method to POST/PUT/DELETE as required by the endpoint.</li>
        <li>Remove or intentionally modify the Anti-CSRF token in the request headers or body.</li>
        <li>Send the request.</li>
        <li><b>Verification:</b> If the server responds with a <code>200 OK</code> and processes the action anyway, the token validation is missing or improperly implemented.</li>
      </ol>`;
  }
  
  return `
    <ol style="margin-left: 20px; list-style-type: decimal; padding-left: 10px; display: flex; flex-direction: column; gap: 8px;">
      <li><b>Setup:</b> Open <a href="https://www.postman.com/downloads/" target="_blank" style="color:var(--primary);">Postman</a> and create a new HTTP request to the affected URL.</li>
      <li><b>Configure Request:</b> Set the HTTP method (GET/POST) and add any specific headers, cookies, or body parameters exactly as they appear in the Evidence section.</li>
      <li><b>Execute:</b> Send the request to the server.</li>
      <li><b>Analyze Response:</b> Inspect the response body and HTTP status code. Compare the output against the expected secure behavior. The vulnerability is confirmed if the server leaks sensitive data, accepts unauthorized input, or behaves unexpectedly as described in the vulnerability description.</li>
    </ol>`;
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 4000);
}

// Init
document.addEventListener('DOMContentLoaded', () => {
  initSocket();
  document.getElementById('target-url').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') startScan();
  });
});
