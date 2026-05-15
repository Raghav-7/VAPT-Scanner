// Mendix VAPT Scanner — Dashboard Application
let socket = null;
let currentScanId = null;
let currentFindings = [];
let activeFilter = 'all';

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
  const btnScan = document.getElementById('btn-scan');
  btnScan.disabled = true;
  btnScan.innerHTML = '<span class="spinner"></span> Starting...';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl, modules })
    });
    const data = await res.json();
    if (data.error) { showToast(data.error, 'error'); resetScanBtn(); return; }

    currentScanId = data.scanId;
    currentFindings = [];
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
      case 'error': handleError(event.data); break;
    }
  });
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
  renderFindings(currentFindings);
}

function renderCategoryFilter(categoryCounts) {
  const container = document.getElementById('category-filter');
  const total = Object.values(categoryCounts).reduce((a, b) => a + b, 0);
  let html = `<button class="filter-btn active" onclick="filterFindings('all')">All<span class="filter-count">(${total})</span></button>`;
  for (const [cat, count] of Object.entries(categoryCounts).sort((a, b) => b[1] - a[1])) {
    html += `<button class="filter-btn" onclick="filterFindings('${cat}')">${cat}<span class="filter-count">(${count})</span></button>`;
  }
  container.innerHTML = html;
}

function filterFindings(category) {
  activeFilter = category;
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.textContent.includes(category === 'all' ? 'All' : category));
  });
  const filtered = category === 'all' ? currentFindings : currentFindings.filter(f => f.category === category);
  renderFindings(filtered);
}

function renderFindings(findings) {
  const container = document.getElementById('findings-list');
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort((a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5));

  container.innerHTML = sorted.map((f, i) => {
    // Build the "How to Fix" section using the remediation guide
    let fixHtml = '';
    if (typeof renderRemediationHTML === 'function') {
      fixHtml = renderRemediationHTML(f);
    } else {
      fixHtml = `<div class="detail-text">${escHtml(f.remediation)}</div>`;
    }

    return `
    <div class="finding-card" id="finding-${i}" onclick="toggleFinding(${i})">
      <div class="finding-header">
        <span class="finding-severity ${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        <span class="finding-category">${escHtml(f.category)}</span>
        <svg class="finding-expand" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>
      </div>
      <div class="finding-details">
        <div class="detail-section"><div class="detail-label">Description</div><div class="detail-text">${escHtml(f.description)}</div></div>
        <div class="detail-section"><div class="detail-label">Evidence</div><div class="detail-code">${escHtml(f.evidence)}</div></div>
        <div class="detail-section">
          <div class="detail-label">Quick Fix</div>
          <div class="detail-text">${escHtml(f.remediation)}</div>
        </div>
        <div class="detail-section">
          <div class="fix-label">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>
            How to Fix in Mendix — Step by Step
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
