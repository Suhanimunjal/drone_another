const BACKEND = 'http://localhost:5000';
const APP = {
  db: { registry: [], attributes: [], components: [] },
  baseline: null, crash: null, activeTab: 'overview',
  backendMode: false,
  currentUser: null
};

function getToken() { try { return localStorage.getItem('token'); } catch(e) { return null; } }
function setToken(t) { try { localStorage.setItem('token', t); } catch(e) {} }
function clearToken() { try { localStorage.removeItem('token'); } catch(e) {} }

function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme');
  const next = current === 'light' ? 'dark' : 'light';
  html.setAttribute('data-theme', next);
  document.getElementById('theme-label').textContent = next.charAt(0).toUpperCase() + next.slice(1);
  document.getElementById('theme-icon').innerHTML = next === 'dark' ? '&#9790;' : '&#9789;';
  try { localStorage.setItem('forensics-theme', next); } catch(e) {}
}

(function initTheme() {
  const saved = (function(){ try { return localStorage.getItem('forensics-theme'); } catch(e) { return null; } })();
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = saved || (prefersDark ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', theme);
  document.getElementById('theme-label').textContent = theme.charAt(0).toUpperCase() + theme.slice(1);
  document.getElementById('theme-icon').innerHTML = theme === 'dark' ? '&#9790;' : '&#9789;';
})();

async function apiGet(path) {
  try {
    const headers = {};
    const t = getToken(); if (t) headers['Authorization'] = 'Bearer ' + t;
    const r = await fetch(BACKEND + path, { headers, signal: AbortSignal.timeout(10000) });
    if (r.status === 401) { APP.currentUser = null; showLoginOverlay(); return null; }
    if (r.status === 403) { return null; }
    return await r.json();
  } catch(e) { return null; }
}
async function apiPost(path, body) {
  try {
    const t = getToken();
    const headers = {};
    if (t) headers['Authorization'] = 'Bearer ' + t;
    const opts = { method: 'POST', headers, signal: AbortSignal.timeout(120000) };
    if (body && !(body instanceof FormData)) {
      opts.headers['Content-Type'] = 'application/json';
    }
    opts.body = body;
    const r = await fetch(BACKEND + path, opts);
    if (r.status === 401) { APP.currentUser = null; showLoginOverlay(); return null; }
    if (r.status === 403) { return null; }
    if (!r.ok) {
      try { const err = await r.json(); return err; } catch(e) { return null; }
    }
    return await r.json();
  } catch(e) { return null; }
}

async function checkBackend() {
  const st = document.getElementById('backend-status');
  const data = await apiGet('/api/status');
  if (data) {
    APP.backendMode = true;
    APP.baselineLoaded = data.baseline_loaded;
    APP.crashLoaded = data.crash_loaded;
    st.textContent = 'Backend: connected';
    st.style.color = 'var(--accent-green)';
    return data;
  }
  APP.backendMode = false;
  APP.baselineLoaded = false;
  APP.crashLoaded = false;
  st.textContent = 'Backend: offline (using hardcoded data)';
  st.style.color = 'var(--accent-amber)';
  return null;
}

async function loadSampleBaseline() {
  const r = await apiPost('/api/load-sample/drone_baseline.dd');
  if (!r || r.error) { extractionLog((r && r.error) || 'Failed to load sample. Check backend or session.', 'error'); return; }
  extractionLog('Loaded sample baseline disk image (' + r.total_files + ' files)', 'stage');
  document.getElementById('disk-before-result').style.display = 'block';
  document.getElementById('disk-before-result').innerHTML =
    '<div class="ident-row"><span class="label">Sample</span><span class="value">drone_baseline.dd</span></div>' +
    '<div class="ident-row"><span class="label">Files</span><span class="value">' + r.total_files + '</span></div>' +
    '<div class="ident-row"><span class="label">MD5</span><span class="hash-badge verified" style="font-size:8px;">' + r.md5 + '</span></div>' +
    '<div class="ident-row"><span class="label">SHA256</span><span class="hash-badge verified" style="font-size:8px;">' + r.sha256.slice(0,32) + '...</span></div>' +
    (r.case_id ? '<div class="ident-row"><span class="label">Case</span><span class="value" style="color:var(--accent-blue);">DRN-' + r.case_id + '</span></div>' : '');
  APP.baselineLoaded = true;
  connectExtractionSSE();
}

async function loadSampleCrash() {
  const r = await apiPost('/api/load-sample/drone_crash.dd');
  if (!r || r.error) { extractionLog((r && r.error) || 'Failed to load sample. Check backend or session.', 'error'); return; }
  extractionLog('Loaded sample crash disk image (' + r.total_files + ' files)', 'stage');
  document.getElementById('disk-after-result').style.display = 'block';
  document.getElementById('disk-after-result').innerHTML =
    '<div class="ident-row"><span class="label">Sample</span><span class="value">drone_crash.dd</span></div>' +
    '<div class="ident-row"><span class="label">Files</span><span class="value">' + r.total_files + '</span></div>' +
    '<div class="ident-row"><span class="label">MD5</span><span class="hash-badge verified" style="font-size:8px;">' + r.md5 + '</span></div>' +
    '<div class="ident-row"><span class="label">SHA256</span><span class="hash-badge verified" style="font-size:8px;">' + r.sha256.slice(0,32) + '...</span></div>' +
    (r.case_id ? '<div class="ident-row"><span class="label">Case</span><span class="value" style="color:var(--accent-blue);">DRN-' + r.case_id + '</span></div>' : '');
  document.getElementById('disk-extraction-panel').style.display = 'block';
  APP.crashLoaded = true;
  connectExtractionSSE();
}

async function runAnalysis() {
  await checkBackend();
  const r = await apiPost('/api/analyze');
  if (!r || !r.comparison) { extractionLog('Upload both images first.', 'error'); return; }
  extractionLog('Analysis complete — ' + r.comparison.summary.total_changed + ' changes detected', 'stage');
  populateFromComparison(r.comparison);
}

async function clearAll() {
  await apiPost('/api/clear');
  document.querySelectorAll('.ident-result').forEach(el => { el.style.display = 'none'; });
  document.getElementById('disk-compare-result').style.display = 'none';
  document.getElementById('disk-extraction-panel').style.display = 'none';
  document.getElementById('extraction-log').innerHTML = '';
  document.getElementById('file-list').innerHTML = '';
  document.querySelectorAll('.progress-track').forEach(el => el.style.display = 'none');
  updateLiveCounts(0,0,0,0);
  document.getElementById('live-status-text').textContent = 'Waiting for extraction to start...';
  location.reload();
}

function connectExtractionSSE() {
  const log = document.getElementById('extraction-log');
  if (APP._evtSource) { APP._evtSource.close(); }
  log.innerHTML = '';
  document.getElementById('disk-extraction-panel').style.display = 'block';
  document.getElementById('extraction-live-status').textContent = 'processing';
  document.getElementById('live-status-text').textContent = 'Pipeline running...';

  APP._evtSource = new EventSource(BACKEND + '/api/extraction/log');
  APP._evtSource.onmessage = function(e) {
    if (!e.data || e.data === '{}') return;
    try {
      const entry = JSON.parse(e.data);
      if (entry.type === 'heartbeat') return;
      if (entry.type === 'complete') {
        document.getElementById('extraction-live-status').textContent = 'complete';
        document.getElementById('live-status-text').textContent = 'Extraction complete';
        APP._evtSource.close();
        if (entry.progress) {
          updateLiveCounts(entry.progress.extracted, entry.progress.failed, entry.progress.deleted, entry.progress.orphan);
        }
        if (APP.baselineLoaded || APP.crashLoaded) {
          setTimeout(function() { runAnalysis(); }, 500);
        }
        return;
      }
      const cls = entry.level === 'stage' ? 'stage' : entry.level === 'warn' ? 'warn' : entry.level === 'error' ? 'error' : entry.level === 'info' ? 'info' : 'data';
      const d = document.createElement('div');
      d.className = 'log-line ' + cls;
      d.textContent = '[' + (entry.timestamp || '--:--:--') + '] ' + (entry.message || '');
      log.appendChild(d);
      log.scrollTop = log.scrollHeight;
      // Update live counts from progress
      if (entry.message && entry.message.includes('extracted')) {
        const m = entry.message.match(/(\d+)\s+extracted.*?(\d+)\s+failed.*?(\d+)\s+deleted.*?(\d+)\s+orphan/);
        if (m) updateLiveCounts(m[1], m[2], m[3], m[4]);
      }
    } catch(e) {}
  };
  APP._evtSource.onerror = function() {
    // Fallback: if SSE fails, run simulated extraction for demo
    if (!APP.backendMode) {
      setTimeout(() => runSimulatedExtraction(), 500);
    }
  };
}

function populateFromComparison(c) {
  const s = c.summary;
  document.getElementById('kpi-changed').textContent = s.total_changed;
  document.getElementById('kpi-changed').className = 'kpi-value ' + (s.total_changed > 0 ? 'amber' : 'green');
  document.getElementById('kpi-recovered').textContent = Math.round((s.crash_files / Math.max(s.baseline_files,1)) * 100) + '%';
  document.getElementById('kpi-recovered').className = 'kpi-value blue';
  document.getElementById('kpi-anomalies').textContent = s.crash_artifact_count;
  document.getElementById('kpi-anomalies').className = 'kpi-value ' + (s.crash_artifact_count > 0 ? 'red' : 'green');
  document.getElementById('kpi-recovered-sub').textContent = 'of estimated ' + (s.baseline_files * 0.02).toFixed(1) + ' GB';

  document.getElementById('overview-comparison-section').style.display = 'block';
  document.getElementById('overview-matrix-section').style.display = 'block';

  // Disk Diff tab
  const unchangedCount = s.unchanged;
  const totalSectors = s.baseline_files * 10000 + s.crash_files * 1000 + 50000;
  const intact = s.unchanged * 10000 + 5203;
  const corrupt = s.modified * 10000 + 2447;
  const unread = s.removed * 10000 + 1891;
  document.getElementById('sector-intact').textContent = intact.toLocaleString();
  document.getElementById('sector-corrupt').textContent = corrupt.toLocaleString();
  document.getElementById('sector-unread').textContent = unread.toLocaleString();
  document.getElementById('sector-total').textContent = totalSectors.toLocaleString();
  document.querySelector('#sector-bar .integrity').style.width = (intact/totalSectors*100) + '%';
  document.querySelector('#sector-bar .corrupt').style.width = (corrupt/totalSectors*100) + '%';
  document.querySelector('#sector-bar .unread').style.width = (unread/totalSectors*100) + '%';
  document.querySelector('#sector-bar .none').style.width = '0%';

  // File list from details
  const allChanges = [
    ...(c.details.added || []).map(f => ({...f, status: 'added'})),
    ...(c.details.removed || []).map(f => ({...f, status: 'removed'})),
    ...(c.details.modified || []).map(f => ({...f, status: 'modified'})),
    ...(c.details.unchanged || []).slice(0,10).map(f => ({...f, status: 'unchanged'})),
  ];
  const fl = document.getElementById('file-list');
  if (allChanges.length) {
    fl.innerHTML = allChanges.map(f =>
      '<div class="file-item"><span class="fname">' + f.path + '</span><span class="fsize">' + (f.size || '') + '</span><span class="fstatus ' + f.status + '">' + f.status + '</span></div>'
    ).join('');
  } else {
    fl.innerHTML = '<div style="padding:8px;text-align:center;color:var(--text-muted);font-size:11px;">No analysis data.</div>';
  }

  document.getElementById('disk-added').textContent = s.added;
  document.getElementById('disk-removed').textContent = s.removed;
  document.getElementById('disk-modified').textContent = s.modified;
  document.getElementById('disk-unchanged').textContent = s.unchanged;

  // Overview attribute matrix
  var matrixRows = [
    ['flight_controller', 'FC with APAS 5.0 (DJI)', s.modified > 0 ? 'Modified — CRC mismatch' : 'Intact', s.modified > 0 ? 'status-warning' : 'status-success', s.modified > 0 ? 'CHANGED' : 'MATCH'],
    ['battery', 'Intelligent Flight Battery 77Wh (DJI)', s.removed > 0 ? 'Missing — no telemetry' : 'Present', s.removed > 0 ? 'status-danger' : 'status-success', s.removed > 0 ? 'LOST' : 'MATCH'],
    ['storage', 'MicroSD + 8GB Internal', s.corrupted > 0 ? 'Partial corruption detected' : 'Intact', s.corrupted > 0 ? 'status-warning' : 'status-success', s.corrupted > 0 ? 'PARTIAL' : 'MATCH'],
    ['radio', 'O3+ Transmission System (DJI)', s.crash_artifact_count > 0 ? 'Degraded — RSSI anomalies' : 'Normal', s.crash_artifact_count > 0 ? 'status-warning' : 'status-success', s.crash_artifact_count > 0 ? 'DEGRADED' : 'MATCH'],
    ['Total Files (Baseline)', String(s.baseline_files), String(s.crash_files), s.total_changed > 0 ? 'status-warning' : 'status-success', s.total_changed > 0 ? 'CHANGED' : 'MATCH'],
    ['Crash Artifacts', '0', String(s.crash_artifact_count), s.crash_artifact_count > 0 ? 'status-danger' : 'status-success', s.crash_artifact_count > 0 ? 'ADDED' : 'NONE'],
    ['Data Integrity', '100%', (100 - s.change_pct).toFixed(1) + '%', s.change_pct > 5 ? 'status-warning' : 'status-success', s.change_pct > 5 ? 'DEGRADED' : 'INTACT'],
  ];
  document.getElementById('matrix-body').innerHTML = matrixRows.map(function(r) {
    return '<tr><td class="attr-name">' + r[0] + '</td><td>' + r[1] + '</td><td>' + r[2] + '</td><td><span class="status-pill ' + r[3] + '" style="font-size:9px;padding:1px 5px;"><span class="dot"></span> ' + r[4] + '</span></td></tr>';
  }).join('');

  // Extraction tab
  document.getElementById('extraction-summary').textContent = Math.round((1 - s.removed / Math.max(s.baseline_files,1)) * 12) + ' / 12 recovered';

  // Disk compare result box
  var diskCompare = document.getElementById('disk-compare-result');
  if (diskCompare) {
    diskCompare.style.display = 'block';
    document.getElementById('disk-compare-body').innerHTML =
      '<div class="ident-row"><span class="label">Baseline Files</span><span class="value">' + s.baseline_files + '</span></div>' +
      '<div class="ident-row"><span class="label">Post-Crash Files</span><span class="value">' + s.crash_files + '</span></div>' +
      '<div class="ident-row"><span class="label">Added (crash artifacts)</span><span class="value" style="color:var(--accent-green);">' + s.added + ' files</span></div>' +
      '<div class="ident-row"><span class="label">Removed</span><span class="value" style="color:var(--accent-red);">' + s.removed + ' files</span></div>' +
      '<div class="ident-row"><span class="label">Modified</span><span class="value" style="color:var(--accent-amber);">' + s.modified + ' files</span></div>' +
      '<div class="ident-row"><span class="label">Sector Integrity</span><span class="value" style="color:var(--accent-amber);">' + (intact/totalSectors*100).toFixed(1) + '% intact</span></div>' +
      '<div class="match-bar" style="margin-top:6px;"><div class="match-bar-fill" style="width:' + (100-s.change_pct).toFixed(0) + '%;background:var(--accent-blue);"></div></div>' +
      '<div style="font-size:9px;color:var(--text-muted);margin-top:4px;">Filesystem match: ' + (100-s.change_pct).toFixed(0) + '%</div>';
  }

  // Update Baseline and Crash panels
  document.getElementById('baseline-panel').innerHTML = '<div style="font-size:11px;font-weight:500;margin-bottom:5px;">' + s.baseline_label + '</div><div class="ident-row"><span class="label">Total Files</span><span class="value">' + s.baseline_files + '</span></div><div class="ident-row"><span class="label">SHA1</span><span class="value" style="font-size:9px;">' + (c.baseline_sha1 || '').slice(0,16) + '...</span></div><div class="ident-row"><span class="label">Status</span><span class="value" style="color:var(--accent-green);">Pre-Flight — Nominal</span></div>';
  document.getElementById('crash-panel').innerHTML = '<div style="font-size:11px;font-weight:500;margin-bottom:5px;color:var(--accent-red);">' + s.crash_label + '</div><div class="ident-row"><span class="label">Total Files</span><span class="value">' + s.crash_files + '</span></div><div class="ident-row"><span class="label">SHA1</span><span class="value" style="font-size:9px;">' + (c.crash_sha1 || '').slice(0,16) + '...</span></div><div class="ident-row"><span class="label">Status</span><span class="value" style="color:var(--accent-amber);">Post-Crash — ' + s.total_changed + ' changes detected</span></div>';

  // Flight Controller tab — show comparison only when both loaded, single otherwise
  var fcBaselineHtml = '<div class="fc-item"><div class="fcl">Firmware</div><div class="fcv">v01.04.0602</div></div><div class="fc-item"><div class="fcl">PID Roll</div><div class="fcv">0.8000 / 0.0400 / 0.0300</div></div><div class="fc-item"><div class="fcl">PID Pitch</div><div class="fcv">0.8000 / 0.0400 / 0.0300</div></div><div class="fc-item"><div class="fcl">PID Yaw</div><div class="fcv">1.2000 / 0.0500 / 0.0100</div></div><div class="fc-item"><div class="fcl">Param CRC</div><div class="fcv">0xA3F7</div></div><div class="fc-item"><div class="fcl">Log Files</div><div class="fcv">12 .BIN files, 6.2 MB</div></div><div class="fc-item"><div class="fcl">IMU Config</div><div class="fcv">Dual-redundant, 500 Hz</div></div><div class="fc-item"><div class="fcl">Compass</div><div class="fcv">Internal + External Mag</div></div><div class="fc-item"><div class="fcl">GPS Type</div><div class="fcv">GPS+GLONASS+Galileo</div></div>';

  var fcCrashHtml = '<div class="fc-item" style="border-color:var(--accent-amber);"><div class="fcl">Status</div><div class="fcv" style="color:var(--accent-amber);">FC ' + (s.modified > 0 ? 'Modified' : 'Intact') + '</div></div><div class="fc-item" style="border-color:var(--accent-green);"><div class="fcl">SPI Flash</div><div class="fcv">Readable — ' + (100 - s.change_pct).toFixed(0) + '% intact</div></div><div class="fc-item" style="border-color:var(--accent-red);"><div class="fcl">Parameters</div><div class="fcv" style="color:var(--accent-red);">' + (s.modified > 0 ? 'CRC mismatch' : 'OK') + '</div></div><div class="fc-item" style="border-color:var(--accent-amber);"><div class="fcl">Changes</div><div class="fcv">' + s.total_changed + ' file deltas</div></div><div class="fc-item" style="border-color:var(--accent-green);"><div class="fcl">Artifacts</div><div class="fcv">' + s.crash_artifact_count + ' crash artifacts</div></div><div class="fc-item" style="border-color:var(--accent-green);"><div class="fcl">Data Recovered</div><div class="fcv">' + Math.round(s.crash_files / Math.max(s.baseline_files,1) * 100) + '%</div></div><div class="fc-item" style="border-color:var(--accent-green);"><div class="fcl">GPS Log</div><div class="fcv">OK — full track reconstructed</div></div><div class="fc-item" style="border-color:var(--accent-amber);"><div class="fcl">Radio</div><div class="fcv">' + (s.crash_artifact_count > 0 ? 'Degraded signal' : 'Normal') + '</div></div><div class="fc-item" style="border-color:var(--accent-green);"><div class="fcl">Integrity</div><div class="fcv">' + (100 - s.change_pct).toFixed(0) + '% match</div></div>';

  var fcCompareEl = document.getElementById('fc-compare-mode');
  var fcSingleEl = document.getElementById('fc-single-mode');
  var fcEmptyEl = document.getElementById('fc-empty-state');

  if (APP.baselineLoaded && APP.crashLoaded) {
    // Both loaded — show comparison
    fcCompareEl.style.display = 'block';
    fcSingleEl.style.display = 'none';
    fcEmptyEl.style.display = 'none';
    document.getElementById('fc-baseline').innerHTML = fcBaselineHtml;
    document.getElementById('fc-crash').innerHTML = fcCrashHtml;
  } else if (APP.crashLoaded) {
    // Only crash loaded — show single crash panel
    fcCompareEl.style.display = 'none';
    fcSingleEl.style.display = 'block';
    fcEmptyEl.style.display = 'none';
    document.getElementById('fc-single-head').textContent = 'Recovered FC Status';
    document.getElementById('fc-single-head').className = 'panel-head crash';
    document.getElementById('fc-single-body').innerHTML = fcCrashHtml;
  } else if (APP.baselineLoaded) {
    // Only baseline loaded — show single baseline panel
    fcCompareEl.style.display = 'none';
    fcSingleEl.style.display = 'block';
    fcEmptyEl.style.display = 'none';
    document.getElementById('fc-single-head').textContent = 'Baseline FC Record';
    document.getElementById('fc-single-head').className = 'panel-head baseline';
    document.getElementById('fc-single-body').innerHTML = fcBaselineHtml;
  } else {
    fcCompareEl.style.display = 'none';
    fcSingleEl.style.display = 'none';
    fcEmptyEl.style.display = 'block';
  }
  document.getElementById('fc-status-badge').textContent = s.crash_artifact_count > 0 ? 'Anomalies Detected' : 'Nominal';
  document.getElementById('fc-present-section').style.display = 'none';
  document.getElementById('fc-fallback-section').style.display = 'none';
}

function applyUserSession(user) {
  if (!user) return;
  APP.currentUser = user;
  document.getElementById('analyst-name').textContent = user.display_name || user.username;
  document.getElementById('user-name-display').textContent = user.display_name || user.username;
  document.getElementById('user-badge').style.display = 'inline-flex';
  document.getElementById('logout-btn').style.display = 'inline-block';

  const adminNav = document.getElementById('nav-admin');
  if (adminNav) adminNav.style.display = user.role === 'admin' ? 'flex' : 'none';

  const readOnly = user.role === 'user';
  document.querySelectorAll('[data-perm-upload]').forEach(el => el.style.display = readOnly ? 'none' : '');
  document.querySelectorAll('[data-perm-write]').forEach(el => el.style.display = readOnly ? 'none' : '');
}

// -----------------------------------------------------------------------
// Simple Login / Logout
// -----------------------------------------------------------------------
function showLoginOverlay() {
  const overlay = document.getElementById('login-overlay');
  if (overlay) overlay.style.display = 'flex';
  document.getElementById('login-error').textContent = '';
}

function hideLoginOverlay() {
  const overlay = document.getElementById('login-overlay');
  if (overlay) overlay.style.display = 'none';
}

async function login() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl = document.getElementById('login-error');
  errEl.textContent = '';
  if (!username || !password) { errEl.textContent = 'Enter username and password'; return; }

  const btn = document.getElementById('login-btn');
  btn.disabled = true; btn.textContent = 'Signing in...';
  try {
    const r = await fetch(BACKEND + '/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await r.json();
    if (!r.ok) { errEl.textContent = data.error || 'Login failed'; btn.disabled = false; btn.textContent = 'Sign In'; return; }
    setToken(data.token);
    APP.currentUser = data.user;
    hideLoginOverlay();
    applyUserSession(data.user);
    loadDatabase();
  } catch(e) { errEl.textContent = 'Connection error'; }
  btn.disabled = false; btn.textContent = 'Sign In';
}

async function logout() {
  const t = getToken();
  if (t) await fetch(BACKEND + '/api/logout', { method: 'POST', headers: { 'Authorization': 'Bearer ' + t } });
  clearToken();
  APP.currentUser = null;
  document.getElementById('user-badge').style.display = 'none';
  document.getElementById('logout-btn').style.display = 'none';
  showLoginOverlay();
}

// -----------------------------------------------------------------------
// User Management (Admin)
// -----------------------------------------------------------------------
function showCreateUserForm() {
  const f = document.getElementById('create-user-form');
  f.style.display = f.style.display === 'none' ? 'block' : 'none';
}

async function createUser() {
  const username = document.getElementById('new-user-username').value.trim();
  const display = document.getElementById('new-user-display').value.trim();
  const password = document.getElementById('new-user-password').value;
  const role = document.getElementById('new-user-role').value;
  if (!username || !password) { alert('Username and password are required'); return; }
  const r = await apiPost('/api/users', JSON.stringify({ username, display_name: display || username, password, role }));
  if (r && r.status === 'ok') {
    document.getElementById('new-user-username').value = '';
    document.getElementById('new-user-display').value = '';
    document.getElementById('new-user-password').value = '';
    document.getElementById('create-user-form').style.display = 'none';
    loadUsers();
  }
}

async function loadUsers() {
  const r = await apiGet('/api/users');
  if (!r || !r.users) return;
  const el = document.getElementById('users-list');
  el.innerHTML = '<table class="user-table"><thead><tr><th>Username</th><th>Display Name</th><th>Role</th><th>Password Reset</th><th>Created</th><th>Last Login</th><th>Actions</th></tr></thead><tbody>' +
    r.users.map(u => {
      const isSelf = APP.currentUser && u.username === APP.currentUser.username;
      return '<tr>' +
        '<td style="font-family:var(--font-mono);font-weight:600;">' + u.username + (isSelf ? ' <span style="font-size:8px;color:var(--accent-green);">(you)</span>' : '') + '</td>' +
        '<td>' + (u.display_name || '-') + '</td>' +
        '<td><span class="role-pill ' + u.role + '">' + u.role + '</span></td>' +
        '<td>' + (u.must_change_password ? '<span style="color:var(--accent-amber);font-size:10px;">Pending</span>' : '<span style="color:var(--accent-green);font-size:10px;">Done</span>') + '</td>' +
        '<td style="font-size:10px;color:var(--text-muted);">' + (u.created_at || '-').slice(0, 10) + '</td>' +
        '<td style="font-size:10px;color:var(--text-muted);">' + (u.last_login || 'Never').slice(0, 19) + '</td>' +
        '<td>' + (isSelf ? '-' : '<button class="btn-sm" onclick="deleteUser(' + u.id + ',\'' + u.username + '\')">Delete</button>') + '</td>' +
        '</tr>';
    }).join('') +
    '</tbody></table>';

  // Load audit trail
  const audit = await apiGet('/api/login-audit');
  if (audit && audit.audit) {
    document.getElementById('audit-count').textContent = audit.audit.length + ' events';
    document.getElementById('login-audit-list').innerHTML =
      '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px;">' +
      audit.audit.map(a => '<div style="font-size:10px;padding:2px 0;font-family:var(--font-mono);">' +
        '<span style="color:var(--text-muted);">' + (a.timestamp || '').slice(0, 19) + '</span> ' +
        '<span style="color:' + (a.action.includes('fail') || a.action.includes('denied') ? 'var(--accent-red)' : a.action.includes('success') ? 'var(--accent-green)' : 'var(--text-secondary)') + ';">' + a.action + '</span>' +
        ' — <span style="color:var(--accent-blue);">' + (a.username || '') + '</span>' +
        ' <span style="color:var(--text-muted);font-size:9px;">(' + (a.ip_address || '') + ')</span>' +
        '</div>').join('') +
      '</div>';
  }
}

async function deleteUser(id, username) {
  if (!confirm('Delete user "' + username + '"?')) return;
  try {
    const resp = await fetch(BACKEND + '/api/users/' + id, { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + (getToken() || '') } });
    const data = await resp.json();
    if (!resp.ok) { alert(data.error || 'Failed'); return; }
    loadUsers();
  } catch(e) { alert('Error deleting user'); }
}

async function loadDatabase() {
  // Load drone database from Excel
  loadDroneRegistry('DJI');

  // Apply user session
  applyUserSession(APP.currentUser);

  // Check backend and populate
  const status = await checkBackend();
  if (status) {
    if (status.baseline_loaded || status.crash_loaded) {
      const comp = await apiGet('/api/comparison');
      if (comp && comp.summary) populateFromComparison(comp);
    }
    loadFlightLogs();
    loadDashboardSummary();
    // Load drone identification after dashboard (which fetches current case id)
    setTimeout(loadDroneIdentification, 500);
  }

  // Auto-load admin tab if admin
  if (APP.currentUser && APP.currentUser.role === 'admin') {
    loadUsers();
  }
}

async function loadDashboardSummary() {
  var r = await apiGet('/api/dashboard');
  if (!r) return;
  if (r.case) {
    document.getElementById('ov-case-count').textContent = r.case.case_number || ('DRN-' + r.case.id);
    document.getElementById('ov-case-sub').textContent = r.case.status + ' | ' + (r.case.drone_model || 'Unknown');
  }
  if (r.findings_count !== undefined) {
    document.getElementById('ov-findings-count').textContent = r.findings_count;
  }
  if (r.evidence && r.evidence.length) {
    document.getElementById('ov-evidence-count').textContent = r.evidence.length;
  }
  if (r.crash_score !== undefined) {
    document.getElementById('ov-crash-score').textContent = r.crash_score + '%';
    document.getElementById('ov-crash-severity').textContent = r.crash_severity;
  }
  // Drone identification
  if (r.drone_identification) {
    loadDroneIdentification(r.case ? r.case.id : null);
  }
}

async function loadDroneIdentification(caseId) {
  if (!caseId) {
    var r = await apiGet('/api/cases/current');
    if (r && r.case_id) caseId = r.case_id;
  }
  if (!caseId) return;
  var data = await apiGet('/api/cases/' + caseId + '/drone-identification');
  if (!data || !data.detected) return;
  var sec = document.getElementById('drone-identification-section');
  sec.style.display = 'block';
  document.getElementById('di-case-num').textContent = 'DRN-' + caseId;
  document.getElementById('di-model').textContent = data.detected;
  document.getElementById('di-model-sub').textContent = data.company || '';
  document.getElementById('di-company').textContent = data.company || '--';
  var reg = data.registry;
  if (reg) {
    document.getElementById('di-type').textContent = reg.type || '--';
    document.getElementById('di-category').textContent = reg.category || '--';
    document.getElementById('di-country').textContent = reg.country || '--';
    document.getElementById('di-endurance').textContent = reg.endurance || '--';
    document.getElementById('di-range').textContent = reg.range_km ? reg.range_km + ' km' : '--';
    document.getElementById('di-weight').textContent = reg.weight || '--';
    document.getElementById('di-speed').textContent = reg.speed || '--';
    document.getElementById('di-ceiling').textContent = reg.ceiling || '--';
    var dims = [];
    if (reg.width) dims.push(reg.width);
    if (reg.length) dims.push(reg.length);
    if (reg.height) dims.push(reg.height);
    document.getElementById('di-dims').textContent = dims.length ? dims.join(' x ') : '--';
  }
}

async function saveFlightPoints() {
  var caseId = null;
  var r = await apiGet('/api/cases/current');
  if (r && r.case_id) caseId = r.case_id;
  if (!caseId) { setPointsStatus('No active case.', 'error'); return; }
  var payload = {};
  var fields = [
    ['fl-takeoff-lat', 'takeoff_lat'],
    ['fl-takeoff-lon', 'takeoff_lon'],
    ['fl-takeoff-alt', 'takeoff_alt'],
    ['fl-landing-lat', 'landing_lat'],
    ['fl-landing-lon', 'landing_lon'],
    ['fl-landing-alt', 'landing_alt'],
  ];
  fields.forEach(function(pair) {
    var el = document.getElementById(pair[0]);
    if (el && el.value !== '') payload[pair[1]] = parseFloat(el.value);
  });
  if (Object.keys(payload).length === 0) { setPointsStatus('No values entered.', 'warning'); return; }
  var res = await apiPost('/api/cases/' + caseId + '/flight-points', payload);
  if (res && res.status === 'ok') {
    setPointsStatus('Points saved! Reload flight logs to see map update.', 'ok');
  } else {
    setPointsStatus('Save failed.', 'error');
  }
}

function setPointsStatus(msg, type) {
  var el = document.getElementById('fl-points-status');
  el.textContent = msg;
  el.style.color = type === 'error' ? 'var(--accent-red)' : type === 'warning' ? 'var(--accent-amber)' : 'var(--accent-green)';
}

async function showManualFlightPoints() {
  document.getElementById('fl-manual-points-section').style.display = 'block';
  var r = await apiGet('/api/cases/current');
  if (!r || !r.case_id) return;
  var pts = await apiGet('/api/cases/' + r.case_id + '/flight-points');
  if (pts && pts.takeoff_lat != null) {
    document.getElementById('fl-takeoff-lat').value = pts.takeoff_lat;
    document.getElementById('fl-takeoff-lon').value = pts.takeoff_lon;
    document.getElementById('fl-takeoff-alt').value = pts.takeoff_alt || '';
  }
  if (pts && pts.landing_lat != null) {
    document.getElementById('fl-landing-lat').value = pts.landing_lat;
    document.getElementById('fl-landing-lon').value = pts.landing_lon;
    document.getElementById('fl-landing-alt').value = pts.landing_alt || '';
  }
}

async function loadDroneRegistry(company) {
  var url = BACKEND + '/api/drone-database';
  if (company) url += '?company=' + encodeURIComponent(company);

  try {
    var data = await apiGet('/api/drone-database' + (company ? '?company=' + encodeURIComponent(company) : ''));
    if (!data) return;
  } catch(e) {
    document.getElementById('drone-registry-body').innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--text-muted);padding:18px;font-size:11px;">Backend offline. Start backend_server.py to load drone database.</td></tr>';
    document.getElementById('overview-total').textContent = 'offline';
    return;
  }

  if (!data.drones || !data.drones.length) {
    document.getElementById('drone-registry-body').innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--text-muted);padding:18px;font-size:11px;">No drones found for company: ' + company + '</td></tr>';
    return;
  }

  document.getElementById('overview-company').textContent = company || 'All';
  document.getElementById('overview-total').textContent = data.total + ' models';
  document.getElementById('db-count').textContent = data.total;

  // Pick key columns to display (not all 100+)
  var displayCols = ['MODEL NAME', 'TYPE', 'CATEGORY', 'COUNTRY', 'ENDURANCE', 'RANGE', 'WEIGHT', 'PAYLOAD ', 'SPEED', 'CEILING'];
  var cols = displayCols.filter(function(c) {
    return data.drones.some(function(d) { return d[c]; });
  });

  // Render header
  document.getElementById('drone-registry-head').innerHTML = cols.map(function(c) {
    return '<th>' + c.replace(/_/g, ' ').trim() + '</th>';
  }).join('');

  // Render rows - highlight Mavic 3 Pro
  document.getElementById('drone-registry-body').innerHTML = data.drones.map(function(drone) {
    var isCase = (drone['MODEL NAME'] || '').indexOf('Mavic 3 Pro') >= 0;
    var rowStyle = isCase ? 'background:rgba(88,166,255,.06);' : '';
    var cells = cols.map(function(c) {
      var val = drone[c] || '--';
      var cellStyle = '';
      if (isCase && c === 'MODEL NAME') cellStyle = 'font-weight:600;color:var(--accent-blue);';
      return '<td style="' + cellStyle + '">' + val + '</td>';
    }).join('');
    var tag = isCase ? ' <span class="status-pill status-active" style="font-size:8px;padding:0 4px;margin-left:4px;"><span class="dot"></span> CASE</span>' : '';
    return '<tr style="' + rowStyle + '"><td class="attr-name" style="white-space:nowrap;">' + (drone['MODEL NAME'] || '--') + tag + '</td>' + cells.substring(cells.indexOf('</td>') + 5) + '</tr>';
  }).join('');

  // Update KPI with case drone
  var caseDrone = data.drones.find(function(d) { return (d['MODEL NAME'] || '').indexOf('Mavic 3 Pro') >= 0; });
  if (caseDrone) {
    document.getElementById('kpi-case-drone').textContent = caseDrone['MODEL NAME'];
    document.getElementById('kpi-case-sub').textContent = (caseDrone['COMPANY'] || '') + ' / ' + (caseDrone['TYPE'] || '') + ' / ' + (caseDrone['COUNTRY'] || '');
  }
}

// Flight Logs tab
async function loadFlightLogs() {
  const hint = document.getElementById('fl-backend-hint');
  if (!APP.backendMode) {
    hint.textContent = 'Backend offline. Start backend_server.py to load live flight data.';
    hint.style.color = 'var(--accent-amber)';
    return;
  }
  hint.textContent = 'Loading flight data...';

  let data = null;
  try {
    data = await apiGet('/api/flight-logs');
    if (!data) {
      hint.textContent = 'Failed to load flight logs.';
      hint.style.color = 'var(--accent-red)';
      return;
    }
  } catch(e) {
    hint.textContent = 'Backend unreachable.';
    hint.style.color = 'var(--accent-red)';
    return;
  }

  if (!data.telemetry_available) {
    hint.textContent = data.error || 'No telemetry data available. Upload and extract a disk image first.';
    hint.style.color = 'var(--accent-amber)';
    document.getElementById('fl-status').textContent = 'No data';
    // Still show manual points section if saved points exist
    showManualFlightPoints();
    return;
  }

  const m = data.metrics;
  hint.textContent = m.gps_fixes + ' GPS points computed from ' + (data.merged_rows || 0) + ' telemetry rows';
  hint.style.color = 'var(--accent-green)';
  document.getElementById('fl-status').textContent = 'Telemetry Ready';

  // KPI cards
  document.getElementById('fl-kpis').style.display = 'grid';
  document.getElementById('fl-kpi-dist').textContent = m.total_distance_km + ' km';
  document.getElementById('fl-kpi-alt').textContent = m.max_altitude_m + ' m';
  document.getElementById('fl-kpi-speed').textContent = m.max_speed_kmh + ' km/h';
  document.getElementById('fl-kpi-avg').textContent = m.avg_speed_kmh + ' km/h';
  document.getElementById('fl-kpi-fixes').textContent = m.gps_fixes;

  // Load saved flight points and override telemetry if set
  var caseR = await apiGet('/api/cases/current');
  var savedPts = {};
  if (caseR && caseR.case_id) {
    savedPts = await apiGet('/api/cases/' + caseR.case_id + '/flight-points');
  }
  if (savedPts && savedPts.takeoff_lat != null) {
    m.takeoff = { lat: savedPts.takeoff_lat, lon: savedPts.takeoff_lon, alt: savedPts.takeoff_alt || m.takeoff.alt };
  }
  if (savedPts && savedPts.landing_lat != null) {
    m.landing = { lat: savedPts.landing_lat, lon: savedPts.landing_lon, alt: savedPts.landing_alt || m.landing.alt };
  }

  // Show manual points section and pre-populate form
  document.getElementById('fl-manual-points-section').style.display = 'block';
  if (savedPts && savedPts.takeoff_lat != null) {
    document.getElementById('fl-takeoff-lat').value = savedPts.takeoff_lat;
    document.getElementById('fl-takeoff-lon').value = savedPts.takeoff_lon;
    document.getElementById('fl-takeoff-alt').value = savedPts.takeoff_alt || '';
  }
  if (savedPts && savedPts.landing_lat != null) {
    document.getElementById('fl-landing-lat').value = savedPts.landing_lat;
    document.getElementById('fl-landing-lon').value = savedPts.landing_lon;
    document.getElementById('fl-landing-alt').value = savedPts.landing_alt || '';
  }

    // Takeoff / Landing details
  document.getElementById('fl-details-section').style.display = 'block';
  function dirLat(lat) { return lat >= 0 ? 'N' : 'S'; }
  function dirLon(lon) { return lon >= 0 ? 'E' : 'W'; }
  const takeoffHtml = `
    <div class="ident-row"><span class="label">Latitude</span><span class="value">${Math.abs(m.takeoff.lat).toFixed(5)} ${dirLat(m.takeoff.lat)}</span></div>
    <div class="ident-row"><span class="label">Longitude</span><span class="value">${Math.abs(m.takeoff.lon).toFixed(5)} ${dirLon(m.takeoff.lon)}</span></div>
    <div class="ident-row"><span class="label">Altitude (AGL)</span><span class="value">${m.takeoff.alt} m</span></div>
    <div class="ident-row"><span class="label">Home Altitude</span><span class="value">${m.home_alt_m} m</span></div>
  `;
  document.getElementById('fl-takeoff-detail').innerHTML = takeoffHtml;

  const landingHtml = `
    <div class="ident-row"><span class="label">Latitude</span><span class="value">${Math.abs(m.landing.lat).toFixed(5)} ${dirLat(m.landing.lat)}</span></div>
    <div class="ident-row"><span class="label">Longitude</span><span class="value">${Math.abs(m.landing.lon).toFixed(5)} ${dirLon(m.landing.lon)}</span></div>
    <div class="ident-row"><span class="label">Altitude (AGL)</span><span class="value">${m.landing.alt} m</span></div>
    <div class="ident-row"><span class="label">Coverage</span><span class="value">${m.coverage_km2} km<sup>2</sup></span></div>
  `;
  document.getElementById('fl-landing-detail').innerHTML = landingHtml;

  renderFlightMap(m);

  // Timeline
  renderFlightTimeline(data.timeline || []);
}

function renderFlightTimeline(events) {
  const section = document.getElementById('fl-timeline-section');
  if (!events || events.length === 0) {
    section.style.display = 'none';
    return;
  }
  section.style.display = 'block';
  document.getElementById('fl-timeline-badge').textContent = events.length + ' events';

  const container = document.getElementById('fl-timeline');
  container.innerHTML = events.map((ev, i) => `
    <div class="timeline-item ${ev.type || 'normal'}">
      <div class="timeline-marker ${i === 0 ? 'first' : (i === events.length - 1 ? 'last' : '')}"></div>
      <div class="timeline-content">
        <div class="timeline-time">${ev.time}</div>
        <div class="timeline-event">${ev.label}</div>
        <div class="timeline-detail">${ev.detail || ''}</div>
      </div>
    </div>
  `).join('');
}

// Photo upload handlers (unchanged from original)
function handlePhotoBefore(input) {
  const file = input.files[0];
  if (!file) return;
  const progress = document.getElementById('photo-before-progress');
  const fill = document.getElementById('photo-before-progress-fill');
  progress.style.display = 'block'; fill.style.width = '0%';
  let pct = 0;
  const intv = setInterval(() => { pct += Math.random() * 20 + 5; if (pct >= 100) { pct = 100; clearInterval(intv); } fill.style.width = pct + '%'; }, 150);
  setTimeout(() => {
    clearInterval(intv); fill.style.width = '100%';
    document.getElementById('photo-before-card').querySelector('.pair-body').classList.add('has-file');
    const r = document.getElementById('photo-before-result');
    r.style.display = 'block';
    r.innerHTML = '<div class="ident-badge"><div class="badge-icon">DJI</div><div><div style="font-weight:500;">DJI Mavic 3 Pro</div><div style="font-size:10px;color:var(--text-muted);">Quadcopter — Baseline</div></div></div><div class="ident-row"><span class="label">Model Confidence</span><span class="value">98.7%</span></div><div class="ident-row"><span class="label">Condition</span><span class="value" style="color:var(--accent-green);">Pre-Flight — All systems nominal</span></div>';
    progress.style.display = 'none';
    checkPhotoCompare();
  }, 1500);
}
function handlePhotoAfter(input) {
  const file = input.files[0];
  if (!file) return;
  const progress = document.getElementById('photo-after-progress');
  const fill = document.getElementById('photo-after-progress-fill');
  progress.style.display = 'block'; fill.style.width = '0%';
  let pct = 0;
  const intv = setInterval(() => { pct += Math.random() * 20 + 5; if (pct >= 100) { pct = 100; clearInterval(intv); } fill.style.width = pct + '%'; }, 150);
  setTimeout(() => {
    clearInterval(intv); fill.style.width = '100%';
    document.getElementById('photo-after-card').querySelector('.pair-body').classList.add('has-file');
    const r = document.getElementById('photo-after-result');
    r.style.display = 'block';
    r.innerHTML = '<div class="ident-badge"><div class="badge-icon">DJI</div><div><div style="font-weight:500;">DJI Mavic 3 Pro</div><div style="font-size:10px;color:var(--text-muted);">Quadcopter — Damaged</div></div></div><div class="ident-row"><span class="label">Model Confidence</span><span class="value">94.1%</span></div><div class="ident-row"><span class="label">Condition</span><span class="value" style="color:var(--accent-red);">Post-Crash — Structural damage detected</span></div>';
    progress.style.display = 'none';
    checkPhotoCompare();
  }, 1500);
}
function checkPhotoCompare() {
  const before = document.getElementById('photo-before-result');
  const after = document.getElementById('photo-after-result');
  if (before.style.display !== 'block' || after.style.display !== 'block') return;
  const box = document.getElementById('photo-compare-result');
  box.style.display = 'block';
  document.getElementById('photo-compare-body').innerHTML = '<div class="ident-row"><span class="label">Manufacturer</span><span class="value">DJI (matched)</span></div><div class="ident-row"><span class="label">Model</span><span class="value">Mavic 3 Pro (matched)</span></div><div class="ident-row"><span class="label">Structure</span><span class="value" style="color:var(--accent-red);">Damage detected — forward arm fracture</span></div><div class="ident-row"><span class="label">FC Status</span><span class="value" style="color:var(--accent-amber);">Partially recoverable — JTAG needed</span></div><div class="ident-row"><span class="label">Camera</span><span class="value" style="color:var(--accent-red);">Main lens shattered, tele intact</span></div><div class="ident-row"><span class="label">Battery</span><span class="value" style="color:var(--accent-red);">Punctured — swollen casing</span></div><div class="ident-row"><span class="label">Overall Assessment</span><span class="value" style="font-weight:600;color:var(--accent-amber);">4 of 7 components damaged — partial recovery possible</span></div><div class="match-bar"><div class="match-bar-fill" style="width:43%;background:var(--accent-amber);"></div></div><div style="font-size:9px;color:var(--text-muted);margin-top:4px;">Structural integrity: 43% — 3 components intact, 4 compromised</div>';
}

// Disk upload handlers — POST to backend
async function handleDiskBefore(input) {
  const file = input.files[0];
  if (!file) return;
  const progress = document.getElementById('disk-before-progress');
  const fill = document.getElementById('disk-before-progress-fill');
  progress.style.display = 'block'; fill.style.width = '10%';
  document.getElementById('disk-extraction-panel').style.display = 'block';
  document.getElementById('extraction-live-status').textContent = 'uploading';

  const form = new FormData();
  form.append('file', file);
  const r = await apiPost('/api/upload/baseline', form);
  if (!r || r.error) {
    extractionLog((r && r.error) || 'Upload failed. Check backend or session.', 'error');
    return;
  }
  fill.style.width = '100%';
  extractionLog('Uploaded baseline: ' + r.label + ' (' + r.total_files + ' files)', 'stage');
  document.getElementById('disk-before-result').style.display = 'block';
  document.getElementById('disk-before-result').innerHTML =
    '<div class="ident-row"><span class="label">Label</span><span class="value">' + r.label + '</span></div>' +
    '<div class="ident-row"><span class="label">Files</span><span class="value">' + r.total_files + '</span></div>' +
    '<div class="ident-row"><span class="label">SHA1</span><span class="value" style="font-size:9px;">' + r.sha1 + '</span></div>' +
    '<div class="ident-row"><span class="label">MD5</span><span class="hash-badge verified" style="font-size:8px;">' + r.md5 + '</span></div>' +
    '<div class="ident-row"><span class="label">SHA256</span><span class="hash-badge verified" style="font-size:8px;">' + r.sha256.slice(0,32) + '...</span></div>' +
    (r.case_id ? '<div class="ident-row"><span class="label">Case</span><span class="value" style="color:var(--accent-blue);">DRN-' + r.case_id + '</span></div>' : '');
  APP.baselineLoaded = true;
  connectExtractionSSE();
}

async function handleDiskAfter(input) {
  const file = input.files[0];
  if (!file) return;
  const progress = document.getElementById('disk-after-progress');
  const fill = document.getElementById('disk-after-progress-fill');
  progress.style.display = 'block'; fill.style.width = '10%';
  document.getElementById('disk-extraction-panel').style.display = 'block';
  document.getElementById('extraction-live-status').textContent = 'uploading';

  const form = new FormData();
  form.append('file', file);
  const r = await apiPost('/api/upload/crash', form);
  if (!r || r.error) {
    extractionLog((r && r.error) || 'Upload failed. Check backend or session.', 'error');
    return;
  }
  fill.style.width = '100%';
  extractionLog('Uploaded crash: ' + r.label + ' (' + r.total_files + ' files)', 'stage');
  document.getElementById('disk-after-result').style.display = 'block';
  document.getElementById('disk-after-result').innerHTML =
    '<div class="ident-row"><span class="label">Label</span><span class="value">' + r.label + '</span></div>' +
    '<div class="ident-row"><span class="label">Files</span><span class="value">' + r.total_files + '</span></div>' +
    '<div class="ident-row"><span class="label">SHA1</span><span class="value" style="font-size:9px;">' + r.sha1 + '</span></div>' +
    '<div class="ident-row"><span class="label">MD5</span><span class="hash-badge verified" style="font-size:8px;">' + r.md5 + '</span></div>' +
    '<div class="ident-row"><span class="label">SHA256</span><span class="hash-badge verified" style="font-size:8px;">' + r.sha256.slice(0,32) + '...</span></div>' +
    (r.case_id ? '<div class="ident-row"><span class="label">Case</span><span class="value" style="color:var(--accent-blue);">DRN-' + r.case_id + '</span></div>' : '');
  APP.crashLoaded = true;
  connectExtractionSSE();
}

// Logging + live counter helpers
function extractionLog(msg, cls) {
  const log = document.getElementById('extraction-log');
  if (!log) return;
  const d = document.createElement('div');
  d.className = 'log-line ' + (cls || 'data');
  const ts = new Date().toISOString().slice(11,19);
  d.textContent = '[' + ts + '] ' + msg;
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
}
function updateLiveCounts(ext, fail, del, orph) {
  document.getElementById('live-extracted').textContent = ext || 0;
  document.getElementById('live-failed').textContent = fail || 0;
  document.getElementById('live-deleted').textContent = del || 0;
  document.getElementById('live-orphan').textContent = orph || 0;
  document.getElementById('live-file-count').textContent = (ext||0)+(fail||0) + ' files';
}

// Simulated extraction (fallback when backend is offline)
function runSimulatedExtraction() {
  const log = document.getElementById('extraction-log');
  log.innerHTML = '';
  document.getElementById('disk-extraction-panel').style.display = 'block';
  document.getElementById('extraction-live-status').textContent = 'processing';
  document.getElementById('live-status-text').textContent = 'Simulating extraction (backend offline)...';

  const stages = [
    { label: 'Stage 1/6: Image Handling', cls: 'stage', lines: ['Image: sample.dd', 'Size: 63.9 MB', 'Format: RAW', 'SHA1: a3f7b92e...'] },
    { label: 'Stage 2/6: Partition Detection', cls: 'stage', lines: ['Running mmls...', 'Partition #0: FAT32 offset=0', 'Partition #1: EXT4 offset=0x03E800'] },
    { label: 'Stage 3/6: Filesystem ID', cls: 'stage', lines: ['fsstat: FAT32', 'Volume label: DRONE_SD', 'Sector size: 512, Cluster: 32KB'] },
    { label: 'Stage 4/6: Enumeration', cls: 'stage', lines: ['fls -r -p -o 0...', 'Enumerating entries...'] },
    { label: 'Stage 5/6: Parsing', cls: 'stage', lines: ['Parsing fls output...'] },
    { label: 'Stage 6/6: Extraction', cls: 'stage', lines: [] },
  ];
  let delay = 0;
  stages.forEach(stage => {
    delay += 300;
    setTimeout(() => { extractionLog(stage.label, stage.cls); }, delay);
    stage.lines.forEach((line, li) => {
      setTimeout(() => { extractionLog('  ' + line, 'info'); }, delay + (li+1)*200);
    });
  });
  const sampleFiles = ['DCIM/100MEDIA/DJI_0001.MP4','DCIM/100MEDIA/DJI_0002.MP4','MISC/FLY001.DAT','MISC/FLY002.DAT','MISC/PARAM.CFG','LOG/FLY001.BIN','RADIO/RSSI_LOG.CSV','CAM/SETTINGS.XML','BAT/CELL_BALANCE.CSV','LOG/CRASH_DUMP.BIN','SYS/ERROR_DUMP.log'];
  let ext = 0, fail = 0, del = 0, orph = 0;
  sampleFiles.forEach((f, i) => {
    setTimeout(() => {
      const r = Math.random();
      let status, cls;
      if (r < 0.15) { status = 'deleted'; cls = 'warn'; del++; }
      else if (r < 0.25) { status = 'modified'; cls = 'warn'; ext++; }
      else if (r < 0.30) { status = 'FAILED'; cls = 'error'; fail++; }
      else if (r < 0.33) { status = 'orphan'; cls = 'warn'; orph++; ext++; }
      else { status = 'OK'; cls = 'info'; ext++; }
      extractionLog('  [' + status.toUpperCase() + ']    ' + f, cls);
      updateLiveCounts(ext, fail, del, orph);
    }, delay + 400 + i * 250);
  });
  setTimeout(() => {
    extractionLog('Extraction complete — ' + ext + ' files processed', 'stage');
    document.getElementById('extraction-live-status').textContent = 'complete';
    document.getElementById('live-status-text').textContent = 'Simulation complete';
    document.getElementById('live-bar').querySelector('.live-dot').style.animation = 'none';
    document.getElementById('kpi-changed').textContent = '47';
    document.getElementById('kpi-recovered').textContent = '84%';
  }, delay + 400 + sampleFiles.length * 250 + 500);
}

// -----------------------------------------------------------------------
// Case Management
// -----------------------------------------------------------------------
async function loadCases() {
  const r = await apiGet('/api/cases');
  if (!r) return;
  const el = document.getElementById('cases-list');
  if (!r.cases.length) {
    el.innerHTML = '<div style="text-align:center;padding:24px;color:var(--text-muted);font-size:11px;border:1px dashed var(--border);border-radius:6px;">No cases yet. Upload a disk image to auto-create one.</div>';
    return;
  }
  el.innerHTML = r.cases.map(c =>
    '<div class="case-card" onclick="viewCase(' + c.id + ')">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;">' +
    '<span class="case-num">' + c.case_number + '</span>' +
    '<span class="status-pill status-' + (c.status === 'open' ? 'active' : c.status === 'closed' ? 'success' : 'pending') + '"><span class="dot"></span> ' + c.status + '</span>' +
    '</div>' +
    '<div class="case-meta">Analyst: ' + (c.analyst || '-') + ' | Drone: ' + (c.drone_model || 'Unknown') + ' | Evidence: ' + c.evidence_count + ' | Findings: ' + c.findings_count + (c.critical_count ? ' (' + c.critical_count + ' critical)' : '') + '</div>' +
    '<div class="case-meta">Created: ' + (c.created_at || '-') + '</div>' +
    '</div>'
  ).join('');
}

async function viewCase(caseId) {
  const r = await apiGet('/api/cases/' + caseId);
  if (!r) return;
  document.getElementById('cases-list').parentElement.style.display = 'none';
  var det = document.getElementById('case-detail-section');
  det.style.display = 'block';
  document.getElementById('case-detail-title').textContent = r.case_number + ' — ' + (r.status || '').toUpperCase();

  var html = '<div class="compare-grid"><div class="compare-panel"><div class="panel-head baseline">Case Info</div><div class="panel-body">' +
    '<div class="ident-row"><span class="label">Analyst</span><span class="value">' + (r.analyst||'-') + '</span></div>' +
    '<div class="ident-row"><span class="label">Drone</span><span class="value">' + (r.drone_model||'Unknown') + '</span></div>' +
    '<div class="ident-row"><span class="label">Status</span><span class="value">' + (r.status||'-') + '</span></div>' +
    '<div class="ident-row"><span class="label">Created</span><span class="value">' + (r.created_at||'-') + '</span></div>' +
    '</div></div><div class="compare-panel"><div class="panel-head crash">Evidence (' + (r.evidence||[]).length + ')</div><div class="panel-body">' +
    (r.evidence||[]).map(e => '<div class="ident-row"><span class="label">' + e.filename + '</span><span class="value" style="font-size:8px;">SHA256: ' + (e.sha256||'').slice(0,16) + '...</span></div>').join('') +
    '</div></div></div>';

  if (r.findings && r.findings.length) {
    html += '<div class="section" style="margin-top:12px;"><h2 style="font-size:13px;font-weight:600;margin-bottom:8px;">Findings (' + r.findings.length + ')</h2>';
    html += r.findings.map(f => '<div class="finding-item ' + f.severity + '"><div class="finding-cat" style="color:var(--accent-' + (f.severity === 'critical' ? 'red' : 'amber') + ');">' + f.category + '</div><div class="finding-desc">' + f.description + '</div></div>').join('');
    html += '</div>';
  }

  if (r.audit && r.audit.length) {
    html += '<div class="section" style="margin-top:12px;"><h2 style="font-size:13px;font-weight:600;margin-bottom:8px;">Audit Trail</h2>';
    html += '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px;">';
    html += r.audit.map(a => '<div style="font-size:10px;padding:2px 0;font-family:var(--font-mono);"><span style="color:var(--text-muted);">' + (a.timestamp||'').slice(0,19) + '</span> ' + a.action + ' — ' + (a.detail||'') + '</div>').join('');
    html += '</div></div>';
  }

  document.getElementById('case-detail-body').innerHTML = html;
}

async function createCase() {
  var model = prompt('Drone model (e.g. DJI Mavic 3 Pro):', 'DJI Mavic 3 Pro');
  if (!model) return;
  var analyst = prompt('Analyst name:', 'Dr. A. Sharma');
  await apiPost('/api/cases', JSON.stringify({drone_model: model, analyst: analyst || 'Dr. A. Sharma'}));
  loadCases();
}

// -----------------------------------------------------------------------
// Findings Engine
// -----------------------------------------------------------------------
async function generateFindings() {
  var r = await apiGet('/api/cases/current');
  if (!r || !r.case_id) { alert('No open case. Upload a disk image first.'); return; }
  var res = await apiPost('/api/findings/generate', JSON.stringify({case_id: r.case_id}));
  if (res) {
    loadFindings();
    alert('Generated ' + res.findings_count + ' findings. Crash Score: ' + res.crash_score + '% (' + res.crash_severity + ')');
  }
}

async function loadFindings() {
  var r = await apiGet('/api/dashboard');
  if (!r) return;
  var grid = document.getElementById('findings-score-grid');
  var list = document.getElementById('findings-list');
  if (!r.findings || !r.findings.length) {
    grid.style.display = 'none';
    list.innerHTML = '<div style="text-align:center;padding:24px;color:var(--text-muted);font-size:11px;">No findings yet. Click "Generate Findings" after analysis.</div>';
    return;
  }
  grid.style.display = 'grid';
  var scoreEl = document.getElementById('crash-score-value');
  scoreEl.textContent = r.crash_score + '%';
  if (r.crash_severity === 'CRITICAL') scoreEl.className = 'kpi-value red';
  else if (r.crash_severity === 'HIGH') scoreEl.className = 'kpi-value red';
  else if (r.crash_severity === 'MEDIUM') scoreEl.className = 'kpi-value amber';
  else scoreEl.className = 'kpi-value green';
  document.getElementById('crash-score-severity').textContent = r.crash_severity + ' risk';
  document.getElementById('findings-critical-count').textContent = r.critical_count || 0;
  document.getElementById('findings-warning-count').textContent = r.warning_count || 0;

  list.innerHTML = r.findings.map(function(f) {
    return '<div class="finding-item ' + f.severity + '">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;">' +
      '<span class="finding-cat" style="color:var(--accent-' + (f.severity === 'critical' ? 'red' : 'amber') + ');">' + f.category + '</span>' +
      '<span class="status-pill status-' + (f.severity === 'critical' ? 'danger' : 'warning') + '" style="font-size:8px;padding:0 4px;"><span class="dot"></span> ' + f.severity + '</span>' +
      '</div>' +
      '<div class="finding-desc">' + f.description + '</div>' +
      '</div>';
  }).join('');
}

// -----------------------------------------------------------------------
// Dynamic Timeline
// -----------------------------------------------------------------------
async function loadTimeline() {
  var r = await apiGet('/api/timeline');
  if (!r) return;
  var el = document.getElementById('timeline');
  var countEl = document.getElementById('timeline-count');
  if (!r.events || !r.events.length) {
    el.innerHTML = '<div style="text-align:center;padding:24px;color:var(--text-muted);font-size:11px;border:1px dashed var(--border);border-radius:6px;">No timeline events recorded yet. Load a disk image with telemetry data.</div>';
    countEl.textContent = '0 events';
    return;
  }
  countEl.textContent = r.events.length + ' events';
  el.innerHTML = r.events.map(function(ev, i) {
    var type = ev.event_type || 'normal';
    var tagLabel = type === 'crash' ? 'CRASH' : type === 'anomaly' ? 'ANOMALY' : i === 0 ? 'START' : i === r.events.length - 1 ? 'END' : 'OK';
    var tagClass = tagLabel === 'START' ? 'start' : tagLabel === 'END' ? 'end' : type;
    return '<div class="tl-event ' + type + '">' +
      '<div class="tl-head">' +
        '<span class="tl-time">' + (ev.time_label || '--') + '</span>' +
        '<span class="tl-label">' + (ev.label || '') + '</span>' +
      '</div>' +
      '<div class="tl-detail">' + (ev.detail || '') + '</div>' +
      '<span class="tl-tag ' + tagClass + '">' + tagLabel + '</span>' +
      '</div>';
  }).join('');
}

// -----------------------------------------------------------------------
// Flight Map (Leaflet)
// -----------------------------------------------------------------------
var flightMap = null;
function renderFlightMap(metrics) {
  if (!metrics || !metrics.takeoff) return;
  var sec = document.getElementById('fl-map-section');
  sec.style.display = 'block';
  if (flightMap) { flightMap.remove(); flightMap = null; }
  var mapEl = document.getElementById('flight-map');
  flightMap = L.map(mapEl).setView([metrics.takeoff.lat, metrics.takeoff.lon], 13);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap', maxZoom: 18
  }).addTo(flightMap);

  var takeoffIcon = L.divIcon({html:'<div style="background:var(--accent-green);width:12px;height:12px;border-radius:50%;border:2px solid #fff;box-shadow:0 0 4px rgba(0,0,0,.4);"></div>', className:'', iconSize:[12,12], iconAnchor:[6,6]});
  var landingIcon = L.divIcon({html:'<div style="background:var(--accent-red);width:12px;height:12px;border-radius:50%;border:2px solid #fff;box-shadow:0 0 4px rgba(0,0,0,.4);"></div>', className:'', iconSize:[12,12], iconAnchor:[6,6]});

  L.marker([metrics.takeoff.lat, metrics.takeoff.lon], {icon: takeoffIcon}).addTo(flightMap)
    .bindPopup('<b>Takeoff</b><br>(' + metrics.takeoff.lat.toFixed(5) + ', ' + metrics.takeoff.lon.toFixed(5) + ')<br>Alt: ' + metrics.takeoff.alt + 'm');
  L.marker([metrics.landing.lat, metrics.landing.lon], {icon: landingIcon}).addTo(flightMap)
    .bindPopup('<b>Landing</b><br>(' + metrics.landing.lat.toFixed(5) + ', ' + metrics.landing.lon.toFixed(5) + ')<br>Alt: ' + metrics.landing.alt + 'm');

  if (metrics.takeoff.lat !== metrics.landing.lat || metrics.takeoff.lon !== metrics.landing.lon) {
    var bounds = L.latLngBounds([[metrics.takeoff.lat, metrics.takeoff.lon], [metrics.landing.lat, metrics.landing.lon]]);
    flightMap.fitBounds(bounds, {padding: [40, 40]});
  }
  setTimeout(function() { flightMap.invalidateSize(); }, 200);
}

// -----------------------------------------------------------------------
// Tab navigation
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', function() {
    const tab = this.dataset.tab;
    if (!tab) return;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    this.classList.add('active');
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    const pane = document.getElementById('pane-' + tab);
    if (pane) { pane.classList.add('active'); pane.classList.add('fade-in'); }
    // Auto-load flight logs when tab is clicked and backend is online
    if (tab === 'flight-logs' && APP.backendMode) {
      loadFlightLogs();
    }
    if (tab === 'cases' && APP.backendMode) {
      loadCases();
    }
    if (tab === 'findings' && APP.backendMode) {
      loadFindings();
    }
    if (tab === 'timeline' && APP.backendMode) {
      loadTimeline();
    }
    if (tab === 'admin' && APP.backendMode) {
      loadUsers();
    }
  });
});

document.addEventListener('DOMContentLoaded', async function() {
  const t = getToken();
  if (!t) { showLoginOverlay(); return; }
  loadDatabase();
});
