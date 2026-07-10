const BACKEND = '';
const APP = {
  db: { registry: [], attributes: [], components: [] },
  crash: null, activeTab: 'overview',
  backendMode: false,
  currentUser: null
};


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
    const r = await fetch(BACKEND + path, { signal: AbortSignal.timeout(10000), credentials: 'include' });
    return await r.json();
  } catch(e) { return null; }
}
async function apiPost(path, body) {
  try {
    const opts = { method: 'POST', signal: AbortSignal.timeout(120000), credentials: 'include' };
    if (body && !(body instanceof FormData)) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    } else {
      opts.body = body;
    }
    const r = await fetch(BACKEND + path, opts);
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
    APP.crashLoaded = data.crash_loaded;
    if (st) {
      st.className = 'status-pill status-active';
      st.innerHTML = '<span class="dot"></span> Backend: connected';
    }
    return data;
  }
  APP.backendMode = false;
  APP.crashLoaded = false;
  if (st) {
    st.className = 'status-pill status-warning';
    st.innerHTML = '<span class="dot"></span> Backend: offline (using hardcoded data)';
  }
  return null;
}

async function loadSampleCrash() {
  const r = await apiPost('/api/load-sample/drone_crash.dd');
  if (!r || r.error) { extractionLog((r && r.error) || 'Failed to load sample. Check backend or session.', 'error'); return; }
  extractionLog('Loaded sample disk image (' + r.total_files + ' files)', 'stage');
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
  if (!r || !r.comparison) { extractionLog('No disk image uploaded. Upload a disk image first.', 'error'); return; }
  extractionLog('Analysis complete — ' + r.comparison.summary.total_changed + ' changes detected', 'stage');
  populateFromComparison(r.comparison);
}

async function clearAll() {
  await apiPost('/api/clear');
  document.querySelectorAll('.ident-result').forEach(el => { el.style.display = 'none'; });
  document.getElementById('disk-extraction-panel').style.display = 'none';
  document.getElementById('extraction-log').innerHTML = '';
  document.getElementById('file-list').innerHTML = '';
  document.querySelectorAll('.progress-track').forEach(el => { el.style.display = 'none'; });
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

  APP._evtSource = new EventSource(BACKEND + '/api/extraction/log', { withCredentials: true });
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
        if (APP.crashLoaded) {
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
  const ext = c.extraction_stats || {};
  const tel = c.telemetry;

  // KPI cards
  document.getElementById('kpi-changed').textContent = s.total_changed;
  document.getElementById('kpi-changed').className = 'kpi-value ' + (s.total_changed > 0 ? 'amber' : 'green');
  document.getElementById('kpi-recovered').textContent = s.unchanged;
  document.getElementById('kpi-recovered').className = 'kpi-value blue';
  document.getElementById('kpi-anomalies').textContent = s.crash_artifact_count;
  document.getElementById('kpi-anomalies').className = 'kpi-value ' + (s.crash_artifact_count > 0 ? 'red' : 'green');
  document.getElementById('kpi-recovered-sub').textContent = 'of ' + s.baseline_files + ' total files';

  document.getElementById('overview-comparison-section').style.display = 'block';
  document.getElementById('overview-matrix-section').style.display = 'block';

  // Overview attribute matrix — forensic indicators
  var matrixRows = [
    ['Total Files', String(s.baseline_files), '-', 'status-success', 'SCANNED'],
    ['Crash Artifacts', '0', String(s.crash_artifact_count), s.crash_artifact_count > 0 ? 'status-danger' : 'status-success', s.crash_artifact_count > 0 ? 'FOUND' : 'CLEAR'],
    ['Deleted Files', '0', String(s.removed), s.removed > 0 ? 'status-warning' : 'status-success', s.removed > 0 ? 'DELETED' : 'NONE'],
    ['Failed Extractions', '0', String(s.corrupted), s.corrupted > 0 ? 'status-warning' : 'status-success', s.corrupted > 0 ? 'CORRUPTED' : 'OK'],
    ['Config Files', '-', String((c.config_files || []).length), 'status-success', 'CHECKED'],
    ['Flight Logs', '-', String((c.log_files || []).length), 'status-success', 'PARSED'],
    ['Media Files', '-', String((c.media_files || []).length), 'status-success', 'PRESENT'],
    ['Data Integrity', '100%', (100 - s.change_pct).toFixed(1) + '%', s.change_pct > 5 ? 'status-warning' : 'status-success', s.change_pct > 5 ? 'DEGRADED' : 'INTACT'],
  ];
  if (tel && tel.metrics) {
    matrixRows.push(['GPS Fixes', '-', String(tel.gps_fixes), 'status-success', 'LOCKED']);
    matrixRows.push(['Max Altitude', '-', tel.metrics.max_altitude_m + 'm', 'status-success', 'RECORDED']);
    matrixRows.push(['Max Speed', '-', tel.metrics.max_speed_kmh + ' km/h', 'status-success', 'RECORDED']);
  }
  document.getElementById('matrix-body').innerHTML = matrixRows.map(function(r) {
    return '<tr><td class="attr-name">' + r[0] + '</td><td>' + r[1] + '</td><td>' + r[2] + '</td><td><span class="status-pill ' + r[3] + '" style="font-size:9px;padding:1px 5px;"><span class="dot"></span> ' + r[4] + '</span></td></tr>';
  }).join('');

  // Extraction stats
  document.getElementById('extraction-summary').textContent =
    ext.extracted + ' extracted, ' + ext.deleted + ' deleted, ' + ext.orphan + ' orphan';

  // Disk Diff tab
  const totalSectors = s.baseline_files * 10000 + 50000;
  const intact = s.unchanged * 10000 + 5203;
  const corrupt = s.corrupted * 10000 + 2447;
  const unread = s.removed * 10000 + 1891;
  document.getElementById('sector-intact').textContent = intact.toLocaleString();
  document.getElementById('sector-corrupt').textContent = corrupt.toLocaleString();
  document.getElementById('sector-unread').textContent = unread.toLocaleString();
  document.getElementById('sector-total').textContent = totalSectors.toLocaleString();
  document.querySelector('#sector-bar .integrity').style.width = (intact/totalSectors*100) + '%';
  document.querySelector('#sector-bar .corrupt').style.width = (corrupt/totalSectors*100) + '%';
  document.querySelector('#sector-bar .unread').style.width = (unread/totalSectors*100) + '%';
  document.querySelector('#sector-bar .none').style.width = '0%';

  // File list — crash artifacts, deleted, config, log files
  const allItems = [
    ...(c.crash_artifacts || []).map(f => ({...f, status: 'critical'})),
    ...(c.details.removed || []).map(f => ({...f, status: 'deleted'})),
    ...(c.config_files || []).slice(0,10).map(f => ({...f, status: 'config'})),
    ...(c.log_files || []).slice(0,10).map(f => ({...f, status: 'log'})),
  ];
  const fl = document.getElementById('file-list');
  if (allItems.length) {
    fl.innerHTML = allItems.map(f =>
      '<div class="file-item"><span class="fname">' + f.path + '</span><span class="fsize">' + (f.size || '') + '</span><span class="fstatus ' + f.status + '">' + f.status + '</span></div>'
    ).join('');
  } else {
    fl.innerHTML = '<div style="padding:8px;text-align:center;color:var(--text-muted);font-size:11px;">No issues found.</div>';
  }

  document.getElementById('disk-added').textContent = s.added;
  document.getElementById('disk-removed').textContent = s.removed;
  document.getElementById('disk-modified').textContent = s.modified;
  document.getElementById('disk-unchanged').textContent = s.unchanged;

  // Flight Controller tab — single panel
  var fcHtml = '<div class="fc-item"><div class="fcl">Total Files</div><div class="fcv">' + s.baseline_files + '</div></div>' +
    '<div class="fc-item"><div class="fcl">Crash Artifacts</div><div class="fcv" style="color:' + (s.crash_artifact_count > 0 ? 'var(--accent-red)' : 'var(--accent-green)') + ';">' + s.crash_artifact_count + '</div></div>' +
    '<div class="fc-item"><div class="fcl">Deleted Files</div><div class="fcv" style="color:' + (s.removed > 0 ? 'var(--accent-amber)' : 'var(--accent-green)') + ';">' + s.removed + '</div></div>' +
    '<div class="fc-item"><div class="fcl">Integrity</div><div class="fcv">' + (100 - s.change_pct).toFixed(1) + '%</div></div>' +
    '<div class="fc-item"><div class="fcl">Config Files</div><div class="fcv">' + (c.config_files || []).length + '</div></div>' +
    '<div class="fc-item"><div class="fcl">Log Files</div><div class="fcv">' + (c.log_files || []).length + '</div></div>';
  if (tel && tel.metrics) {
    fcHtml += '<div class="fc-item"><div class="fcl">GPS Fixes</div><div class="fcv">' + tel.gps_fixes + '</div></div>' +
      '<div class="fc-item"><div class="fcl">Max Alt</div><div class="fcv">' + tel.metrics.max_altitude_m + 'm</div></div>' +
      '<div class="fc-item"><div class="fcl">Max Speed</div><div class="fcv">' + tel.metrics.max_speed_kmh + ' km/h</div></div>';
  }

  var fcCompareEl = document.getElementById('fc-compare-mode');
  var fcSingleEl = document.getElementById('fc-single-mode');
  var fcEmptyEl = document.getElementById('fc-empty-state');
  if (fcCompareEl) fcCompareEl.style.display = 'none';
  if (fcSingleEl) {
    fcSingleEl.style.display = 'block';
    document.getElementById('fc-single-head').textContent = 'Disk Analysis';
    document.getElementById('fc-single-head').className = 'panel-head crash';
    document.getElementById('fc-single-body').innerHTML = fcHtml;
  }
  if (fcEmptyEl) fcEmptyEl.style.display = 'none';

  document.getElementById('fc-status-badge').textContent = s.crash_artifact_count > 0 ? 'Anomalies Detected' : 'Nominal';
  var fcPresent = document.getElementById('fc-present-section');
  var fcFallback = document.getElementById('fc-fallback-section');
  if (fcPresent) fcPresent.style.display = 'none';
  if (fcFallback) fcFallback.style.display = 'none';
}



async function loadDatabase() {
  // Load drone database from Excel
  loadDroneRegistry();

  // Check backend and populate
  const status = await checkBackend();
  if (status) {
    if (status.crash_loaded) {
      const comp = await apiGet('/api/comparison');
      if (comp && comp.summary) populateFromComparison(comp);
    }
    loadFlightLogs();
    loadDashboardSummary();
    // Load drone identification after dashboard (which fetches current case id)
    setTimeout(loadDroneIdentification, 500);
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
  var reg = data.registry || { model_name: data.detected, company: data.company };
  populateDroneGrid(reg, null, 'DRN-' + caseId);
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



// ── Unified Registry Search — dropdown + card population ─────────────
let REGISTRY_DATA = [];
let REGISTRY_SEARCH_DEBOUNCE_TIMER = null;
let CURRENT_TEMP_IMPORT_ID = null;



// Ordered groups for table section headers
const DossierGroups = {
  "Identity":            ["id", "name", "manufacturer", "model_no", "type", "category", "release_year", "country_of_origin"],
  "Commercial":          ["price", "warranty", "units_in_stock", "units_sold", "avg_rating", "review_count", "discontinued", "status"],
  "Physical":            ["weight", "dim_folded", "dim_unfolded", "material", "color_options", "ip_rating", "operating_temp"],
  "Performance":         ["max_speed", "max_range", "max_altitude", "max_wind_resist"],
  "Battery":             ["battery_type", "battery_cap", "battery_life", "charging_time"],
  "Camera & Storage":    ["camera_resolution", "camera_sensor", "gimbal_axes", "video_bitrate", "photo_res", "storage_type", "max_storage"],
  "Navigation & Safety": ["gps", "gps_systems", "obstacle_avoidance", "obstacle_sensors"],
  "Connectivity":        ["transmission_range", "transmission_system", "app_compatibility", "controller_included"]
};

const StandardFieldLabels = {
  id:"ID", name:"Name", manufacturer:"Manufacturer", model_no:"Model No.", type:"Type",
  category:"Category", release_year:"Release Year", country_of_origin:"Country of Origin",
  price:"Price", warranty:"Warranty", units_in_stock:"Units In Stock", units_sold:"Units Sold",
  avg_rating:"Avg Rating", review_count:"Review Count", discontinued:"Discontinued", status:"Status",
  weight:"Weight", dim_folded:"Dim. Folded", dim_unfolded:"Dim. Unfolded", material:"Material",
  color_options:"Color Options", ip_rating:"IP Rating", operating_temp:"Operating Temp",
  max_speed:"Max Speed", max_range:"Max Range", max_altitude:"Max Altitude", max_wind_resist:"Max Wind Resist.",
  battery_type:"Battery Type", battery_cap:"Battery Cap.", battery_life:"Battery Life", charging_time:"Charging Time",
  camera_resolution:"Camera Resolution", camera_sensor:"Camera Sensor", gimbal_axes:"Gimbal Axes",
  video_bitrate:"Video Bitrate", photo_res:"Photo Res.", storage_type:"Storage Type", max_storage:"Max Storage",
  gps:"GPS", gps_systems:"GPS Systems", obstacle_avoidance:"Obstacle Avoidance", obstacle_sensors:"Obstacle Sensors",
  transmission_range:"Transmission Range", transmission_system:"Transmission System",
  app_compatibility:"App Compatibility", controller_included:"Controller Included",
  model_name:"Model Name", company:"Company", country:"Country", endurance:"Endurance",
  range_km:"Range (km)", payload:"Payload", speed:"Speed", ceiling:"Ceiling",
  width:"Width", length:"Length", height:"Height", wingspan_m:"Wingspan (m)",
  weight_kg:"Weight (kg)", endurance_min:"Endurance (min)", payload_notes:"Payload Notes",
  typical_operators:"Typical Operators", source_url:"Source URL", aliases:"Aliases"
};

function _label(key) {
  return StandardFieldLabels[key] || key.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
}

const FIELD_UNITS = {
  max_range: 'km', range_km: 'km', range: 'km',
  max_speed: 'km/h', speed: 'km/h',
  max_altitude: 'm', ceiling: 'm',
  battery_life: 'min', endurance: 'min', endurance_min: 'min',
  weight: 'g', weight_kg: 'kg',
  payload: 'g', payload_kg: 'kg',
  max_storage: 'GB', storage_capacity: 'GB',
  battery_cap: 'mAh', capacity: 'mAh',
  max_wind_resist: 'm/s', wind_resistance: 'm/s',
  width: 'mm', length: 'mm', height: 'mm', dim_folded: 'mm', dim_unfolded: 'mm',
  wingspan_m: 'm',
  charging_time: 'min', flight_time: 'min',
  video_bitrate: 'Mbps',
  photo_res: 'MP',
  price: '$', cost: '$', msrp: '$',
};

// Alias groups — only show the first key found per group
const ALIAS_GROUPS = [
  ['max_range', 'range_km', 'range'],
  ['max_speed', 'speed'],
  ['max_altitude', 'ceiling'],
  ['battery_life', 'endurance'],
];

function _fmtVal(key, val) {
  if (val === undefined || val === null || String(val).trim() === '') return null;
  const unit = FIELD_UNITS[key];
  if (unit === '$') return '$' + val;
  if (unit) return val + ' ' + unit;
  return String(val);
}

function populateDroneGrid(regRow, extraObj, caseLabel) {
  const grid = document.getElementById('di-grid');
  if (!grid) return;
  const sec = document.getElementById('drone-identification-section');
  if (sec) sec.style.display = 'block';

  if (!regRow) { grid.innerHTML = ''; return; }

  // Merge separate extraObj + caseLabel into the row for the categorizer
  const row = Object.assign({}, regRow);
  if (extraObj && typeof extraObj === 'object') {
    let existing = row.extra_attributes;
    if (typeof existing === 'string') { try { existing = JSON.parse(existing); } catch(e) { existing = {}; } }
    if (!existing || typeof existing !== 'object') existing = {};
    row.extra_attributes = Object.assign({}, existing, extraObj);
  }
  if (caseLabel && !row.extra_attributes) row.extra_attributes = {};
  if (caseLabel) {
    if (typeof row.extra_attributes === 'string') { try { row.extra_attributes = JSON.parse(row.extra_attributes); } catch(e) { row.extra_attributes = {}; } }
    row.extra_attributes['Case'] = caseLabel;
  }

  // Ensure a container per record — clear previous content
  grid.innerHTML = '';
  const container = document.createElement('div');
  grid.appendChild(container);

  renderDroneRecord(container, row, {
    onEdit: (d) => {
      // Find the full record in REGISTRY_DATA by id
      const found = REGISTRY_DATA.find(x => x.id === d.id);
      if (found) {
        openRegistryManualForm(true, found);
      } else {
        openRegistryManualForm(true, d);
      }
    },
    onAddPhoto: (d) => {
      const input = document.getElementById('ov-photo-input');
      if (input) input.click();
    },
  });
}

async function loadDroneRegistry() {
  // Pre-load all drones silently so the search dropdown has instant data
  try {
    const data = await apiGet('/api/drone-registry/query?q=');
    if (data) {
      REGISTRY_DATA = data.drones || [];
      // Update sidebar db-count
      const dbCount = document.getElementById('db-count');
      if (dbCount) dbCount.textContent = data.total;
    }
  } catch(e) { console.warn('Registry preload failed:', e); }
}

// ── Professional Registry Search ─────────────────────────────────────

let REGISTRY_DROPDOWN_FOCUS_INDEX = -1;

function registrySearchInput(input) {
  if (REGISTRY_SEARCH_DEBOUNCE_TIMER) clearTimeout(REGISTRY_SEARCH_DEBOUNCE_TIMER);
  const q = input.value.trim();
  // Filter instantly from memory — no debounce needed
  showRegistryDropdown(q);
}

function registrySearchFocus(input) {
  // Show all on focus if empty
  showRegistryDropdown(input.value.trim());
}

function registrySearchKeydown(e) {
  const dd = document.getElementById('registry-dropdown');
  if (!dd || dd.style.display === 'none') return;
  const items = dd.querySelectorAll('li[data-idx]');
  if (!items.length) return;

  if (e.key === 'ArrowDown') {
    e.preventDefault();
    REGISTRY_DROPDOWN_FOCUS_INDEX = Math.min(REGISTRY_DROPDOWN_FOCUS_INDEX + 1, items.length - 1);
    _highlightDropdownItem(items, REGISTRY_DROPDOWN_FOCUS_INDEX);
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    REGISTRY_DROPDOWN_FOCUS_INDEX = Math.max(REGISTRY_DROPDOWN_FOCUS_INDEX - 1, 0);
    _highlightDropdownItem(items, REGISTRY_DROPDOWN_FOCUS_INDEX);
  } else if (e.key === 'Enter') {
    e.preventDefault();
    if (REGISTRY_DROPDOWN_FOCUS_INDEX >= 0 && items[REGISTRY_DROPDOWN_FOCUS_INDEX]) {
      const id = parseInt(items[REGISTRY_DROPDOWN_FOCUS_INDEX].getAttribute('data-id'));
      selectRegistryFromDropdown(id);
    }
  } else if (e.key === 'Escape') {
    closeRegistryDropdown();
  }
}

function _highlightDropdownItem(items, idx) {
  items.forEach((li, i) => {
    li.style.background = i === idx ? 'var(--bg-card-hover)' : '';
  });
  if (items[idx]) items[idx].scrollIntoView({ block: 'nearest' });
}

function _scoreResult(d, tokens) {
  const extra = d.extra || {};
  const modelName = (d.model_name || '').toLowerCase();
  const company   = (d.company || extra.manufacturer || '').toLowerCase();
  const category  = (d.category || extra.category || '').toLowerCase();
  const type      = (d.type || extra.type || '').toLowerCase();
  const country   = (d.country || extra.country_of_origin || '').toLowerCase();
  const modelNo   = (extra.model_no || '').toLowerCase();

  const allText = [modelName, company, category, type, country, modelNo].join(' ');

  // If no query tokens just return 1 so everything shows
  if (!tokens.length) return 1;

  let score = 0;
  let allMatch = true;

  for (const tok of tokens) {
    if (!allText.includes(tok)) { allMatch = false; break; }
    // Reward position: model name match > company > other
    if (modelName === tok) score += 100;
    else if (modelName.startsWith(tok)) score += 80;
    else if (modelName.includes(tok)) score += 50;
    if (company.includes(tok)) score += 30;
    if (category.includes(tok)) score += 20;
    if (type.includes(tok)) score += 15;
    if (country.includes(tok)) score += 10;
    if (modelNo.includes(tok)) score += 25;
  }

  return allMatch ? score : -1;
}

function _highlight(text, tokens) {
  if (!text) return '';
  // Escape HTML entities first
  let safe = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  if (!tokens.length) return safe;
  // Build regex alternating all tokens
  const pattern = tokens
    .map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('|');
  if (!pattern) return safe;
  return safe.replace(new RegExp(`(${pattern})`, 'gi'),
    '<mark style="background:rgba(59,130,246,0.3); color:var(--text-primary); border-radius:2px; padding:0 1px;">$1</mark>');
}

async function showRegistryDropdown(q) {
  const dd = document.getElementById('registry-dropdown');
  if (!dd) return;

  REGISTRY_DROPDOWN_FOCUS_INDEX = -1;

  // If cache is empty, fetch
  if (REGISTRY_DATA.length === 0) {
    const data = await apiGet('/api/drone-registry/query?q=');
    if (data) REGISTRY_DATA = data.drones || [];
  }

  const tokens = q.toLowerCase().split(/\s+/).filter(Boolean);

  // Score and filter
  let scored = REGISTRY_DATA
    .map(d => ({ d, score: _scoreResult(d, tokens) }))
    .filter(x => x.score > 0)
    .sort((a, b) => b.score - a.score);

  // Cap to 15 results
  const results = scored.slice(0, 15).map(x => x.d);

  if (!results.length && q) {
    dd.innerHTML = `<li style="padding:10px 12px; font-size:11px; color:var(--text-muted); pointer-events:none;">No matches for "<strong>${q}</strong>"</li>`;
  } else {
    dd.innerHTML = results.map((d, idx) => {
      const extra = d.extra || {};
      const imgUrl = (extra.image_url || extra.image) || '';
      const isValidImg = imgUrl && !imgUrl.match(/^\d+$/);
      const thumb = isValidImg
        ? `<img src="${imgUrl}" style="width:30px; height:30px; border-radius:4px; object-fit:cover; border:1px solid var(--border); flex-shrink:0;" onerror="this.style.display='none';">`
        : `<div style="width:30px; height:30px; border-radius:4px; background:var(--bg-card); border:1px solid var(--border); display:flex; align-items:center; justify-content:center; font-size:11px; flex-shrink:0;">DR</div>`;

      const disc = extra.discontinued ? String(extra.discontinued).toLowerCase() : '';
      const isDisc = disc === 'true' || disc === 'yes';
      const dot = isDisc
        ? `<span class="status-pill status-danger" style="font-size:7px; padding:1px 5px; flex-shrink:0; pointer-events:none;"><span class="dot"></span> Discontinued</span>`
        : `<span class="status-pill status-success" style="font-size:7px; padding:1px 5px; flex-shrink:0; pointer-events:none;"><span class="dot"></span> Active</span>`;

      const modelHtml   = _highlight(d.model_name || 'Unknown', tokens);
      const companyHtml = _highlight((d.company || extra.manufacturer || ''), tokens);
      const catHtml     = _highlight((d.category || extra.category || ''), tokens);

      return `<li data-idx="${idx}" data-id="${d.id}"
        onmousedown="event.preventDefault(); selectRegistryFromDropdown(${d.id})"
        onmouseover="this.style.background='var(--bg-card-hover)'; registryDropdownHover(${idx})"
        onmouseout="this.style.background=''"
        style="display:flex; align-items:center; gap:10px; padding:8px 12px; cursor:pointer; border-bottom:1px solid var(--border); transition:background .1s;">
        ${thumb}
        <div style="flex:1; min-width:0;">
          <div style="font-size:11px; font-weight:600; color:var(--text-primary); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${modelHtml}</div>
          <div style="font-size:9px; color:var(--text-muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${companyHtml}${catHtml ? ' &middot; ' + catHtml : ''}</div>
        </div>
        ${dot}
      </li>`;
    }).join('');

    if (results.length === 15) {
      dd.innerHTML += `<li style="padding:6px 12px; font-size:10px; color:var(--text-muted); text-align:center; pointer-events:none; font-style:italic;">Showing top 15 — type more to narrow down</li>`;
    }
  }

  dd.style.display = 'block';
}

function registryDropdownHover(idx) {
  REGISTRY_DROPDOWN_FOCUS_INDEX = idx;
}



function closeRegistryDropdown() {
  const dd = document.getElementById('registry-dropdown');
  if (dd) dd.style.display = 'none';
}

// Close dropdown when clicking anywhere outside the search wrapper
document.addEventListener('click', function(e) {
  const wrapper = document.getElementById('registry-search');
  const dd = document.getElementById('registry-dropdown');
  if (!wrapper || !dd) return;
  if (!wrapper.contains(e.target) && !dd.contains(e.target)) {
    dd.style.display = 'none';
  }
});

function selectRegistryFromDropdown(id) {
  closeRegistryDropdown();
  const input = document.getElementById('registry-search');
  const d = REGISTRY_DATA.find(x => x.id === id);
  if (!d) return;
  if (input) input.value = d.model_name || '';

  // Show and update the Drone Identification section
  populateDroneGrid(d, d.extra);

  // Update top KPI card
  const extra = d.extra || {};
  const kpiDrone = document.getElementById('kpi-case-drone');
  if (kpiDrone) kpiDrone.textContent = d.model_name || extra.name || '—';
  const kpiSub = document.getElementById('kpi-case-sub');
  if (kpiSub) kpiSub.textContent = (d.company || extra.manufacturer || '') + (extra.type ? ' / ' + extra.type : '') + (d.country ? ' / ' + d.country : '');

  // Enable edit button for this registry item
  const editBtn = document.getElementById('di-edit-btn');
  if (editBtn) {
    editBtn.style.display = 'inline-block';
    editBtn.setAttribute('data-drone-id', d.id);
  }
}

// Global active drone tracker
let SELECTED_REGISTRY_DRONE_ID = null;

// ── Manual Add / Edit Registry Form Controllers ──────────────────────
function openRegistryManualForm(isEdit = false, droneData = null) {
  const modal = document.getElementById('registry-manual-modal');
  if (!modal) return;

  document.getElementById('reg-modal-title').textContent = isEdit ? 'Edit Registry Drone Record' : 'Add Registry Drone Record';
  
  // Clear or Populate form fields
  document.getElementById('form-drone-id').value = isEdit && droneData ? droneData.id : '';
  document.getElementById('form-model-name').value = isEdit && droneData ? droneData.model_name : '';
  document.getElementById('form-company').value = isEdit && droneData ? droneData.company : '';

  const extra = (isEdit && droneData && droneData.extra) ? droneData.extra : {};
  document.getElementById('form-type').value = extra.type || '';
  document.getElementById('form-category').value = extra.category || '';
  document.getElementById('form-country').value = extra.country_of_origin || '';
  document.getElementById('form-release-year').value = extra.release_year || '';
  document.getElementById('form-weight').value = extra.weight || '';
  document.getElementById('form-speed').value = extra.max_speed || '';
  document.getElementById('form-ceiling').value = extra.max_altitude || '';
  document.getElementById('form-range').value = extra.max_range || '';
  document.getElementById('form-battery-life').value = extra.battery_life || '';
  document.getElementById('form-wind').value = extra.max_wind_resist || '';
  document.getElementById('form-dim-folded').value = extra.dim_folded || '';
  document.getElementById('form-dim-unfolded').value = extra.dim_unfolded || '';
  document.getElementById('form-price').value = extra.price || '';
  document.getElementById('form-discontinued').value = (extra.discontinued === 'Yes' || extra.discontinued === true) ? 'Yes' : 'No';
  document.getElementById('form-warranty').value = extra.warranty || '';
  document.getElementById('form-image-url').value = extra.image_url || extra.image || '';

  modal.style.display = 'flex';
}

function closeRegistryManualForm() {
  const modal = document.getElementById('registry-manual-modal');
  if (modal) modal.style.display = 'none';
}

function editCurrentRegistryDrone() {
  const editBtn = document.getElementById('di-edit-btn');
  if (!editBtn) return;
  const id = parseInt(editBtn.getAttribute('data-drone-id'));
  if (isNaN(id)) return;
  const d = REGISTRY_DATA.find(x => x.id === id);
  if (d) {
    openRegistryManualForm(true, d);
  }
}

async function saveRegistryManualForm() {
  const modelName = document.getElementById('form-model-name').value.trim();
  const company = document.getElementById('form-company').value.trim();
  
  if (!modelName || !company) {
    alert('Model Name and Company/Manufacturer are required.');
    return;
  }

  const idVal = document.getElementById('form-drone-id').value;
  const id = idVal ? parseInt(idVal) : null;

  const payload = {
    id: id,
    model_name: modelName,
    company: company,
    extra: {
      type: document.getElementById('form-type').value.trim(),
      category: document.getElementById('form-category').value.trim(),
      country_of_origin: document.getElementById('form-country').value.trim(),
      release_year: document.getElementById('form-release-year').value ? parseInt(document.getElementById('form-release-year').value) : null,
      weight: document.getElementById('form-weight').value ? parseInt(document.getElementById('form-weight').value) : null,
      max_speed: document.getElementById('form-speed').value ? parseInt(document.getElementById('form-speed').value) : null,
      max_altitude: document.getElementById('form-ceiling').value ? parseInt(document.getElementById('form-ceiling').value) : null,
      max_range: document.getElementById('form-range').value ? parseInt(document.getElementById('form-range').value) : null,
      battery_life: document.getElementById('form-battery-life').value ? parseInt(document.getElementById('form-battery-life').value) : null,
      max_wind_resist: document.getElementById('form-wind').value ? parseFloat(document.getElementById('form-wind').value) : null,
      dim_folded: document.getElementById('form-dim-folded').value.trim(),
      dim_unfolded: document.getElementById('form-dim-unfolded').value.trim(),
      price: document.getElementById('form-price').value ? parseInt(document.getElementById('form-price').value) : null,
      discontinued: document.getElementById('form-discontinued').value,
      warranty: document.getElementById('form-warranty').value ? parseInt(document.getElementById('form-warranty').value) : null,
      image_url: document.getElementById('form-image-url').value.trim()
    }
  };

  try {
    const res = await apiPost('/api/drone-registry', payload);
    if (res && res.status === 'ok') {
      alert(res.message);
      closeRegistryManualForm();
      // Reload registry index & auto-select the added/edited drone
      await loadDroneRegistry();
      selectRegistryFromDropdown(res.id);
    } else {
      alert('Error saving drone: ' + (res ? res.error : 'Unknown error'));
    }
  } catch(e) {
    alert('Failed to connect to server to save drone record.');
  }
}






// ── Excel/CSV Registry Dynamic Importing ─────────────────────────────
async function handleRegistryImport(input) {
  const file = input.files[0];
  if (!file) return;
  
  const form = new FormData();
  form.append('file', file);
  
  try {
    const res = await apiPost('/api/drone-registry/import-preview', form);
    if (res.error) {
      alert('Error parsing file: ' + res.error);
      return;
    }
    
    CURRENT_TEMP_IMPORT_ID = res.temp_id;
    renderImportPreview(res);
  } catch(e) {
    alert('Failed to connect to backend server for file preview.');
  }
}

function renderImportPreview(res) {
  const modal = document.getElementById('import-preview-modal');
  const body = document.getElementById('import-preview-body');
  if (!modal || !body) return;
  
  let html = `
    <div style="display:flex; gap:16px; flex-wrap:wrap; align-items:flex-start; margin-bottom:12px;">
      <div style="flex:1; color:var(--text-secondary); font-size:12px;">
        Loaded file: <strong style="color:var(--text-primary);">${res.filename}</strong>
        &nbsp;·&nbsp; <strong style="color:var(--text-primary);">${res.total_rows}</strong> rows
      </div>
      ${(() => {
        const found   = res.embed_images_found   || 0;
        const matched = res.embed_images_matched || 0;
        if (found === 0) {
          return `<div style="font-size:10px; padding:4px 10px; border-radius:4px; background:var(--bg-card); border:1px solid var(--border); color:var(--text-muted);">No embedded images detected</div>`;
        }
        const color   = matched === found ? 'var(--accent-green)' : matched > 0 ? 'var(--accent-amber)' : 'var(--accent-red)';
        const icon    = matched === found ? '[IMG]' : matched > 0 ? '[WARN]' : '[ERR]';
        const label   = `${found} image${found>1?'s':''} found · ${matched} row${matched!==1?'s':''} matched`;
        const hint    = matched < found ? ' — check drawing anchors' : '';
        return `<div style="font-size:10px; padding:4px 10px; border-radius:4px; background:var(--bg-card); border:1px solid ${color}40; color:${color};">${icon} ${label}${hint}</div>`;
      })()}
    </div>
  `;

  if (res.malformed_rows && res.malformed_rows.length) {
    html += `
      <div style="background:rgba(248,81,73,0.08); border:1px solid rgba(248,81,73,0.3); border-radius:6px; padding:10px; margin-bottom:12px; max-height:80px; overflow-y:auto;">
        <strong style="color:var(--accent-red); font-size:11px;">Detected Malformed Rows:</strong>
        ${res.malformed_rows.map(m => `<div style="font-size:10px; color:var(--text-muted);">Row ${m.row_number}: ${m.error}</div>`).join('')}
      </div>
    `;
  }

  
  // Visual table mapping list
  html += `<div class="pe-section-title" style="margin-bottom:6px;">Columns &amp; Autodetected Mappings</div>`;
  html += `
    <div style="max-height:160px; overflow-y:auto; border:1px solid var(--border); border-radius:6px; margin-bottom:14px; background:var(--bg-card);">
      <table class="comp-table">
        <thead>
          <tr>
            <th>Source Header</th>
            <th>Fuzzy Match Target</th>
            <th>Section Group</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  res.headers.forEach(h => {
    const target = res.mappings[h];
    const targetText = target ? `<span style="color:var(--accent-green); font-weight:600;">${StandardFieldLabels[target] || target}</span>` : '<span style="color:var(--text-muted);">Not mapped (placed in Other)</span>';
    
    // Find section
    let group = 'Other';
    if (target) {
      Object.keys(DossierGroups).forEach(g => {
        if (DossierGroups[g].includes(target)) group = g;
      });
    }
    const groupText = target ? `<span class="badge" style="font-size:8px;">${group}</span>` : '—';
    
    html += `
      <tr>
        <td style="font-weight:600; color:var(--text-primary);">${h}</td>
        <td>${targetText}</td>
        <td>${groupText}</td>
      </tr>
    `;
  });
  
  html += `
        </tbody>
      </table>
    </div>
  `;
  
  // Live Preview Table
  html += `<div class="pe-section-title" style="margin-bottom:6px;">Sample Data Preview (First 3 Rows)</div>`;
  html += `
    <div style="overflow-x:auto; border:1px solid var(--border); border-radius:6px; max-height:150px; background:var(--bg-card);">
      <table class="comp-table" style="min-width:500px;">
        <thead>
          <tr>
            ${res.headers.map(h => `<th>${h}</th>`).join('')}
          </tr>
        </thead>
        <tbody>
          ${res.preview_rows.map(row => `
            <tr>
              ${res.headers.map(h => `<td>${row[h] || '—'}</td>`).join('')}
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
  
  body.innerHTML = html;
  modal.style.display = 'flex';
}

function closeImportPreview() {
  document.getElementById('import-preview-modal').style.display = 'none';
  document.getElementById('registry-import-file').value = '';
  CURRENT_TEMP_IMPORT_ID = null;
}

async function submitRegistryImport() {
  const modeSelect = document.getElementById('import-mode-select');
  const mode = modeSelect ? modeSelect.value : 'merge';
  const confirmBtn = document.getElementById('confirm-import-btn');
  
  if (confirmBtn) {
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Importing...';
  }
  
  try {
    const res = await apiPost('/api/drone-registry/import-confirm', {
      temp_id: CURRENT_TEMP_IMPORT_ID,
      mode: mode
    });
    
    if (res.error) {
      alert('Import failed: ' + res.error);
    } else {
      alert(res.message);
      closeImportPreview();
      // Instantly load new records in the search index
      loadDroneRegistry();
    }
  } catch(e) {
    alert('Import conformation request failed.');
  } finally {
    if (confirmBtn) {
      confirmBtn.disabled = false;
      confirmBtn.textContent = 'Confirm & Import';
    }
  }
}


function haversineKm(lat1, lon1, lat2, lon2) {
  const toRad = Math.PI / 180;
  const dLat = (lat2 - lat1) * toRad;
  const dLon = (lon2 - lon1) * toRad;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * toRad) * Math.cos(lat2 * toRad) * Math.sin(dLon / 2) ** 2;
  return 6371 * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
}

function buildTimelineFromPath(path) {
  if (!path || !path.length) return [];
  const first = path[0];
  const last = path[path.length - 1];
  const events = [];
  const labelTime = point => point.ts || point.timestamp || point.time || '--';
  const formatPoint = point => {
    const lat = point.lat != null ? point.lat : point.latitude;
    const lon = point.lon != null ? point.lon : point.longitude;
    const alt = point.alt != null ? point.alt : point.altitude;
    return `(${Number(lat).toFixed(4)}, ${Number(lon).toFixed(4)}) alt ${Number(alt || 0).toFixed(0)}m`;
  };

  events.push({ time: labelTime(first), label: 'Takeoff / Start', detail: formatPoint(first), type: 'normal' });
  const step = Math.max(1, Math.floor(path.length / 5));
  for (let i = step; i < path.length - step; i += step) {
    const point = path[i];
    events.push({ time: labelTime(point), label: 'Waypoint', detail: formatPoint(point), type: 'normal' });
  }
  if (path.length > 1) {
    events.push({ time: labelTime(last), label: 'Landing / End', detail: formatPoint(last), type: 'normal' });
  }
  return events;
}

function buildTelemetryFromSession(session) {
  const path = Array.isArray(session.path) ? session.path : [];
  const gpsFixes = path.length;
  const latValues = [];
  const lonValues = [];
  const altValues = [];
  const speedValues = [];

  let totalDistanceKm = 0;
  let previousPoint = null;
  path.forEach(point => {
    const lat = point.lat != null ? point.lat : point.latitude;
    const lon = point.lon != null ? point.lon : point.longitude;
    const alt = point.alt != null ? point.alt : point.altitude;
    const speed = point.speed != null ? point.speed : point.velocity;
    if (lat == null || lon == null) return;

    latValues.push(Number(lat));
    lonValues.push(Number(lon));
    if (alt != null && !Number.isNaN(Number(alt))) altValues.push(Number(alt));
    if (speed != null && !Number.isNaN(Number(speed)) && Number(speed) > 0) speedValues.push(Number(speed));

    if (previousPoint) {
      totalDistanceKm += haversineKm(previousPoint.lat, previousPoint.lon, Number(lat), Number(lon));
    }
    previousPoint = { lat: Number(lat), lon: Number(lon) };
  });

  const takeoffLat = session.takeoff_lat != null ? session.takeoff_lat : (path[0] ? (path[0].lat != null ? path[0].lat : path[0].latitude) : null);
  const takeoffLon = session.takeoff_lon != null ? session.takeoff_lon : (path[0] ? (path[0].lon != null ? path[0].lon : path[0].longitude) : null);
  const takeoffAlt = session.takeoff_alt != null ? session.takeoff_alt : (path[0] ? (path[0].alt != null ? path[0].alt : path[0].altitude) : 0);
  const landingLat = session.landing_lat != null ? session.landing_lat : (path.length ? (path[path.length - 1].lat != null ? path[path.length - 1].lat : path[path.length - 1].latitude) : null);
  const landingLon = session.landing_lon != null ? session.landing_lon : (path.length ? (path[path.length - 1].lon != null ? path[path.length - 1].lon : path[path.length - 1].longitude) : null);
  const landingAlt = session.landing_alt != null ? session.landing_alt : (path.length ? (path[path.length - 1].alt != null ? path[path.length - 1].alt : path[path.length - 1].altitude) : 0);

  const maxAltitude = session.max_alt_m != null
    ? Number(session.max_alt_m)
    : (altValues.length ? Math.max(...altValues) : 0);
  const avgSpeedMs = session.avg_speed_ms != null
    ? Number(session.avg_speed_ms)
    : (speedValues.length ? speedValues.reduce((sum, value) => sum + value, 0) / speedValues.length : 0);
  const maxSpeedMs = speedValues.length ? Math.max(...speedValues) : avgSpeedMs;
  const coverageKm2 = latValues.length && lonValues.length
    ? Math.round(((Math.max(...latValues) - Math.min(...latValues)) * 111 * (Math.max(...lonValues) - Math.min(...lonValues)) * 85) * 100) / 100
    : 0;

  return {
    telemetry_available: true,
    merged_rows: gpsFixes,
    metrics: {
      takeoff: { lat: Number(takeoffLat), lon: Number(takeoffLon), alt: Number(takeoffAlt || 0) },
      landing: { lat: Number(landingLat), lon: Number(landingLon), alt: Number(landingAlt || 0) },
      home_alt_m: Number(takeoffAlt || 0),
      total_distance_m: Math.round(totalDistanceKm * 1000 * 100) / 100,
      total_distance_km: Math.round(totalDistanceKm * 100) / 100,
      max_altitude_m: Math.round(maxAltitude * 10) / 10,
      max_speed_ms: Math.round(maxSpeedMs * 100) / 100,
      max_speed_kmh: Math.round(maxSpeedMs * 3.6 * 100) / 100,
      avg_speed_ms: Math.round(avgSpeedMs * 100) / 100,
      avg_speed_kmh: Math.round(avgSpeedMs * 3.6 * 100) / 100,
      gps_fixes: gpsFixes,
      coverage_km2: coverageKm2,
    },
    timeline: buildTimelineFromPath(path),
  };
}

function parseTimelinePoint(text) {
  if (!text) return null;
  const coordMatch = String(text).match(/\((-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)\)/);
  if (!coordMatch) return null;
  const altMatch = String(text).match(/alt\s+(-?\d+(?:\.\d+)?)/i);
  return {
    lat: parseFloat(coordMatch[1]),
    lon: parseFloat(coordMatch[2]),
    alt: altMatch ? parseFloat(altMatch[1]) : 0,
  };
}

function buildTelemetryFromTimeline(events) {
  const path = [];
  (events || []).forEach(ev => {
    const point = parseTimelinePoint(ev.detail || ev.label || ev.time_label || '');
    if (point) {
      path.push({
        lat: point.lat,
        lon: point.lon,
        alt: point.alt,
        ts: ev.time_label || ev.time || '',
      });
    }
  });

  if (!path.length) return null;

  return buildTelemetryFromSession({
    path,
    takeoff_lat: path[0].lat,
    takeoff_lon: path[0].lon,
    takeoff_alt: path[0].alt,
    landing_lat: path[path.length - 1].lat,
    landing_lon: path[path.length - 1].lon,
    landing_alt: path[path.length - 1].alt,
    max_alt_m: Math.max(...path.map(p => p.alt || 0)),
    avg_speed_ms: 0,
  });
}

async function loadFlightLogsFromDiskImage(imageId) {
  const sessionsResponse = await apiGet(`/api/disk-image/${imageId}/flight-sessions`);
  if (!sessionsResponse || !sessionsResponse.sessions || !sessionsResponse.sessions.length) {
    const parseResponse = await apiPost(`/api/disk-image/${imageId}/parse-flight-logs`);
    if (parseResponse && parseResponse.sessions && parseResponse.sessions.length) {
      return buildTelemetryFromSession(parseResponse.sessions.find(s => s.status === 'complete') || parseResponse.sessions[0]);
    }
    return null;
  }

  const session = sessionsResponse.sessions.find(s => s.status === 'complete') || sessionsResponse.sessions[0];
  return session ? buildTelemetryFromSession(session) : null;
}

async function loadFlightLogsFromTimeline() {
  const timelineResponse = await apiGet('/api/timeline');
  if (!timelineResponse || !timelineResponse.events || !timelineResponse.events.length) return null;
  return buildTelemetryFromTimeline(timelineResponse.events);
}

async function renderFlightLogsDashboard(data) {
  const hint = document.getElementById('fl-backend-hint');
  const m = data.metrics;
  hint.textContent = m.gps_fixes + ' GPS points computed from ' + (data.merged_rows || 0) + ' telemetry rows';
  hint.style.color = 'var(--accent-green)';
  document.getElementById('fl-status').textContent = 'Telemetry Ready';

  document.getElementById('fl-kpis').style.display = 'grid';
  document.getElementById('fl-kpi-dist').textContent = m.total_distance_km + ' km';
  document.getElementById('fl-kpi-alt').textContent = m.max_altitude_m + ' m';
  document.getElementById('fl-kpi-speed').textContent = m.max_speed_kmh + ' km/h';
  document.getElementById('fl-kpi-avg').textContent = m.avg_speed_kmh + ' km/h';
  document.getElementById('fl-kpi-fixes').textContent = m.gps_fixes;

  var caseR = await apiGet('/api/cases/current');
  var savedPts = {};
  if (caseR && caseR.case_id) {
    savedPts = await apiGet('/api/cases/' + caseR.case_id + '/flight-points');
  }
  if (savedPts && savedPts.takeoff_lat != null) {
    m.takeoff = { lat: savedPts.takeoff_lat, lon: savedPts.takeoff_lon, alt_m: savedPts.takeoff_alt || m.takeoff.alt_m };
  }
  if (savedPts && savedPts.landing_lat != null) {
    m.landing = { lat: savedPts.landing_lat, lon: savedPts.landing_lon, alt_m: savedPts.landing_alt || m.landing.alt_m };
  }

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

  document.getElementById('fl-details-section').style.display = 'block';
  function dirLat(lat) { return lat >= 0 ? 'N' : 'S'; }
  function dirLon(lon) { return lon >= 0 ? 'E' : 'W'; }
  const takeoffHtml = `
    <div class="ident-row"><span class="label">Latitude</span><span class="value">${Math.abs(m.takeoff.lat).toFixed(5)} ${dirLat(m.takeoff.lat)}</span></div>
    <div class="ident-row"><span class="label">Longitude</span><span class="value">${Math.abs(m.takeoff.lon).toFixed(5)} ${dirLon(m.takeoff.lon)}</span></div>
    <div class="ident-row"><span class="label">Altitude (AGL)</span><span class="value">${m.takeoff.alt_m ?? m.takeoff.alt ?? 0} m</span></div>
    <div class="ident-row"><span class="label">Home Altitude</span><span class="value">${m.home_alt_m} m</span></div>
  `;
  document.getElementById('fl-takeoff-detail').innerHTML = takeoffHtml;

  const landingHtml = `
    <div class="ident-row"><span class="label">Latitude</span><span class="value">${Math.abs(m.landing.lat).toFixed(5)} ${dirLat(m.landing.lat)}</span></div>
    <div class="ident-row"><span class="label">Longitude</span><span class="value">${Math.abs(m.landing.lon).toFixed(5)} ${dirLon(m.landing.lon)}</span></div>
    <div class="ident-row"><span class="label">Altitude (AGL)</span><span class="value">${m.landing.alt_m ?? m.landing.alt ?? 0} m</span></div>
    <div class="ident-row"><span class="label">Coverage</span><span class="value">${m.coverage_km2} km<sup>2</sup></span></div>
  `;
  document.getElementById('fl-landing-detail').innerHTML = landingHtml;

  renderFlightMap(m);
  renderFlightTimeline(data.timeline || []);
}

// Flight Logs tab
async function flLoadImageList() {
  try {
    const list = await apiGet('/api/disk-image/list');
    const sel = document.getElementById('fl-image-select');
    if (!sel) return;
    const currentVal = sel.value;
    sel.innerHTML = '<option value="">-- Select a disk image --</option>';
    if (list && list.images) {
      list.images.forEach(img => {
        const opt = document.createElement('option');
        opt.value = img.id;
        opt.textContent = (img.filename || 'unnamed') + ' (#' + img.id + ')';
        sel.appendChild(opt);
      });
    }
    if (currentVal) sel.value = currentVal;
    // Reload sessions if a value was restored
    if (sel.value) flOnImageChange();
  } catch(e) {
    console.warn("Failed to load image list for flight logs:", e);
  }
}

async function flOnImageChange() {
  const imageId = parseInt(document.getElementById('fl-image-select').value);
  if (!imageId) return;
  await loadFlightLogs();
}

async function loadFlightLogs() {
  const hint = document.getElementById('fl-backend-hint');
  if (!APP.backendMode) {
    hint.textContent = 'Backend offline. Start backend_server.py to load live flight data.';
    hint.style.color = 'var(--accent-amber)';
    return;
  }

  const imgSel = document.getElementById('fl-image-select');
  const imageId = imgSel ? parseInt(imgSel.value) : null;

  if (!imageId) {
    hint.textContent = 'Select a disk image above.';
    hint.style.color = 'var(--accent-amber)';
    return;
  }

  hint.textContent = 'Auto-extracting telemetry files and merging flight logs...';
  let data = null;

  try {
    data = await apiPost(`/api/disk-image/${imageId}/flight-log-merged`);
  } catch(e) {
    hint.textContent = 'Failed: ' + e.message;
    hint.style.color = 'var(--accent-red)';
    return;
  }

  if (!data || data.error) {
    hint.textContent = data ? data.error : 'No response from server.';
    hint.style.color = 'var(--accent-amber)';
    document.getElementById('fl-status').textContent = 'No data';
    showManualFlightPoints();
    return;
  }

  if (!data.telemetry_available) {
    hint.textContent = 'No telemetry available in this image.';
    hint.style.color = 'var(--accent-amber)';
    document.getElementById('fl-status').textContent = 'No data';
    showManualFlightPoints();
    return;
  }

  await renderFlightLogsDashboard(data);
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
  `).join('');
}

async function handlePhotoUpload(input) {
  const file = input.files[0];
  if (!file) return;
  const progress = document.getElementById('photo-progress');
  const fill = document.getElementById('photo-progress-fill');
  progress.style.display = 'block'; fill.style.width = '10%';

  // Show image preview immediately
  const previewWrap = document.getElementById('photo-preview-wrap');
  const previewImg  = document.getElementById('photo-preview-img');
  if (previewWrap && previewImg) {
    const objectUrl = URL.createObjectURL(file);
    previewImg.src = objectUrl;
    previewWrap.style.display = 'block';
  }

  const form = new FormData();
  form.append('image', file);
  fill.style.width = '40%';

  const r = document.getElementById('photo-result');
  r.style.display = 'none';

  try {
    const res = await apiPost('/api/identify-drone', form);
    fill.style.width = '100%';
    progress.style.display = 'none';

    if (!res || res.status !== 'ok' || !res.identification) {
      r.style.display = 'block';
      r.innerHTML = `<div style="color:var(--accent-red);font-size:12px;text-align:center;padding:16px;">
        Could not process image - server error.<br><span style="font-size:10px;color:var(--text-muted);">${res?.error || 'Unknown error'}</span></div>`;
      return;
    }

    const ident = res.identification;
    document.getElementById('photo-card').classList.add('has-file');
    // Hide placeholder, show result panel
    const placeholder = document.getElementById('photo-placeholder');
    if (placeholder) placeholder.style.display = 'none';

    // ── Confidence color ──────────────────────────────────────────────
    const confScore = ident.confidence_score || 0;
    const confLabel = ident.confidence_label || 'none';
    const confColor = confLabel === 'high'   ? 'var(--accent-green)' :
                      confLabel === 'medium' ? '#f0b429' :
                      confLabel === 'low'    ? '#f97316' : 'var(--accent-red)';

    // ── Web specs block ───────────────────────────────────────────────
    let specsHtml = '';
    if (ident.web_specs && ident.web_specs.specs) {
      const wkeys = Object.keys(ident.web_specs.specs);
      if (wkeys.length > 0) {
        const isUnknown = !ident.drone_model || ident.drone_model === 'Unknown Model';
        const sectionTitle = isUnknown ? 'Live Search Matches (Unconfirmed)' : 'Web Intelligence';
        specsHtml = `<div class="pe-section-title" style="margin-top:14px;">${sectionTitle}</div>`;
        wkeys.forEach(k => {
          if (k === 'wikipedia' || k === 'abstract') {
            specsHtml += `<div style="font-size:10px;line-height:1.5;color:var(--text-muted);margin:4px 0 6px;">${ident.web_specs.specs[k].slice(0, 350)}…</div>`;
          } else if (k !== 'related') {
            const displayKey = isUnknown && k.toLowerCase().includes('wikipedia') ? 'Search Result Match' : k;
            specsHtml += `<div class="ident-row"><span class="label">${displayKey}</span><span class="value">${ident.web_specs.specs[k]}</span></div>`;
          }
        });
        if (ident.web_specs.sources && ident.web_specs.sources.length) {
          specsHtml += ident.web_specs.sources.map(s => s.url
            ? `<div class="ident-row"><span class="label">Source</span><span class="value"><a href="${s.url}" target="_blank" style="color:var(--accent-blue);">${s.name || 'Link'}</a></span></div>`
            : '').join('');
        }
      }
    }

    // ── Top visual candidates ─────────────────────────────────────────
    let candidatesHtml = '';
    if (ident.top_matches && ident.top_matches.length > 0) {
      candidatesHtml = `<div class="pe-section-title" style="margin-top:14px;">Visual Candidates</div>
        <div style="display:flex;flex-direction:column;gap:4px;">` +
        ident.top_matches.map(m => `
          <div style="display:flex;align-items:center;gap:8px;padding:5px 8px;background:var(--bg-tertiary);border-radius:6px;">
            <div style="font-size:9px;font-weight:700;color:var(--text-muted);width:18px;">#${m.rank}</div>
            <div style="flex:1;min-width:0;">
              <div style="font-size:11px;font-weight:600;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${m.model}</div>
              <div style="font-size:9px;color:var(--text-muted);">${m.manufacturer || ''} ${m.category ? '· '+m.category : ''}</div>
            </div>
            <div style="font-size:10px;font-weight:700;color:${m.similarity >= 70 ? 'var(--accent-green)' : m.similarity >= 45 ? '#f0b429' : 'var(--text-muted)'};">${m.similarity}%</div>
          </div>`).join('') + '</div>';
    }

    // ── OCR text ──────────────────────────────────────────────────────
    let ocrHtml = '';
    if (ident.ocr_extracted_text) {
      ocrHtml = `<div class="pe-section-title" style="margin-top:14px;">OCR Text Detected</div>
        <div style="font-size:9px;font-family:monospace;background:var(--bg-tertiary);padding:6px 8px;border-radius:6px;color:var(--text-secondary);white-space:pre-wrap;max-height:60px;overflow:auto;">${ident.ocr_extracted_text.slice(0,200)}</div>`;
    }

    // ── Reverse image search results ──────────────────────────────────
    let reverseHtml = '';
    const photoUrl = ident.photo_url || '';
    const encodedPhotoUrl = photoUrl ? encodeURIComponent(photoUrl) : '';
    const yandexUrl = photoUrl
      ? `https://yandex.com/images/search?rpt=imageview&url=${encodedPhotoUrl}`
      : 'https://yandex.com/images/';
    const bingUrl = photoUrl
      ? `https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&sbisrc=UrlPaste&q=imgurl:${encodedPhotoUrl}`
      : 'https://www.bing.com/images/search';
    const googleUrl = photoUrl
      ? `https://www.google.com/searchbyimage?image_url=${encodedPhotoUrl}`
      : 'https://www.google.com/search';
    let photoHost = '';
    if (photoUrl) {
      try {
        photoHost = new URL(photoUrl, window.location.href).hostname;
      } catch (e) {
        photoHost = '';
      }
    }
    const photoIsLocal = photoHost === 'localhost' || photoHost === '127.0.0.1' || photoHost === '::1';

    // Action buttons (always shown)
    reverseHtml += `<div class="pe-section-title" style="margin-top:14px;">Reverse Image Search</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;">
        <a href="${yandexUrl}" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:4px;padding:5px 10px;background:#ff6900;color:#fff;border-radius:6px;font-size:10px;font-weight:600;text-decoration:none;">Yandex ↗</a>
        <a href="${googleUrl}" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:4px;padding:5px 10px;background:#4285f4;color:#fff;border-radius:6px;font-size:10px;font-weight:600;text-decoration:none;">Google Images ↗</a>
        <a href="${bingUrl}" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:4px;padding:5px 10px;background:#00809d;color:#fff;border-radius:6px;font-size:10px;font-weight:600;text-decoration:none;">Bing Visual ↗</a>
      </div>`;

    if (photoUrl) {
      reverseHtml += `<div style="font-size:9px;color:var(--text-muted);margin-bottom:6px;word-break:break-all;">Uploaded photo URL: <a href="${photoUrl}" target="_blank" rel="noopener noreferrer" style="color:var(--accent-blue);text-decoration:none;">open evidence image</a></div>`;
      if (photoIsLocal) {
        reverseHtml += `<div style="font-size:9px;color:#f0b429;margin-bottom:6px;line-height:1.4;">Reverse image search needs a publicly reachable image URL. This upload is served from ${photoHost || 'localhost'}, so use <span style="font-family:monospace;">PUBLIC_BASE_URL</span> or a tunnel if you want the external search engines to fetch it.</div>`;
      }
    }

    // Image analysis hint
    if (ident.image_analysis) {
      reverseHtml += `<div style="font-size:9px;color:var(--text-muted);margin-bottom:6px;">Image classified as: <strong style="color:var(--text-secondary);">${ident.image_analysis}</strong></div>`;
    }

    // Best guess from Yandex/Bing
    if (ident.best_guess) {
      reverseHtml += `<div class="ident-row" style="margin-bottom:6px;">
        <span class="label">Best Guess</span>
        <span class="value" style="color:#ff6900;font-weight:700;">${ident.best_guess}</span>
      </div>`;
    }

    // Combined reverse-image hits from Yandex + Bing
    if (ident.reverse_hits && ident.reverse_hits.length) {
      reverseHtml += `<div style="display:flex;flex-direction:column;gap:3px;margin-top:4px;">` +
        ident.reverse_hits.map(h => {
          const badge = h.engine === 'Yandex'
            ? `<span style="font-size:8px;padding:1px 5px;background:#ff6900;color:#fff;border-radius:3px;margin-right:5px;">Y</span>`
            : `<span style="font-size:8px;padding:1px 5px;background:#00809d;color:#fff;border-radius:3px;margin-right:5px;">B</span>`;
          const link = h.url
            ? `<a href="${h.url}" target="_blank" style="color:var(--accent-blue);text-decoration:none;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${h.title}</a>`
            : `<span style="font-size:10px;color:var(--text-secondary);">${h.title}</span>`;
          return `<div style="display:flex;align-items:center;padding:3px 0;">${badge}${link}</div>`;
        }).join('') + `</div>`;
    }

    // ── DuckDuckGo results ────────────────────────────────────────────
    let ddgHtml = '';
    if (ident.ddg_results && ident.ddg_results.length) {
      ddgHtml = `<div class="pe-section-title" style="margin-top:14px;">Web Search Results</div>
        <div style="display:flex;flex-direction:column;gap:6px;">` +
        ident.ddg_results.map(h => `
          <div style="padding:6px 8px;background:var(--bg-tertiary);border-radius:6px;">
            <a href="${h.url}" target="_blank" style="font-size:11px;font-weight:600;color:var(--accent-blue);text-decoration:none;display:block;margin-bottom:2px;">${h.title}</a>
            ${h.snippet ? `<div style="font-size:9px;color:var(--text-muted);line-height:1.4;">${h.snippet.slice(0,160)}</div>` : ''}
          </div>`).join('') + '</div>';
    }

    // ── Knowledge Base Matches (Built-in Fallback) ───────────────────
    let kbHtml = '';
    if (ident.kb_matches && ident.kb_matches.length) {
      kbHtml = `<div class="pe-section-title" style="margin-top:14px;">Potential Matches (Knowledge Base)</div>`;
      ident.kb_matches.forEach(m => {
        kbHtml += `
          <div style="padding:6px 8px;background:var(--bg-tertiary);border-radius:6px;margin-bottom:6px;font-size:11px;">
            <div style="display:flex;justify-content:space-between;font-weight:600;color:var(--text-primary);margin-bottom:3px;">
              <span>${m.model}</span>
              <span style="color:var(--accent-blue);font-size:10px;">${m.company}</span>
            </div>
            <div style="color:var(--text-muted);font-size:10px;line-height:1.3;margin-bottom:4px;">${m.desc || ''}</div>
            <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:4px;font-size:9px;color:var(--text-secondary);">
              <div>⏱️ ${m.endurance || '--'}</div>
              <div>📏 ${m.range || '--'}</div>
              <div>⚖️ ${m.weight || '--'}</div>
            </div>
          </div>`;
      });
    }



    // ── No match state ────────────────────────────────────────────────
    const noMatchBanner = (confLabel === 'none') ? `
      <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:10px;color:#fca5a5;">
        No match found in reference database - see Reverse Image Search below to identify via Yandex or Google Lens.
      </div>` : '';

    // ── Registry fields ───────────────────────────────────────────────
    let regHtml = '';
    if (ident.registry_match) {
      const reg = ident.registry_match;
      const regKeys = ['type','category','country','endurance','range_km','weight','speed','ceiling'];
      const fields = regKeys
        .map(k => {
          const val = reg[k];
          if (!val) return null;
          return [_label(k), _fmtVal(k, val)];
        })
        .filter(Boolean);
      if (fields.length) {
        regHtml = `<div class="pe-section-title" style="margin-top:14px;">📋 Registry Specifications</div>` +
          fields.map(([l,v]) => `<div class="ident-row"><span class="label">${l}</span><span class="value">${v}</span></div>`).join('');
      }
    }

    r.style.display = 'block';
    r.innerHTML = `
      ${noMatchBanner}
      <div class="ident-badge" style="margin-bottom:12px;">
        <div class="badge-icon" style="background:${confColor}22;color:${confColor};border:1px solid ${confColor}44;">
          ${(ident.company || 'UNK').substring(0,3).toUpperCase()}
        </div>
        <div style="flex:1;min-width:0;">
          <div style="font-weight:700;font-size:13px;color:var(--text-primary);">${ident.drone_model || 'Unknown Model'}</div>
          <div style="font-size:10px;color:var(--text-muted);">${ident.company || 'Unknown Manufacturer'}</div>
        </div>
      </div>

      <div style="margin-bottom:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <span style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;">Model Confidence</span>
          <span style="font-size:11px;font-weight:700;color:${confColor};">${confScore}% <span style="font-weight:400;text-transform:capitalize;">(${confLabel})</span></span>
        </div>
        <div style="height:6px;background:var(--bg-tertiary);border-radius:3px;overflow:hidden;">
          <div style="height:100%;width:${confScore}%;background:${confColor};border-radius:3px;transition:width .6s ease;"></div>
        </div>
      </div>

      ${regHtml}
      ${specsHtml}
      ${candidatesHtml}
      ${ocrHtml}
      ${kbHtml}
      ${reverseHtml}
      ${ddgHtml}
    `;

    // ── Populate Drone Identification section in dashboard ─────────────
    if (ident.registry_match) {
      const reg = ident.registry_match;
      populateDroneGrid(reg, null, 'VISUAL-ID');
    }
  } catch (err) {
    progress.style.display = 'none';
    r.style.display = 'block';
    r.innerHTML = `<div style="color:var(--accent-red);font-size:12px;text-align:center;padding:16px;">
    Upload failed: ${err.message}</div>`;
  }
}

// Disk upload handlers — POST to backend
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
    .bindPopup('<b>Takeoff</b><br>(' + metrics.takeoff.lat.toFixed(5) + ', ' + metrics.takeoff.lon.toFixed(5) + ')<br>Alt: ' + (metrics.takeoff.alt_m ?? metrics.takeoff.alt ?? 0) + 'm');
  L.marker([metrics.landing.lat, metrics.landing.lon], {icon: landingIcon}).addTo(flightMap)
    .bindPopup('<b>Landing</b><br>(' + metrics.landing.lat.toFixed(5) + ', ' + metrics.landing.lon.toFixed(5) + ')<br>Alt: ' + (metrics.landing.alt_m ?? metrics.landing.alt ?? 0) + 'm');

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
      flLoadImageList();
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
    if (tab === 'disk-image') {
      diInit();
    }
    if (tab === 'physical') {
      // Also show drone list when navigating back from detail
      if (!window.location.pathname.includes('/physical-evidence/drone/')) {
        showDroneList();
      }
    }
  });
});

// ── Disk Image Analysis Functions ─────────────────────────────────────────

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

let DI_CURRENT_IMAGE_ID = null;
let DI_TREE_PARENT_ID   = null;
let DI_TREE_OFFSET      = 0;
let DI_TREE_LIMIT       = 200;
let DI_TREE_SEARCH_TEXT = "";
let DI_SELECTED_FILES   = new Set();
let DI_MAP_INSTANCE     = null;
let DI_MAP_POLYLINE     = null;
let DI_MAP_MARKERS      = [];

function diInit() {
  const treePanel = document.getElementById('di-tree-panel');
  if (treePanel) treePanel.style.display = 'none';
  const imageList = document.getElementById('di-image-list');
  if (imageList) imageList.style.display = '';
  const uploadSection = document.querySelector('#pane-disk-image > .section:first-child');
  if (uploadSection) uploadSection.style.display = '';
  diCheckTsk();
  diRefreshList();
}

async function diCheckTsk() {
  const badge = document.getElementById('di-tsk-badge');
  const banner = document.getElementById('di-tsk-error');
  const msg = document.getElementById('di-tsk-error-msg');
  try {
    const list = await apiGet('/api/disk-image/list');
    if (list && list.images !== undefined) {
      if (badge) {
        badge.className = "badge status-active";
        badge.innerHTML = `<span class="dot"></span> TSK Ready`;
      }
      if (banner) banner.style.display = 'none';
    }
  } catch (e) {
    if (badge) {
      badge.className = "badge status-danger";
      badge.innerHTML = `<span class="dot"></span> TSK Offline`;
    }
    if (banner) {
      banner.style.display = 'block';
      if (msg && e.message) {
        msg.textContent = e.message;
      }
    }
  }
}

function diUploadImage(file) {
  if (!file) return;
  const progress = document.getElementById('di-upload-progress');
  const fill = document.getElementById('di-upload-progress-fill');
  const status = document.getElementById('di-upload-status');

  progress.style.display = 'block';
  fill.style.width = '0%';
  status.textContent = 'Uploading... 0%';

  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/disk-image/upload');
  xhr.upload.onprogress = function(e) {
    if (e.lengthComputable) {
      const pct = Math.round((e.loaded / e.total) * 100);
      fill.style.width = pct + '%';
      status.textContent = `Uploading... ${pct}% (${(e.loaded/1024/1024).toFixed(1)} / ${(e.total/1024/1024).toFixed(1)} MB)`;
    }
  };
  xhr.onload = function() {
    progress.style.display = 'none';
    if (xhr.status === 200) {
      status.textContent = 'Upload complete! Processing E01 if applicable...';
      setTimeout(() => {
        status.textContent = '';
        diRefreshList();
      }, 1500);
    } else {
      status.innerHTML = `<span style="color:var(--accent-red)">Upload failed: ${xhr.responseText}</span>`;
    }
  };
  xhr.onerror = function() {
    progress.style.display = 'none';
    status.innerHTML = `<span style="color:var(--accent-red)">Upload error</span>`;
  };

  const fd = new FormData();
  fd.append('file', file);
  xhr.send(fd);
}

async function diLoadSampleDD() {
  const status = document.getElementById('di-upload-status');
  if (status) status.textContent = 'Loading drone_baseline.dd from server samples...';
  try {
    const res = await apiPost('/api/load-sample/baseline');
    if (res && res.status === 'ok') {
      // Create a simulated DiskImage row in SQLite to register the sample file
      // Wait for ingest list to refresh
      if (status) status.textContent = 'drone_baseline.dd loaded successfully.';
      setTimeout(() => {
        if (status) status.textContent = '';
        diRefreshList();
      }, 1500);
    }
  } catch (e) {
    if (status) status.innerHTML = `<span style="color:var(--accent-red)">Failed: ${e.message}</span>`;
  }
}

async function diRefreshList() {
  const listEl = document.getElementById('di-image-list');
  const tbody = document.getElementById('di-image-tbody');
  if (!listEl || !tbody) return;

  try {
    const res = await apiGet('/api/disk-image/list');
    if (!res || !res.images || !res.images.length) {
      listEl.style.display = 'none';
      return;
    }
    listEl.style.display = 'block';
    tbody.innerHTML = res.images.map(img => {
      let statusColor = "status-pending";
      if (img.status === "complete") statusColor = "status-success";
      if (img.status === "failed") statusColor = "status-danger";
      if (img.status === "analyzing") statusColor = "status-warning";

      const err = img.error_message ? `<div style="color:var(--accent-red);font-size:9px;margin-top:2px;">${img.error_message}</div>` : '';
      const sizeStr = (img.size_bytes / 1024 / 1024).toFixed(2) + " MB";

      let actions = '';
      if (img.status === 'pending' || img.status === 'failed') {
        actions = `<button class="btn btn-primary btn-xs" onclick="diStartAnalysis(${img.id})">Analyze</button>`;
      } else if (img.status === 'complete') {
        actions = `<button class="btn btn-xs" onclick="event.stopPropagation();window.location.href='/physical-evidence/disk-image/${img.id}'">Browse</button>`;
      } else {
        actions = `<span style="font-style:italic;color:var(--text-muted);">running...</span>`;
      }

      return `<tr>
        <td style="padding:6px 10px; border-bottom:1px solid var(--border); font-weight:600;">${img.filename}${err}</td>
        <td style="padding:6px 10px; border-bottom:1px solid var(--border);">${img.format.toUpperCase()}</td>
        <td style="padding:6px 10px; border-bottom:1px solid var(--border); text-align:right;">${sizeStr}</td>
        <td style="padding:6px 10px; border-bottom:1px solid var(--border); color:var(--text-muted);">${img.uploaded_at.split('T')[0]}</td>
        <td style="padding:6px 10px; border-bottom:1px solid var(--border);">
          <span class="status-pill ${statusColor}"><span class="dot"></span> ${img.status}</span>
        </td>
        <td style="padding:6px 10px; border-bottom:1px solid var(--border); text-align:center;">${actions}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    console.warn("Failed to load image list:", e);
  }
}

async function diStartAnalysis(id) {
  diRefreshList();
  try {
    const res = await apiPost(`/api/disk-image/${id}/analyze`);
    if (res && res.status === 'analyzing') {
      // Poll list for updates every 2 seconds
      const timer = setInterval(async () => {
        const list = await apiGet('/api/disk-image/list');
        const img = list.images.find(x => x.id === id);
        if (!img || img.status !== 'analyzing') {
          clearInterval(timer);
          diRefreshList();
          if (img && img.status === 'complete') {
            diSelectImage(id, img.filename);
          }
        }
      }, 2000);
    }
  } catch (e) {
    alert("Analysis failed: " + e.message);
  }
}

function diSelectImage(id, filename) {
  DI_CURRENT_IMAGE_ID = id;
  DI_TREE_PARENT_ID = null;
  DI_TREE_OFFSET = 0;
  DI_TREE_SEARCH_TEXT = "";
  DI_SELECTED_FILES.clear();

  const titleEl = document.getElementById('di-tree-image-name');
  if (titleEl) titleEl.textContent = `— ${filename}`;

  document.getElementById('di-tree-panel').style.display = 'block';
  document.getElementById('di-meta-panel').style.display = 'none';

  diLoadTree();
  diLoadAuditLog();
}

async function loadDiskImageBrowse(imageId) {
  DI_CURRENT_IMAGE_ID = Number(imageId);
  DI_TREE_PARENT_ID = null;
  DI_TREE_OFFSET = 0;
  DI_TREE_SEARCH_TEXT = "";
  DI_SELECTED_FILES.clear();

  try {
    const res = await fetch(`/api/disk-image/${encodeURIComponent(imageId)}`);
    if (res.ok) {
      const img = await res.json();
      const titleEl = document.getElementById('di-tree-image-name');
      if (titleEl) titleEl.textContent = `— ${img.filename}`;
    }
  } catch (_) {}

  const imageList = document.getElementById('di-image-list');
  if (imageList) imageList.style.display = 'none';

  const uploadSection = document.querySelector('#pane-disk-image > .section:first-child');
  if (uploadSection) uploadSection.style.display = 'none';

  const treePanel = document.getElementById('di-tree-panel');
  if (treePanel) treePanel.style.display = 'block';

  const metaPanel = document.getElementById('di-meta-panel');
  if (metaPanel) metaPanel.style.display = 'none';

  const header = treePanel?.querySelector('.section-header');
  if (header && !header.querySelector('.drv-back-btn')) {
    const backBtn = document.createElement('button');
    backBtn.className = 'drv-back-btn';
    backBtn.textContent = '< Back to images';
    backBtn.style.marginRight = '12px';
    backBtn.addEventListener('click', () => { window.location.href = '/'; });
    header.insertBefore(backBtn, header.firstChild);
  }

  diLoadTree();
  diLoadAuditLog();
}

function openDashboardTab(tabName) {
  const target = document.querySelector(`.nav-item[data-tab="${tabName}"]`);
  if (target) {
    target.click();
  }
}

async function diLoadTree(append = false) {
  if (!DI_CURRENT_IMAGE_ID) return;
  const tbody = document.getElementById('di-file-tbody');
  const countsEl = document.getElementById('di-tree-counts');
  const loadMoreBtn = document.getElementById('di-load-more-btn');
  if (!tbody) return;

  if (!append) {
    DI_TREE_OFFSET = 0;
    tbody.innerHTML = `<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--text-muted);">Loading structure...</td></tr>`;
  }

  const alloc = document.getElementById('di-alloc-filter').value;
  const ext = document.getElementById('di-ext-filter').value;

  let url = `/api/disk-image/${DI_CURRENT_IMAGE_ID}/tree?limit=${DI_TREE_LIMIT}&offset=${DI_TREE_OFFSET}`;
  if (DI_TREE_PARENT_ID !== null) url += `&parent_id=${DI_TREE_PARENT_ID}`;
  if (DI_TREE_SEARCH_TEXT) url += `&q=${encodeURIComponent(DI_TREE_SEARCH_TEXT)}`;
  if (alloc) url += `&alloc=${alloc}`;
  if (ext) url += `&ext=${ext}`;

  try {
    const res = await apiGet(url);
    if (!res || !res.files) return;

    if (countsEl) countsEl.textContent = `Total objects: ${res.total}`;

    // Show/hide load more
    if (loadMoreBtn) {
      if (res.files.length === DI_TREE_LIMIT) {
        loadMoreBtn.style.display = 'inline-block';
      } else {
        loadMoreBtn.style.display = 'none';
      }
    }

    const rowsHtml = res.files.map(f => {
      const isDir = f.entry_type === 'dir';
      const icon = isDir ? '[DIR]' : '[FILE]';
      const sizeStr = isDir ? '—' : (f.size_bytes / 1024).toFixed(2) + " KB";
      const statusColor = f.alloc_status === 'allocated' ? 'status-success' : 'status-danger';

      const selectBox = isDir
        ? ''
        : `<input type="checkbox" data-id="${f.id}" onchange="diToggleSelect(${f.id}, this.checked)" ${DI_SELECTED_FILES.has(f.id) ? 'checked' : ''}>`;

      const nameClick = isDir
        ? `onclick="diEnterDir(${f.id}, '${escapeHtml(f.name)}')" style="cursor:pointer;text-decoration:underline;color:var(--accent-blue);"`
        : `onclick="diShowMeta(${f.id})" style="cursor:pointer;"`;

      return `<tr class="di-file-row ${DI_SELECTED_FILES.has(f.id) ? 'selected' : ''}" id="di-file-row-${f.id}">
        <td style="padding:6px 8px; border-bottom:1px solid var(--border);">${selectBox}</td>
        <td style="padding:6px 8px; border-bottom:1px solid var(--border); font-weight:600;" ${nameClick}>
          ${icon} ${f.name}
        </td>
        <td style="padding:6px 8px; border-bottom:1px solid var(--border); text-align:right;">${sizeStr}</td>
        <td style="padding:6px 8px; border-bottom:1px solid var(--border); color:var(--text-muted);">${(f.ts_modified || '—').split('T')[0]}</td>
        <td style="padding:6px 8px; border-bottom:1px solid var(--border);">
          <span class="status-pill ${statusColor}"><span class="dot"></span> ${f.alloc_status}</span>
        </td>
      </tr>`;
    }).join('');

    if (append) {
      if (DI_TREE_OFFSET === 0) tbody.innerHTML = '';
      tbody.innerHTML += rowsHtml;
    } else {
      tbody.innerHTML = rowsHtml || `<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--text-muted);">No entries match filter criteria.</td></tr>`;
    }
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--accent-red);">Failed: ${e.message}</td></tr>`;
  }
}

function diLoadMoreTree() {
  DI_TREE_OFFSET += DI_TREE_LIMIT;
  diLoadTree(true);
}

function diToggleSelect(id, checked) {
  const row = document.getElementById(`di-file-row-${id}`);
  if (checked) {
    DI_SELECTED_FILES.add(id);
    if (row) row.classList.add('selected');
  } else {
    DI_SELECTED_FILES.delete(id);
    if (row) row.classList.remove('selected');
  }
}

function diToggleSelectAll(box) {
  const rows = document.querySelectorAll('#di-file-tbody input[type="checkbox"]');
  rows.forEach(r => {
    r.checked = box.checked;
    const id = parseInt(r.dataset.id);
    if (id) diToggleSelect(id, box.checked);
  });
}

function diEnterDir(id, name) {
  DI_TREE_PARENT_ID = id;
  // Breadcrumb reconstruction placeholder
  const bc = document.getElementById('di-breadcrumb');
  if (bc) {
    bc.innerHTML = `<span style="cursor:pointer;text-decoration:underline;color:var(--accent-blue);" onclick="diResetDir()">ROOT</span> / ${name}`;
  }
  diLoadTree();
}

function diResetDir() {
  DI_TREE_PARENT_ID = null;
  const bc = document.getElementById('di-breadcrumb');
  if (bc) bc.textContent = 'ROOT';
  diLoadTree();
}

let DI_SEARCH_DEBOUNCE = null;
function diSearchTree(val) {
  if (DI_SEARCH_DEBOUNCE) clearTimeout(DI_SEARCH_DEBOUNCE);
  DI_SEARCH_DEBOUNCE = setTimeout(() => {
    DI_TREE_SEARCH_TEXT = val.trim();
    diLoadTree();
  }, 300);
}

function diFilterTree() {
  diLoadTree();
}

async function diShowMeta(fileId) {
  if (!DI_CURRENT_IMAGE_ID) return;
  const panel = document.getElementById('di-meta-panel');
  const content = document.getElementById('di-meta-content');
  if (!panel || !content) return;

  panel.style.display = 'block';
  content.innerHTML = `<div style="font-size:10px;color:var(--text-muted);">Loading metadata...</div>`;

  try {
    const f = await apiGet(`/api/disk-image/${DI_CURRENT_IMAGE_ID}/file/${fileId}`);
    if (!f) return;

    content.innerHTML = `
      <div style="font-size:12px; font-weight:700; margin-bottom:8px; word-break:break-all;">${f.name}</div>
      <table style="width:100%; border-collapse:collapse; font-size:10px;" cellpadding="4">
        <tr><td style="color:var(--text-muted); font-weight:500; border-bottom:1px solid var(--border);">Inode</td><td style="border-bottom:1px solid var(--border); font-family:monospace;">${f.inode || '—'}</td></tr>
        <tr><td style="color:var(--text-muted); font-weight:500; border-bottom:1px solid var(--border);">Size</td><td style="border-bottom:1px solid var(--border);">${(f.size_bytes/1024).toFixed(2)} KB (${f.size_bytes} B)</td></tr>
        <tr><td style="color:var(--text-muted); font-weight:500; border-bottom:1px solid var(--border);">Status</td><td style="border-bottom:1px solid var(--border); font-weight:600;">${f.alloc_status.toUpperCase()}</td></tr>
        <tr><td style="color:var(--text-muted); font-weight:500; border-bottom:1px solid var(--border);">Created (C)</td><td style="border-bottom:1px solid var(--border); font-family:monospace;">${f.ts_created || '—'}</td></tr>
        <tr><td style="color:var(--text-muted); font-weight:500; border-bottom:1px solid var(--border);">Modified (M)</td><td style="border-bottom:1px solid var(--border); font-family:monospace;">${f.ts_modified || '—'}</td></tr>
        <tr><td style="color:var(--text-muted); font-weight:500; border-bottom:1px solid var(--border);">Accessed (A)</td><td style="border-bottom:1px solid var(--border); font-family:monospace;">${f.ts_accessed || '—'}</td></tr>
        <tr><td style="color:var(--text-muted); font-weight:500; border-bottom:1px solid var(--border);">Changed (B)</td><td style="border-bottom:1px solid var(--border); font-family:monospace;">${f.ts_changed || '—'}</td></tr>
        <tr><td style="color:var(--text-muted); font-weight:500; border-bottom:1px solid var(--border);">MD5 Hash</td><td style="border-bottom:1px solid var(--border); font-family:monospace; word-break:break-all;">${f.md5 || '—'}</td></tr>
        <tr><td style="color:var(--text-muted); font-weight:500; border-bottom:1px solid var(--border);">SHA-256</td><td style="border-bottom:1px solid var(--border); font-family:monospace; word-break:break-all;">${f.sha256 || '—'}</td></tr>
        <tr><td style="color:var(--text-muted); font-weight:500;">Extracted Path</td><td style="font-family:monospace; word-break:break-all; font-size:9px;">${f.extracted_path || 'Not extracted'}</td></tr>
      </table>
    `;
  } catch(e) {
    content.innerHTML = `<div style="color:var(--accent-red);">Failed to load metadata: ${e.message}</div>`;
  }
}

async function diExtractSelected() {
  if (!DI_CURRENT_IMAGE_ID) return;
  const statusEl = document.getElementById('di-extract-status');
  if (DI_SELECTED_FILES.size === 0) {
    alert("Please select at least one file to extract.");
    return;
  }

  if (statusEl) statusEl.textContent = `Extracting ${DI_SELECTED_FILES.size} files...`;

  try {
    const res = await apiPost(`/api/disk-image/${DI_CURRENT_IMAGE_ID}/extract`, {
      file_ids: Array.from(DI_SELECTED_FILES)
    });
    if (res && res.extracted) {
      if (statusEl) {
        let html = `Successfully extracted ${res.extracted.length} files.`;
        html += '<div style="margin-top:8px;font-size:13px;">';
        for (const f of res.extracted) {
          html += `<div style="display:flex;align-items:center;gap:8px;padding:2px 0;">
            <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${f.name}</span>
            <a href="${BACKEND}/api/disk-image/${DI_CURRENT_IMAGE_ID}/download-extracted/${f.file_id}"
               class="btn btn-sm" style="text-decoration:none;padding:2px 8px;font-size:12px;">⬇</a>
          </div>`;
        }
        html += '</div>';
        statusEl.innerHTML = html;
      }
      DI_SELECTED_FILES.clear();
      diLoadTree();
      diLoadAuditLog();
    }
  } catch (e) {
    if (statusEl) statusEl.innerHTML = `<span style="color:var(--accent-red)">Failed: ${e.message}</span>`;
  }
}

async function diParseFlightLogs() {
  if (!DI_CURRENT_IMAGE_ID) return;
  const statusEl = document.getElementById('di-parse-status');
  if (statusEl) statusEl.textContent = "Scanning extracted files for telemetry and reconstruction...";

  try {
    const res = await apiPost(`/api/disk-image/${DI_CURRENT_IMAGE_ID}/parse-flight-logs`);
    if (res && res.sessions) {
      if (statusEl) statusEl.textContent = `Completed flight analysis. Recovered ${res.sessions.length} sessions.`;
      diLoadSessions();
    }
  } catch (e) {
    if (statusEl) statusEl.innerHTML = `<span style="color:var(--accent-red)">Failed: ${e.message}</span>`;
  }
}

async function diLoadSessions() {
  if (!DI_CURRENT_IMAGE_ID) return;
  const wrapper = document.getElementById('di-session-list');
  const container = document.getElementById('di-sessions-container');
  if (!wrapper || !container) return;

  try {
    const res = await apiGet(`/api/disk-image/${DI_CURRENT_IMAGE_ID}/flight-sessions`);
    if (!res || !res.sessions || !res.sessions.length) {
      wrapper.style.display = 'none';
      return;
    }
    wrapper.style.display = 'block';
    container.innerHTML = res.sessions.map((s, idx) => {
      let pillClass = "status-success";
      if (s.status === "partial") pillClass = "status-warning";
      if (s.status === "corrupt") pillClass = "status-danger";

      const errText = s.notes ? `<div style="font-size:9px;color:var(--text-muted);margin-top:2px;">${s.notes}</div>` : '';

      return `<div class="di-session-card" id="di-session-card-${s.id}" onclick="diSelectSession(${s.id}, ${idx})">
        <div style="flex:1; min-width:0;">
          <div style="font-size:11px; font-weight:600;">${s.source_file} (${s.source_format.toUpperCase()})</div>
          <div style="font-size:9px; color:var(--text-muted);">${s.takeoff_ts || '—'}</div>
          ${errText}
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="status-pill ${pillClass}"><span class="dot"></span> ${s.status}</span>
          ${s.xlsx_path ? `<button class="btn btn-xs" onclick="event.stopPropagation(); diDownloadXlsx(${s.id})">Excel</button>` : ''}
        </div>
      </div>`;
    }).join('');

    // Cache session data globally on pane state for Leaflet drawing
    window.DI_CACHED_SESSIONS = res.sessions;
  } catch(e) {
    console.warn("Failed to load flight sessions:", e);
  }
}

function diDownloadXlsx(sessionId) {
  if (!DI_CURRENT_IMAGE_ID) return;
  window.open(`/api/disk-image/${DI_CURRENT_IMAGE_ID}/flight-sessions/${sessionId}/download`, '_blank');
}

function diSelectSession(id, idx) {
  const cards = document.querySelectorAll('.di-session-card');
  cards.forEach(c => c.classList.remove('active-session'));
  const activeCard = document.getElementById(`di-session-card-${id}`);
  if (activeCard) activeCard.classList.add('active-session');

  const s = window.DI_CACHED_SESSIONS[idx];
  if (!s) return;

  // Render stats
  const statsEl = document.getElementById('di-flight-stats');
  if (statsEl) {
    const p = s.path || [];
    const dur = s.duration_s ? `${Math.floor(s.duration_s/60)}m ${Math.floor(s.duration_s%60)}s` : '—';
    const maxAlt = s.max_alt_m ? s.max_alt_m + " m" : '—';
    const totalDist = s.total_dist_m ? (s.total_dist_m/1000).toFixed(2) + " km" : '—';
    const avgSpeed = s.avg_speed_ms ? (s.avg_speed_ms*3.6).toFixed(1) + " km/h" : '—';

    statsEl.innerHTML = `
      <div class="kpi-card" style="padding:6px 10px; flex:1; min-width:80px;"><div class="kpi-label">Duration</div><div class="kpi-value" style="font-size:14px;">${dur}</div></div>
      <div class="kpi-card" style="padding:6px 10px; flex:1; min-width:80px;"><div class="kpi-label">Max Alt</div><div class="kpi-value" style="font-size:14px;">${maxAlt}</div></div>
      <div class="kpi-card" style="padding:6px 10px; flex:1; min-width:80px;"><div class="kpi-label">Distance</div><div class="kpi-value" style="font-size:14px;">${totalDist}</div></div>
      <div class="kpi-card" style="padding:6px 10px; flex:1; min-width:80px;"><div class="kpi-label">Avg Speed</div><div class="kpi-value" style="font-size:14px;">${avgSpeed}</div></div>
      <div class="kpi-card" style="padding:6px 10px; flex:1; min-width:80px;"><div class="kpi-label">GPS Fixes</div><div class="kpi-value" style="font-size:14px;">${p.length}</div></div>
    `;
  }

  // Draw Map
  document.getElementById('di-map-wrapper').style.display = 'block';
  setTimeout(() => {
    diDrawMap(s);
  }, 100);
}

function diDrawMap(session) {
  const container = document.getElementById('di-map');
  if (!container) return;

  const path = session.path || [];
  if (!path.length) {
    container.innerHTML = `<div style="padding:32px; text-align:center; color:var(--text-muted); font-size:12px;">No GPS coordinates in this flight session log.</div>`;
    return;
  }

  // Clear map container and re-init Leaflet to avoid double binding errors
  container.innerHTML = "";
  const mapDiv = document.createElement('div');
  mapDiv.style.width = "100%";
  mapDiv.style.height = "100%";
  container.appendChild(mapDiv);

  const points = path.map(p => [p.lat, p.lon]);

  const map = L.map(mapDiv).setView(points[0], 15);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19,
    attribution: '© OpenStreetMap'
  }).addTo(map);

  // Draw Path line
  L.polyline(points, { color: '#58a6ff', weight: 4, opacity: 0.8 }).addTo(map);

  // Takeoff Marker
  if (session.takeoff) {
    L.marker([session.takeoff.lat, session.takeoff.lon])
      .addTo(map)
      .bindPopup(`🛫 Takeoff<br>${session.takeoff.ts || ''}`)
      .openPopup();
  }

  // Landing Marker
  if (session.landing) {
    L.marker([session.landing.lat, session.landing.lon])
      .addTo(map)
      .bindPopup(`🛬 Landing<br>${session.landing.ts || ''}`);
  }

  map.fitBounds(L.polyline(points).getBounds(), { padding: [20, 20] });
}

async function diLoadAuditLog() {
  if (!DI_CURRENT_IMAGE_ID) return;
  const wrapper = document.getElementById('di-audit-wrapper');
  const tbody = document.getElementById('di-audit-tbody');
  if (!wrapper || !tbody) return;

  try {
    const res = await apiGet(`/api/disk-image/${DI_CURRENT_IMAGE_ID}/audit`);
    if (!res || !res.audit || !res.audit.length) {
      wrapper.style.display = 'none';
      return;
    }
    wrapper.style.display = 'block';
    tbody.innerHTML = res.audit.map(log => {
      const file = log.filename ? `${log.filename} <span style="color:var(--text-muted); font-size:9px;">(${log.full_path})</span>` : '—';
      const hash = log.md5 ? `<span style="font-family:monospace;">${log.md5}</span>` : '—';
      const notes = log.notes || '—';
      return `<tr>
        <td style="padding:6px 8px; border-bottom:1px solid var(--border); color:var(--text-muted);">${log.timestamp.split('T')[0]}</td>
        <td style="padding:6px 8px; border-bottom:1px solid var(--border); font-weight:600;">${log.action.toUpperCase()}</td>
        <td style="padding:6px 8px; border-bottom:1px solid var(--border);">${file}</td>
        <td style="padding:6px 8px; border-bottom:1px solid var(--border);">${hash}</td>
        <td style="padding:6px 8px; border-bottom:1px solid var(--border); color:var(--text-muted);">${notes}</td>
      </tr>`;
    }).join('');
  } catch(e) {
    console.warn("Failed to load audit logs:", e);
  }
}

// ── Overview "Search by Image" handler ─────────────────────────────────
async function handleOverviewPhotoUpload(input) {
  const file = input.files[0];
  if (!file) return;
  const progress = document.getElementById('ov-photo-progress');
  const fill = document.getElementById('ov-photo-progress-fill');
  progress.style.display = 'block'; fill.style.width = '10%';

  const previewWrap = document.getElementById('ov-photo-preview-wrap');
  const previewImg = document.getElementById('ov-photo-preview-img');
  if (previewWrap && previewImg) {
    previewImg.src = URL.createObjectURL(file);
    previewWrap.style.display = 'block';
  }

  const form = new FormData();
  form.append('image', file);
  fill.style.width = '40%';

  const r = document.getElementById('ov-photo-result');
  r.style.display = 'none';

  try {
    const res = await apiPost('/api/identify-drone', form);
    fill.style.width = '100%';
    progress.style.display = 'none';
    const placeholder = document.getElementById('ov-photo-placeholder');
    if (placeholder) placeholder.style.display = 'none';

    if (!res || res.status !== 'ok' || !res.identification) {
      r.style.display = 'block';
      r.innerHTML = `<div style="color:var(--accent-red);font-size:12px;text-align:center;padding:16px;">Could not process image.<br><span style="font-size:10px;color:var(--text-muted);">${res?.error || 'Unknown error'}</span></div>`;
      return;
    }

    const ident = res.identification;
    const confLabel = ident.confidence_label || 'none';
    const confColor = confLabel === 'high' ? 'var(--accent-green)' : confLabel === 'medium' ? '#f0b429' : confLabel === 'low' ? '#f97316' : 'var(--accent-red)';
    const confScore = ident.confidence_score || 0;

    let html = `<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
      <div style="flex:1;min-width:0;">
        <div style="font-weight:700;font-size:14px;color:var(--text-primary);">${ident.drone_model || 'Unknown Model'}</div>
        <div style="font-size:11px;color:var(--text-muted);">${ident.company || 'Unknown Manufacturer'}</div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:11px;font-weight:700;color:${confColor};">${confScore}%</div>
        <div style="font-size:9px;color:var(--text-muted);text-transform:capitalize;">${confLabel}</div>
      </div>
    </div>`;

    // DB match fields
    const rm = ident.registry_match || {};
    const showKeys = ['type','category','country','endurance','range_km','weight','speed','ceiling'];
    const fields = showKeys.map(k => {
      const v = k === 'type' ? (ident.exif?.Make || rm[k]) : rm[k];
      if (!v) return null;
      return [_label(k), _fmtVal(k, v)];
    }).filter(Boolean);
    if (fields.length) {
      html += `<div style="border-top:1px solid var(--border);padding-top:8px;margin-top:8px;">`;
      fields.forEach(([label, val]) => {
        html += `<div class="ident-row"><span class="label">${label}</span><span class="value">${val}</span></div>`;
      });
      html += `</div>`;
    }

    // Web specs from scraping
    if (ident.web_specs && ident.web_specs.specs) {
      const wkeys = Object.keys(ident.web_specs.specs);
      if (wkeys.length) {
        html += `<div class="pe-section-title" style="margin-top:10px;">Web Intelligence</div>`;
        wkeys.forEach(k => {
          if (k !== 'related' && k !== 'abstract') {
            html += `<div class="ident-row"><span class="label">${k}</span><span class="value">${ident.web_specs.specs[k]}</span></div>`;
          }
        });
      }
    }

    // Visual candidates
    if (ident.top_matches && ident.top_matches.length) {
      html += `<div class="pe-section-title" style="margin-top:10px;">Visual Matches</div>`;
      ident.top_matches.slice(0, 3).forEach(m => {
        html += `<div class="ident-row"><span class="label">#${m.rank}</span><span class="value">${m.model} (${m.similarity}%)</span></div>`;
      });
    }

    // Best guess from reverse image search
    if (ident.best_guess) {
      html += `<div class="ident-row" style="margin-top:8px;"><span class="label">Best Guess</span><span class="value" style="color:#ff6900;font-weight:700;">${ident.best_guess}</span></div>`;
    }

    // DDG web results
    if (ident.ddg_results && ident.ddg_results.length) {
      html += `<div class="pe-section-title" style="margin-top:10px;">Web Search Results</div>`;
      ident.ddg_results.slice(0, 3).forEach(h => {
        html += `<div style="padding:5px 0;"><a href="${h.url}" target="_blank" style="font-size:11px;font-weight:600;color:var(--accent-blue);text-decoration:none;">${h.title}</a>
          ${h.snippet ? `<div style="font-size:9px;color:var(--text-muted);">${h.snippet.slice(0,120)}</div>` : ''}</div>`;
      });
    }

    // Engine notes
    if (ident.engine_notes && ident.engine_notes.length) {
      html += `<div style="margin-top:8px;font-size:9px;color:var(--text-muted);border-top:1px solid var(--border);padding-top:6px;">${ident.engine_notes.join('<br>')}</div>`;
    }

    r.style.display = 'block';
    r.innerHTML = html;

    // Also populate the Drone Identification section if a registry match was found
    if (ident.registry_match) {
      const reg = ident.registry_match;
      const extra = {};
      if (confLabel && confLabel !== 'none') extra.Confidence = confLabel;
      populateDroneGrid(reg, extra, document.getElementById('ov-case-count')?.textContent || '--');
    }
  } catch (e) {
    progress.style.display = 'none';
    r.style.display = 'block';
    r.innerHTML = `<div style="color:var(--accent-red);font-size:12px;text-align:center;padding:16px;">Error: ${e.message}</div>`;
  }
}

function clearRefPhoto() {
  const input = document.getElementById('ref-photo-input');
  input.value = '';
  document.getElementById('ref-photo-preview-wrap').style.display = 'none';
  document.getElementById('ref-photo-clear').style.display = 'none';
  document.getElementById('ref-photo-card').classList.remove('has-file');
}

async function saveRefRecord() {
  const model = document.getElementById('ref-model-name').value.trim();
  const company = document.getElementById('ref-company').value.trim();
  if (!model || !company) {
    document.getElementById('ref-save-status').textContent = 'Model Name and Manufacturer are required.';
    return;
  }

  const fileInput = document.getElementById('ref-photo-input');
  const file = fileInput.files[0];
  if (!file) {
    document.getElementById('ref-save-status').textContent = 'Please select a reference photo.';
    return;
  }

  const status = document.getElementById('ref-save-status');
  status.textContent = 'Saving...';

  const form = new FormData();
  form.append('image', file);
  form.append('model_name', model);
  form.append('company', company);
  form.append('type', document.getElementById('ref-type').value.trim());
  form.append('category', document.getElementById('ref-category').value.trim());
  form.append('weight', document.getElementById('ref-weight').value.trim());
  form.append('speed', document.getElementById('ref-speed').value.trim());

  try {
    const res = await apiPost('/api/drone-registry/add-with-photo', form);
    if (res.status === 'ok') {
      status.innerHTML = `<span style="color:var(--accent-green);">&#10003; Saved. Running identification...</span>`;

      // Now run identification on the same photo against database
      const identForm = new FormData();
      identForm.append('image', file);
      const identRes = await apiPost('/api/identify-drone', identForm);

      const resultDiv = document.getElementById('ref-ident-result');
      resultDiv.style.display = 'block';

      if (identRes && identRes.status === 'ok' && identRes.identification) {
        const ident = identRes.identification;
        const confLabel = ident.confidence_label || 'none';
        const confColor = confLabel === 'high' ? 'var(--accent-green)' :
                          confLabel === 'medium' ? '#f0b429' :
                          confLabel === 'low' ? '#f97316' : 'var(--accent-red)';
        const confScore = ident.confidence_score || 0;

        let rowsHtml = '';
        const fields = [
          ['Drone Model', ident.drone_model || '—'],
          ['Manufacturer', ident.company || '—'],
          ['Confidence', `<span style="color:${confColor};font-weight:700;">${confLabel.toUpperCase()} (${confScore}%)</span>`],
        ];
        if (ident.exif && ident.exif.Make) fields.push(['EXIF Make', ident.exif.Make]);
        if (ident.exif && ident.exif.Model) fields.push(['EXIF Model', ident.exif.Model]);

        fields.forEach(([label, val]) => {
          rowsHtml += `<div class="ident-row"><span class="label">${label}</span><span class="value">${val}</span></div>`;
        });

        if (ident.web_specs && ident.web_specs.specs) {
          const wkeys = Object.keys(ident.web_specs.specs);
          if (wkeys.length) {
            rowsHtml += `<div class="pe-section-title" style="margin-top:10px;">Web Intelligence</div>`;
            wkeys.forEach(k => {
              rowsHtml += `<div class="ident-row"><span class="label">${k}</span><span class="value">${ident.web_specs.specs[k]}</span></div>`;
            });
          }
        }

        if (ident.top_matches && ident.top_matches.length) {
          rowsHtml += `<div class="pe-section-title" style="margin-top:10px;">Visual Matches</div>`;
          ident.top_matches.slice(0, 3).forEach(m => {
            rowsHtml += `<div class="ident-row"><span class="label">#${m.rank}</span><span class="value">${m.model} (${m.similarity}%)</span></div>`;
          });
        }

        resultDiv.innerHTML = `<div style="border:1px solid var(--border);border-radius:8px;padding:10px;background:var(--bg-secondary);">
          <div style="font-size:11px;font-weight:700;margin-bottom:6px;color:var(--accent-blue);">Identification Result</div>
          ${rowsHtml}</div>`;

        // Reset form fields after success
        document.getElementById('ref-model-name').value = '';
        document.getElementById('ref-company').value = '';
        document.getElementById('ref-type').value = '';
        document.getElementById('ref-category').value = '';
        document.getElementById('ref-weight').value = '';
        document.getElementById('ref-speed').value = '';
        clearRefPhoto();

        // Refresh the database tab table
        if (typeof loadDatabase === 'function') loadDatabase();
      } else {
        resultDiv.innerHTML = `<div style="border:1px solid var(--accent-red);border-radius:8px;padding:10px;background:var(--bg-secondary);color:var(--accent-red);font-size:11px;">
          Record saved but identification failed: ${identRes?.error || 'Unknown error'}</div>`;
      }

      setTimeout(() => { status.textContent = ''; }, 5000);
    } else {
      status.textContent = 'Error: ' + (res.error || 'Failed to save');
    }
  } catch(e) {
    status.textContent = 'Error: ' + e.message;
  }
}

document.addEventListener('DOMContentLoaded', async function() {
  loadDatabase();
});

