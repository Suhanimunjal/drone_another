(function () {
  var DATA = [];
  var FOCUS = -1;
  var user = null;

  // ── Session check ──
  fetch("/api/session")
    .then(function (r) { return r.json(); })
    .then(function (d) {
      user = d && d.user ? d.user : null;
      var el = document.getElementById("top-right");
      if (user) {
        var dashPort = user.role === "investigator" ? 5003 : (user.role === "admin" ? 5001 : 5002);
        el.innerHTML =
          '<a href="http://localhost:' + dashPort + '" class="login-btn">Dashboard</a>';
      } else {
        el.innerHTML = '<a href="/login" class="login-btn">Log in</a>';
      }
    });

  // ── Load data ──
  fetch("/api/drone-registry/query?q=")
    .then(function (r) { return r.json(); })
    .then(function (d) {
      DATA = (d && d.drones) || [];
      // Populate stats
      var companies = {}, cats = {};
      for (var i = 0; i < DATA.length; i++) {
        var dr = DATA[i];
        var extra = dr.extra || {};
        var comp = dr.company || extra.manufacturer || "Unknown";
        var cat = dr.category || extra.category || "Other";
        companies[comp] = true;
        cats[cat] = true;
      }
      var statDrones = document.getElementById("stat-drones");
      var statMfgs = document.getElementById("stat-manufacturers");
      var statCats = document.getElementById("stat-categories");
      if (statDrones) statDrones.textContent = DATA.length;
      if (statMfgs) statMfgs.textContent = Object.keys(companies).length;
      if (statCats) statCats.textContent = Object.keys(cats).length;
      var eyebrow = document.getElementById("result-count");
      if (eyebrow) eyebrow.textContent = DATA.length + " drones on record";
    });

  function score(d, tokens) {
    if (!tokens.length) return 1;
    var extra = d.extra || {};
    var modelName = (d.model_name || "").toLowerCase();
    var company   = (d.company || extra.manufacturer || "").toLowerCase();
    var category  = (d.category || extra.category || "").toLowerCase();
    var type      = (d.type || extra.type || "").toLowerCase();
    var country   = (d.country || extra.country_of_origin || "").toLowerCase();
    var modelNo   = (extra.model_no || "").toLowerCase();
    var extraValues = Object.values(extra).filter(function(v){ return v != null; }).map(function(v){ return String(v).toLowerCase(); }).join(" ");
    var allText   = [modelName, company, category, type, country, modelNo, extraValues].join(" ");
    var score = 0;
    for (var i = 0; i < tokens.length; i++) {
      var tok = tokens[i];
      if (allText.indexOf(tok) === -1) return -1;
      if (modelName === tok) score += 100;
      else if (modelName.indexOf(tok) === 0) score += 80;
      else if (modelName.indexOf(tok) !== -1) score += 50;
      if (company.indexOf(tok) !== -1) score += 30;
      if (category.indexOf(tok) !== -1) score += 20;
      if (type.indexOf(tok) !== -1) score += 15;
      if (country.indexOf(tok) !== -1) score += 10;
      if (modelNo.indexOf(tok) !== -1) score += 25;
    }
    return score;
  }

  function highlight(text, tokens) {
    if (!text) return "";
    var safe = esc(text);
    if (!tokens.length) return safe;
    var pattern = tokens.map(function (t) { return t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }).join("|");
    if (!pattern) return safe;
    return safe.replace(new RegExp("(" + pattern + ")", "gi"),
      '<mark style="background:rgba(55,211,153,0.25);color:var(--text);border-radius:2px;padding:0 1px;">$1</mark>');
  }

  function esc(str) {
    var d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
  }

  function showDropdown(q) {
    var dd = document.getElementById("registry-dropdown");
    if (!dd) return;
    FOCUS = -1;
    var tokens = q.toLowerCase().split(/\s+/).filter(Boolean);

    var scored = DATA
      .map(function (d) { return { d: d, score: score(d, tokens) }; })
      .filter(function (x) { return x.score > 0; })
      .sort(function (a, b) { return b.score - a.score; })
      .slice(0, 20);

    if (!scored.length) {
      dd.innerHTML = '<li style="color:var(--text-muted);font-style:italic;cursor:default;">No results</li>';
      dd.style.display = "block";
      return;
    }

    dd.innerHTML = scored.map(function (x, i) {
      var d = x.d;
      var extra = d.extra || {};
      var label = highlight(d.model_name || "", tokens);
      var company = d.company || extra.manufacturer || "";
      var catInfo = [d.type, d.category, extra.category || ""].filter(Boolean).join(" &middot; ");
      return '<li data-id="' + d.id + '" data-idx="' + i + '">' +
        '<span class="dd-model">' + label + '</span>' +
        (company ? '<span class="dd-company">' + esc(company) + '</span>' : "") +
        (catInfo ? '<span class="dd-cat">' + esc(catInfo) + '</span>' : "") +
        "</li>";
    }).join("");

    dd.style.display = "block";
  }

  function closeDropdown() {
    var dd = document.getElementById("registry-dropdown");
    if (dd) dd.style.display = "none";
  }

  function selectDrone(id) {
    window.location.href = "/physical-evidence/drone/" + id;
  }

  window.psSearchInput = function (input) {
    showDropdown(input.value.trim());
  };

  window.psSearchFocus = function (input) {
    showDropdown(input.value.trim());
  };

  window.psSearchKeydown = function (e) {
    var dd = document.getElementById("registry-dropdown");
    if (!dd || dd.style.display === "none") return;
    var items = dd.querySelectorAll("li[data-idx]");
    if (!items.length) return;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      FOCUS = Math.min(FOCUS + 1, items.length - 1);
      items.forEach(function (li, i) { li.style.background = i === FOCUS ? "rgba(55,211,153,0.1)" : ""; });
      if (items[FOCUS]) items[FOCUS].scrollIntoView({ block: "nearest" });
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      FOCUS = Math.max(FOCUS - 1, 0);
      items.forEach(function (li, i) { li.style.background = i === FOCUS ? "rgba(55,211,153,0.1)" : ""; });
      if (items[FOCUS]) items[FOCUS].scrollIntoView({ block: "nearest" });
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (FOCUS >= 0 && items[FOCUS]) {
        selectDrone(parseInt(items[FOCUS].getAttribute("data-id")));
      }
    } else if (e.key === "Escape") {
      closeDropdown();
    }
  };

  document.addEventListener("click", function (e) {
    var dd = document.getElementById("registry-dropdown");
    var input = document.getElementById("registry-search");
    var li = e.target.closest ? e.target.closest("#registry-dropdown li") : null;
    if (li && dd && dd.contains(li)) {
      e.preventDefault();
      selectDrone(parseInt(li.getAttribute("data-id")));
    } else if (input && !input.contains(e.target) && dd && !dd.contains(e.target)) {
      dd.style.display = "none";
    }
  });

  // ── Import flow ──
  function setStatus(msg, isError) {
    var el = document.getElementById("import-status");
    if (!el) return;
    el.textContent = msg;
    el.style.color = isError ? "var(--status-danger)" : "var(--text-muted)";
  }

  window.psImport = function () {
    document.getElementById("registry-import-file").click();
  };

  window.psHandleImport = function (input) {
    if (!input.files.length) return;
    var file = input.files[0];
    var form = new FormData();
    form.append("file", file);

    setStatus("Parsing " + file.name + "...");

    fetch("/api/drone-registry/import-preview", {
      method: "POST", body: form, credentials: "include"
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { setStatus("Error: " + d.error, true); return; }
      showImportPreview(d, file.name);
    })
    .catch(function (err) {
      setStatus("Import failed: " + (err && err.message ? err.message : "connection error"), true);
    });
  };

  function showImportPreview(res, filename) {
    var container = document.getElementById("import-preview-container");
    setStatus("");

    var html = '<div class="import-overlay" id="import-overlay">';
    html += '<div class="import-modal">';
    html += '<div class="import-modal-header">';
    html += '<h3>Import Preview</h3>';
    html += '<button class="import-close" onclick="psCloseImport()">&times;</button>';
    html += '</div>';
    html += '<div class="import-modal-body">';

    html += '<div style="margin-bottom:12px;font-size:13px;color:var(--text-secondary);">';
    html += 'File: <strong style="color:var(--text);">' + esc(filename) + '</strong>';
    html += ' &middot; <strong style="color:var(--text);">' + (res.total_rows || 0) + '</strong> rows';
    html += '</div>';

    if (res.malformed_rows && res.malformed_rows.length) {
      html += '<div style="background:rgba(228,91,91,0.08);border:1px solid rgba(228,91,91,0.3);border-radius:6px;padding:10px;margin-bottom:12px;max-height:80px;overflow-y:auto;">';
      html += '<strong style="color:var(--status-danger);font-size:11px;font-family:var(--font-mono);">Malformed Rows:</strong>';
      for (var i = 0; i < res.malformed_rows.length; i++) {
        var m = res.malformed_rows[i];
        html += '<div style="font-size:10px;color:var(--text-muted);">Row ' + m.row_number + ': ' + esc(m.error) + '</div>';
      }
      html += '</div>';
    }

    var mappings = res.mappings || {};
    var mappingKeys = Object.keys(mappings);
    if (mappingKeys.length) {
      html += '<div style="margin-bottom:12px;">';
      html += '<div style="font-size:12px;font-weight:500;margin-bottom:6px;color:var(--text);">Column Mappings</div>';
      html += '<table style="width:100%;font-size:11px;border-collapse:collapse;">';
      html += '<tr><th style="text-align:left;padding:4px 8px;border-bottom:1px solid var(--border);color:var(--text-muted);font-family:var(--font-mono);">Column</th><th style="text-align:left;padding:4px 8px;border-bottom:1px solid var(--border);color:var(--text-muted);font-family:var(--font-mono);">Maps To</th></tr>';
      for (var i = 0; i < mappingKeys.length; i++) {
        var col = mappingKeys[i];
        var mapsTo = mappings[col];
        html += '<tr><td style="padding:4px 8px;border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:11px;">' + esc(col) + '</td>';
        html += '<td style="padding:4px 8px;border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:11px;color:' + (mapsTo ? 'var(--accent-teal)' : 'var(--status-danger)') + ';">' + esc(mapsTo || 'Unmapped') + '</td></tr>';
      }
      html += '</table>';
      html += '</div>';
    }

    var pRows = res.preview_rows || [];
    if (pRows.length) {
      html += '<div style="margin-bottom:12px;">';
      html += '<div style="font-size:12px;font-weight:500;margin-bottom:6px;color:var(--text);">Data Preview (first ' + Math.min(5, pRows.length) + ' of ' + res.total_rows + ' rows)</div>';
      html += '<div style="max-height:200px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--radius-sm);">';
      html += '<table style="width:100%;font-size:11px;border-collapse:collapse;">';
      var hdrs = res.headers || [];
      if (hdrs.length) {
        html += '<tr>';
        for (var i = 0; i < hdrs.length; i++) {
          html += '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid var(--border);color:var(--text-muted);white-space:nowrap;font-family:var(--font-mono);font-size:10.5px;">' + esc(hdrs[i]) + '</th>';
        }
        html += '</tr>';
      }
      for (var ri = 0; ri < Math.min(5, pRows.length); ri++) {
        html += '<tr>';
        var row = pRows[ri];
        for (var ci = 0; ci < hdrs.length; ci++) {
          var val = row[hdrs[ci]] !== undefined ? row[hdrs[ci]] : "";
          html += '<td style="padding:4px 8px;border-bottom:1px solid var(--border);font-size:11px;">' + esc(val) + '</td>';
        }
        html += '</tr>';
      }
      html += '</table>';
      html += '</div>';
      html += '</div>';
    }

    html += '</div>';
    html += '<div class="import-modal-footer">';
    html += '<button class="btn-primary" onclick="psConfirmImport(\'' + esc(res.temp_id || "") + '\')">Confirm Import</button>';
    html += '<button class="btn-ghost" onclick="psCloseImport()" style="margin-left:8px;">Cancel</button>';
    html += '</div>';
    html += '</div>';
    html += '</div>';

    container.innerHTML = html;
  }

  window.psCloseImport = function () {
    document.getElementById("import-preview-container").innerHTML = "";
    document.getElementById("registry-import-file").value = "";
  };

  window.psConfirmImport = function (tempId) {
    if (!tempId) { setStatus("No import data to confirm.", true); return; }

    var confirmBtn = document.querySelector("#import-overlay .btn-primary");
    if (confirmBtn) { confirmBtn.disabled = true; confirmBtn.textContent = "Importing..."; }

    fetch("/api/drone-registry/import-confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ temp_id: tempId }),
      credentials: "include"
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { setStatus("Error: " + d.error, true); psCloseImport(); return; }
      setStatus("Imported " + (d.imported_rows || "?") + " records.");
      fetch("/api/drone-registry/query?q=")
        .then(function (r) { return r.json(); })
        .then(function (d) { if (d) DATA = d.drones || []; });
      psCloseImport();
    })
    .catch(function () { setStatus("Confirm failed.", true); });
  };

  window.psAddRecord = function () {
    if (user) {
      var dashPort = user.role === "investigator" ? 5003 : (user.role === "admin" ? 5001 : 5002);
      window.location.href = "http://localhost:" + dashPort + "/overview";
      return;
    }
    window.location.href = "/login?next=" + encodeURIComponent(window.location.pathname);
  };

  window.psImageLookup = function () {
    if (user) { document.getElementById("ov-photo-input").click(); return; }
    window.location.href = "/login?next=" + encodeURIComponent(window.location.pathname);
  };

  window.psHandlePhoto = function (input) {
    if (!input.files.length) return;
    if (!user) {
      window.location.href = "/login?next=" + encodeURIComponent(window.location.pathname);
      return;
    }
    setStatus("Photo upload requires the dashboard. Log in and use Image Lookup from there.", true);
    input.value = "";
  };
})();
