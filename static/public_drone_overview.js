(function () {
  var droneId = window.location.pathname.match(/\/physical-evidence\/drone\/([^/]+)/);
  if (!droneId) return;
  droneId = droneId[1];

  var loadingEl = document.getElementById("loading-state");
  var notFoundEl = document.getElementById("not-found");
  var contentEl = document.getElementById("drone-content");
  var detailContainer = document.getElementById("drone-detail-container");
  var createBtn = document.getElementById("create-case-btn");
  var errorEl = document.getElementById("create-case-error");

  var user = null;

  // Check session
  fetch("/api/session")
    .then(function (r) { return r.json(); })
    .then(function (data) {
      user = data && data.user ? data.user : null;
      var topRight = document.getElementById("top-right");
      if (user) {
        topRight.innerHTML =
          '<span style="color:#8b949e;font-size:13px;">' + escapeHtml(user.username) + '</span>' +
          ' &middot; <a href="/overview" style="color:#58a6ff;text-decoration:none;">Dashboard</a>';
      } else {
        topRight.innerHTML =
          '<a href="/login?next=' + encodeURIComponent(window.location.pathname) +
          '" style="color:#58a6ff;text-decoration:none;font-size:13px;">Log in</a>';
      }
    })
    .catch(function () {
      var topRight = document.getElementById("top-right");
      topRight.innerHTML =
        '<a href="/login?next=' + encodeURIComponent(window.location.pathname) +
        '" style="color:#58a6ff;text-decoration:none;font-size:13px;">Log in</a>';
    });

  // Fetch drone data
  fetch("/api/public/drones/" + encodeURIComponent(droneId))
    .then(function (r) {
      if (!r.ok) throw new Error("not found");
      return r.json();
    })
    .then(function (drone) {
      loadingEl.style.display = "none";
      contentEl.style.display = "block";

      // Render full detailed view using the same renderer the dashboard uses
      renderDroneRecord(detailContainer, drone, {
        onEdit: function (row) {
          // On the public page, redirect to login if not authenticated
          if (user) {
            window.location.href = "/overview";
          } else {
            window.location.href = "/login?next=" + encodeURIComponent(window.location.pathname);
          }
        },
      });
    })
    .catch(function () {
      loadingEl.style.display = "none";
      notFoundEl.style.display = "block";
    });

  // Create case handler
  createBtn.addEventListener("click", function () {
    if (user) {
      createBtn.disabled = true;
      createBtn.textContent = "Creating case...";
      errorEl.style.display = "none";

      fetch("/api/cases", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ drone_id: parseInt(droneId, 10) }),
      })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data.case_id) {
            window.location.href = "/cases/" + data.case_id;
          } else {
            showError(data.error || "Failed to create case");
            createBtn.disabled = false;
            createBtn.textContent = "Create case";
          }
        })
        .catch(function () {
          showError("Network error");
          createBtn.disabled = false;
          createBtn.textContent = "Create case";
        });
    } else {
      window.location.href = "/login?next=" + encodeURIComponent(
        "/physical-evidence/drone/" + droneId + "/create-case"
      );
    }
  });

  function showError(msg) {
    errorEl.textContent = msg;
    errorEl.style.display = "block";
  }

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
})();
