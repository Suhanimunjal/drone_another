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
        var dashUrl = (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")
          ? "http://localhost:" + (user.role === "investigator" ? 5003 : (user.role === "admin" ? 5001 : 5002))
          : "/overview";
        topRight.innerHTML =
          '<a href="' + dashUrl + '" class="login-btn" style="background:var(--accent-teal);color:#04241A;padding:8px 16px;border-radius:6px;font-size:13.5px;font-weight:500;text-decoration:none;margin-left:12px;">Dashboard</a>';
      } else {
        topRight.innerHTML = '';
      }
    })
    .catch(function () {
      // ignore
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
          if (user) {
            var dashUrl = (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")
              ? "http://localhost:" + (user.role === "investigator" ? 5003 : (user.role === "admin" ? 5001 : 5002)) + "/overview"
              : "/overview";
            window.location.href = dashUrl;
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
})();
