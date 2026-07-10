function renderDroneSummaryCard(row) {
  const pills = [row.type, row.category].filter(Boolean);

  const card = document.createElement("div");
  card.className = "drv-summary-card";
  card.innerHTML = `
    <div class="drv-summary-thumb drv-summary-thumb-empty">no photo on file</div>
    <div class="drv-summary-body">
      <p class="drv-summary-model">${escapeHtml(row.model_name || row.id)}</p>
      <p class="drv-summary-manufacturer">${escapeHtml(row.company || "Unknown")}</p>
      ${pills.map(p => `<span class="drv-summary-confidence">${escapeHtml(p)}</span>`).join(" ")}
    </div>`;

  card.addEventListener("click", () => navigateToDroneDetail(row.id));
  return card;
}

function renderDroneListView(gridEl, droneRows) {
  if (!gridEl) return;
  gridEl.innerHTML = "";
  gridEl.className = "drv-summary-grid";

  if (!droneRows || droneRows.length === 0) {
    gridEl.innerHTML = `<p class="drv-summary-empty">No drone records yet.</p>`;
    return;
  }
  droneRows.forEach(row => gridEl.appendChild(renderDroneSummaryCard(row)));
}

async function loadDroneBrowseList() {
  const listContainer = document.getElementById("drone-list-container");
  if (!listContainer) return;

  try {
    const res = await fetch("/api/drone-registry/query");
    if (!res.ok) throw new Error(`status ${res.status}`);
    const data = await res.json();
    renderDroneListView(listContainer, data.drones);
  } catch (err) {
    console.error("Failed to load drone registry list:", err);
    listContainer.innerHTML = `<p class="drv-error">Could not load records.</p>`;
  }
}

async function showDroneDetail(droneId) {
  const listContainer = document.getElementById("drone-list-container");
  const detailContainer = document.getElementById("drone-detail-container");
  if (listContainer) listContainer.style.display = "none";
  if (detailContainer) detailContainer.style.display = "block";
  if (!detailContainer) return;
  detailContainer.innerHTML = `<p class="drv-loading">Loading record...</p>`;

  try {
    const res = await fetch(`/api/drone-registry/${encodeURIComponent(droneId)}`);
    if (!res.ok) throw new Error(`status ${res.status}`);
    const row = await res.json();

    const backBtn = document.createElement("button");
    backBtn.className = "drv-back-btn";
    backBtn.textContent = "< Back to all records";
    backBtn.addEventListener("click", navigateToDroneList);

    detailContainer.innerHTML = "";
    detailContainer.appendChild(backBtn);
    const recordDiv = document.createElement("div");
    detailContainer.appendChild(recordDiv);

    renderDroneRecord(recordDiv, row, {
      onEdit: (r) => openRegistryManualForm(true, r),
      onAddPhoto: (r) => {
        const existingInput = document.querySelector('#pane-physical input[type="file"]');
        if (existingInput) {
          existingInput.click();
        } else {
          alert("Photo upload isn't available from this view yet — use the main Physical Evidence upload panel.");
        }
      },
    });
  } catch (err) {
    console.error("Failed to load drone record:", err);
    detailContainer.innerHTML = ``;
  }
}

function showDroneList() {
  const listContainer = document.getElementById("drone-list-container");
  const detailContainer = document.getElementById("drone-detail-container");
  if (detailContainer) detailContainer.style.display = "none";
  if (listContainer) listContainer.style.display = "block";
  loadDroneBrowseList();
}
