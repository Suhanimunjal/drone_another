const DRONE_DETAIL_PATTERN = /^physical-evidence\/drone\/([^/]+)$/;
const DISK_IMAGE_DETAIL_PATTERN = /^physical-evidence\/disk-image\/([^/]+)$/;

function activatePhysicalEvidenceTab() {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const navItem = document.querySelector('.nav-item[data-tab="physical"]');
  if (navItem) navItem.classList.add('active');

  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  const pane = document.getElementById('pane-physical');
  if (pane) pane.classList.add('active');
}

function navigateToDroneDetail(droneId) {
  history.pushState({ droneId }, "", `/physical-evidence/drone/${encodeURIComponent(droneId)}`);
  activatePhysicalEvidenceTab();
  showDroneDetail(droneId);
}

function navigateToDroneList() {
  history.pushState({}, "", "/physical-evidence");
  activatePhysicalEvidenceTab();
  showDroneList();
}

function activateDiskImageTab() {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const navItem = document.querySelector('.nav-item[data-tab="disk-image"]');
  if (navItem) navItem.classList.add('active');

  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  const pane = document.getElementById('pane-disk-image');
  if (pane) pane.classList.add('active');
}

function handleCurrentPath() {
  const path = window.location.pathname.replace(/^\/+/, "");
  const diMatch = path.match(DISK_IMAGE_DETAIL_PATTERN);
  if (diMatch) {
    activateDiskImageTab();
    if (typeof loadDiskImageBrowse === 'function') {
      loadDiskImageBrowse(diMatch[1]);
    }
    return;
  }
  const match = path.match(DRONE_DETAIL_PATTERN);
  if (match) {
    activatePhysicalEvidenceTab();
    showDroneDetail(match[1]);
  } else if (path === "physical-evidence" || path.startsWith("physical-evidence/")) {
    activatePhysicalEvidenceTab();
    showDroneList();
  }
}

window.addEventListener("popstate", handleCurrentPath);
window.addEventListener("DOMContentLoaded", handleCurrentPath);
