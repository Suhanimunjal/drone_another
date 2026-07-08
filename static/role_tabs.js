/*
role_tabs.js
Renders the sidebar based on the logged-in user's role. Simple flat
model — no locked tabs, no request-access flow. A role either sees a
tab or doesn't. The investigator additionally gets an "Upload Evidence
Photo" action on the Overview page even though they have no other tabs.

Pulls the allowed-sections list from /api/my-access rather than
hardcoding the role map here too, so frontend and backend can't drift
out of sync with each other.
*/

async function applyRoleBasedUI() {
  let access;
  try {
    const res = await fetch("/api/my-access", { credentials: 'include' });
    if (!res.ok) throw new Error(`status ${res.status}`);
    access = await res.json();
  } catch (err) {
    console.error("Could not load role/access info:", err);
    return;
  }

  const { role, allowed_sections, can_upload_evidence_photo } = access;

  // Hide every sidebar tab not in this role's allowed list.
  document.querySelectorAll("[data-section]").forEach(tab => {
    const key = tab.dataset.section;
    tab.style.display = allowed_sections.includes(key) ? "" : "none";
  });

  // Admin panel entry
  const adminTab = document.querySelector('[data-section="admin"]');
  if (adminTab) {
    adminTab.style.display = allowed_sections.includes("admin") ? "" : "none";
  }

  console.log(`Role-based UI applied for role="${role}", sections=[${allowed_sections.join(", ")}]`);
}

async function uploadEvidencePhoto(fileInputEl) {
  const file = fileInputEl.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append("photo", file);

  try {
    const res = await fetch("/api/evidence-photo/upload", {
      method: "POST",
      body: formData,
    });
    const data = await res.json();
    if (res.ok) {
      alert("Photo uploaded successfully.");
    } else {
      alert(data.error || "Upload failed.");
    }
  } catch (err) {
    console.error("Evidence photo upload failed:", err);
    alert("Something went wrong uploading the photo — please try again.");
  }
}

window.addEventListener("DOMContentLoaded", applyRoleBasedUI);
