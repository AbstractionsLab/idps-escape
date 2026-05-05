"use strict";

let activeType = "all";
let activeStatus = "all";

function applyFilters() {
  document.querySelectorAll("#scenarios-table tbody tr").forEach(row => {
    const type = row.dataset.type;
    const status = row.dataset.status;
    const matchT = activeType === "all" || type === activeType;
    const matchS = activeStatus === "all" || status === activeStatus;
    row.classList.toggle("row--hidden", !(matchT && matchS));
  });
  updateSummary();
}

document.querySelectorAll("[data-filter-type]").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("[data-filter-type]").forEach(b => b.classList.remove("pill--active"));
    btn.classList.add("pill--active");
    activeType = btn.dataset.filterType;
    applyFilters();
  });
});

document.querySelectorAll("[data-filter-status]").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("[data-filter-status]").forEach(b => b.classList.remove("pill--active"));
    btn.classList.add("pill--active");
    activeStatus = btn.dataset.filterStatus;
    applyFilters();
  });
});

function openBindModal(scenarioId, scenarioName) {
  document.getElementById("bind-scenario-id").value = scenarioId;
  document.getElementById("bind-modal-title").textContent = "Bind: " + scenarioName;
  document.getElementById("bind-error").textContent = "";
  document.querySelectorAll(".bind-mit-cb").forEach(cb => { cb.checked = false; });
  document.getElementById("bind-modal").style.display = "flex";
}

function closeBindModal(evt) {
  const modal = document.getElementById("bind-modal");
  if (evt && evt.target !== modal) return;
  modal.style.display = "none";
}

async function submitBind() {
  const scenarioId = document.getElementById("bind-scenario-id").value;
  const mitigations = Array.from(document.querySelectorAll(".bind-mit-cb:checked"))
    .map(cb => cb.value);

  document.getElementById("bind-error").textContent = "";

  try {
    const data = await window.RADAR.radarFetch(
      `/api/scenarios/${encodeURIComponent(scenarioId)}/bind`,
      { method: "POST", body: JSON.stringify({ mitigations }) }
    );
    if (data.ok) {
      document.getElementById("bind-modal").style.display = "none";
      setTimeout(() => location.reload(), 300);
    } else {
      document.getElementById("bind-error").textContent = data.error || "Bind failed";
    }
  } catch (e) {
    document.getElementById("bind-error").textContent = e.message;
  }
}

async function unbindScenario(scenarioId) {
  if (!confirm("Unbind this scenario? Its ar.yaml entry will be removed.")) return;
  try {
    const data = await window.RADAR.radarFetch(
      `/api/scenarios/${encodeURIComponent(scenarioId)}/unbind`,
      { method: "POST" }
    );
    if (data.ok) {
      setTimeout(() => location.reload(), 300);
    }
  } catch (e) {
    alert("Unbind failed: " + e.message);
  }
}

function updateSummary() {
  const el = document.getElementById("summary-text");
  if (!el) return;
  const rows = document.querySelectorAll("#scenarios-table tbody tr");
  let bound = 0, unbound = 0, demo = 0;
  rows.forEach(row => {
    if (row.dataset.status === "demo") { demo++; return; }
    if (row.dataset.bound === "true") bound++; else unbound++;
  });
  el.innerHTML =
    `<strong>${bound}</strong> bound &nbsp;&middot;&nbsp; <strong>${unbound}</strong> unbound &nbsp;&middot;&nbsp; <strong>${demo}</strong> demo`;
}

document.addEventListener("DOMContentLoaded", updateSummary);