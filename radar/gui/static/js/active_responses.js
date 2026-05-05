"use strict";

function updateWeightTotal() {
  const ad = parseFloat(document.getElementById("w_ad")?.value || 0);
  const sig = parseFloat(document.getElementById("w_sig")?.value || 0);
  const cti = parseFloat(document.getElementById("w_cti")?.value || 0);
  const total = Math.round((ad + sig + cti) * 100) / 100;
  const totalEl = document.getElementById("weight-total");
  const warnEl = document.getElementById("weight-warn");
  if (!totalEl) return;
  totalEl.textContent = total.toFixed(2);
  const ok = Math.abs(total - 1.0) < 0.001;
  totalEl.className = "weight-total" + (ok ? "" : " weight-total--bad");
  if (warnEl) warnEl.style.display = ok ? "none" : "";
}

function validateTiers() {
  const t1 = parseFloat(document.getElementById("tier1_max")?.value || 0.33);
  const t2 = parseFloat(document.getElementById("tier2_max")?.value || 0.66);
  const t3 = parseFloat(document.getElementById("tier3_max")?.value || 0.85);
  const warn = document.getElementById("tier-warn");
  const valid = t1 < t2 && t2 < t3 && t3 < 1.0;
  if (warn) warn.style.display = valid ? "none" : "";
  return valid;
}

function addMitTag(selectEl, listId) {
  const value = selectEl.value;
  if (!value) return;
  selectEl.value = "";

  const list = document.getElementById(listId);
  if (!list) return;

  const existing = Array.from(list.querySelectorAll(".mit-tag")).map(t => t.dataset.value);
  if (existing.includes(value)) return;

  const tag = document.createElement("span");
  tag.className = "mit-tag";
  tag.dataset.value = value;
  tag.innerHTML = `${value}<button type="button" class="mit-tag-remove" onclick="removeMitTag(this)">&#10005;</button>`;
  list.appendChild(tag);
}

function removeMitTag(btn) {
  btn.closest(".mit-tag").remove();
}

function _readTags(listId) {
  const list = document.getElementById(listId);
  if (!list) return [];
  return Array.from(list.querySelectorAll(".mit-tag")).map(t => t.dataset.value);
}

function _collectSignatureLikelihood() {
  const hiddenEl = document.getElementById("signature_likelihood");
  if (!hiddenEl) return null;
  if (hiddenEl.value === "__list__") {
    const rows = document.querySelectorAll(".sl-weight-input");
    if (!rows.length) return null;
    const list = [];
    rows.forEach(input => {
      const ruleIds = (input.dataset.ruleIds || "").split(",")
        .map(r => parseInt(r.trim())).filter(r => !isNaN(r));
      list.push({ rule_id: ruleIds, weight: parseFloat(input.value) });
    });
    return list;
  }
  const val = parseFloat(hiddenEl.value);
  return isNaN(val) ? null : val;
}

function _setMsg(msg, ok) {
  const el = document.getElementById("save-msg");
  if (!el) return;
  el.textContent = msg;
  el.className = "ar-footer__msg" + (ok ? " ar-footer__msg--ok" : " ar-footer__msg--err");
}

async function saveConfig() {
  const scenarioId = document.getElementById("active-scenario-id")?.value;
  if (!scenarioId) return;

  const ad = parseFloat(document.getElementById("w_ad")?.value || 0);
  const sig = parseFloat(document.getElementById("w_sig")?.value || 0);
  const cti = parseFloat(document.getElementById("w_cti")?.value || 0);
  const total = Math.round((ad + sig + cti) * 100) / 100;
  if (Math.abs(total - 1.0) > 0.001) {
    _setMsg("Weights must sum to 1.0 — currently " + total.toFixed(2), false);
    return;
  }

  if (!validateTiers()) {
    _setMsg("Tier thresholds must be strictly increasing (T1 < T2 < T3 < 1.0)", false);
    return;
  }

  const sl = _collectSignatureLikelihood();

  const patch = {
    w_ad: ad,
    w_sig: sig,
    w_cti: cti,
    delta_ad_minutes: parseInt(document.getElementById("delta_ad_minutes")?.value || 10),
    delta_signature_minutes: parseInt(document.getElementById("delta_signature_minutes")?.value || 1),
    signature_impact: parseFloat(document.getElementById("signature_impact")?.value || 0.5),
    tiers: {
      tier1_max: parseFloat(document.getElementById("tier1_max")?.value || 0.33),
      tier2_max: parseFloat(document.getElementById("tier2_max")?.value || 0.66),
      tier3_max: parseFloat(document.getElementById("tier3_max")?.value || 0.85),
    },
    mitigations_tier2: _readTags("mit-tags-2"),
    mitigations_tier3: _readTags("mit-tags-3"),
    mitigations_tier4: _readTags("mit-tags-4"),
    allow_mitigation: document.getElementById("allow_mitigation")?.checked || false,
  };

  if (sl !== null) patch.signature_likelihood = sl;

  try {
    const data = await window.RADAR.radarFetch(
      `/api/scenarios/${encodeURIComponent(scenarioId)}/ar-config`,
      { method: "PUT", body: JSON.stringify(patch) }
    );
    _setMsg(data.ok ? "Saved to ar.yaml" : (data.error || "Save failed"), data.ok);
  } catch (e) {
    _setMsg(e.message, false);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  updateWeightTotal();
  validateTiers();
});