"use strict";

function openModal(id) {
  document.getElementById(id).style.display = "flex";
}

function closeModal(evt, id) {
  if (evt && evt.target !== document.getElementById(id)) return;
  document.getElementById(id).style.display = "none";
}

function _setError(id, msg) {
  const el = document.getElementById(id);
  if (el) el.textContent = msg || "";
}

function _toast(msg, kind) {
  const host = document.getElementById("toast-host") || document.getElementById("global-toast-host");
  if (!host) return;
  const el = document.createElement("div");
  el.className = "toast toast--" + (kind || "ok");
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => el.classList.add("toast--out"), 2200);
  setTimeout(() => el.remove(), 2800);
}

async function _initVaultBanner() {
  try {
    const s = await fetch("/api/vault/status", { credentials: "same-origin" }).then(r => r.json());
    const banner = document.getElementById("vault-banner");
    const msg = document.getElementById("vault-banner-msg");
    const btnUnlock = document.getElementById("vault-banner-btn-unlock");
    const btnCreate = document.getElementById("vault-banner-btn-create");

    if (!banner) return;

    if (s.vault_exists && !s.unlocked) {
      msg.textContent = "Vault is locked. Unlock it to save or use sudo credentials for remote nodes.";
      btnUnlock.style.display = "";
      btnCreate.style.display = "none";
      banner.style.display = "";
      banner.className = "strip strip--amber";
    } else if (!s.vault_exists) {
      msg.textContent = "No vault configured. Set a vault password to securely store sudo credentials for remote nodes.";
      btnUnlock.style.display = "none";
      btnCreate.style.display = "";
      banner.style.display = "";
      banner.className = "strip strip--blue";
    } else {
      banner.style.display = "none";
    }
  } catch (_) {}
}

function openVaultCreate(onSuccess) {
  document.getElementById("vault-create-pw").value = "";
  document.getElementById("vault-create-pw2").value = "";
  _setError("vault-create-error", "");
  openModal("vault-create-modal");
  setTimeout(() => document.getElementById("vault-create-pw").focus(), 60);
  window._vaultCreateCallback = onSuccess || null;
}

async function submitVaultCreate() {
  _setError("vault-create-error", "");
  const pw = document.getElementById("vault-create-pw").value;
  const pw2 = document.getElementById("vault-create-pw2").value;
  if (!pw) return _setError("vault-create-error", "Password cannot be empty");
  if (pw !== pw2) return _setError("vault-create-error", "Passwords do not match");
  try {
    const data = await window.RADAR.radarFetch("/api/vault/create", {
      method: "POST",
      body: JSON.stringify({ password: pw }),
    });
    if (data.ok) {
      closeModal(null, "vault-create-modal");
      _toast("Vault password set — credentials can now be saved", "ok");
      _initVaultBanner();
      if (typeof window._vaultCreateCallback === "function") {
        window._vaultCreateCallback();
        window._vaultCreateCallback = null;
      }
    } else {
      _setError("vault-create-error", data.error || "Failed");
    }
  } catch (e) {
    _setError("vault-create-error", e.message);
  }
}

async function _ensureVault(onReady) {
  try {
    const s = await fetch("/api/vault/status", { credentials: "same-origin" }).then(r => r.json());
    if (s.unlocked) {
      onReady();
    } else if (s.vault_exists) {
      const ok = await window.RADAR.promptVaultUnlock();
      if (ok) onReady();
    } else {
      openVaultCreate(onReady);
    }
  } catch (_) {
    onReady();
  }
}

function toggleMgrFields() {
  const kind = document.getElementById("mgr-kind").value;
  const isLocal = document.getElementById("mgr-is-local").checked;
  document.getElementById("mgr-docker-fields").style.display = kind === "docker" ? "" : "none";
  if (kind === "host") {
    document.getElementById("mgr-local-toggle-wrap").style.display = "none";
    document.getElementById("mgr-remote-fields").style.display = "";
  } else {
    document.getElementById("mgr-local-toggle-wrap").style.display = "";
    document.getElementById("mgr-remote-fields").style.display = isLocal ? "none" : "";
  }
  _updateVaultHints();
}

function _isRemoteMgr() {
  const kind = document.getElementById("mgr-kind")?.value;
  const isLocal = document.getElementById("mgr-is-local")?.checked;
  if (kind === "host") return true;
  return kind === "docker" && !isLocal;
}

function _updateVaultHints() {
  const hint = document.getElementById("mgr-vault-hint");
  if (hint) hint.style.display = _isRemoteMgr() ? "" : "none";
}

function _resetMgrModal() {
  document.getElementById("mgr-edit-original-name").value = "";
  document.getElementById("mgr-name").value = "";
  document.getElementById("mgr-name").disabled = false;
  document.getElementById("mgr-kind").value = "docker";
  document.getElementById("mgr-is-local").checked = true;
  document.getElementById("mgr-ip").value = "";
  document.getElementById("mgr-user").value = "";
  document.getElementById("mgr-port").value = "22";
  document.getElementById("mgr-container").value = "";
  document.getElementById("mgr-service").value = "";
  document.getElementById("mgr-pw").value = "";
  _setError("mgr-error", "");
  document.getElementById("mgr-modal-title").textContent = "Add Manager";
  document.getElementById("mgr-submit-btn").textContent = "Add manager";
  document.getElementById("mgr-pw-wrap").style.display = "";
  toggleMgrFields();
}

function openAddManager() {
  _resetMgrModal();
  openModal("mgr-modal");
}

function openEditManager(name) {
  const card = document.querySelector(`[data-name="${CSS.escape(name)}"].infra-card--manager`);
  if (!card) { _toast("Card not found: " + name, "fail"); return; }
  _resetMgrModal();
  document.getElementById("mgr-edit-original-name").value = name;
  document.getElementById("mgr-name").value = name;
  document.getElementById("mgr-name").disabled = true;
  document.getElementById("mgr-kind").value = card.dataset.uiKind || "docker";
  document.getElementById("mgr-is-local").checked = card.dataset.connection === "local";
  document.getElementById("mgr-ip").value = card.dataset.ip || "";
  document.getElementById("mgr-user").value = card.dataset.user || "";
  document.getElementById("mgr-port").value = card.dataset.port || "22";
  document.getElementById("mgr-container").value = card.dataset.container || "";
  document.getElementById("mgr-service").value = card.dataset.service || "";
  document.getElementById("mgr-modal-title").textContent = "Edit Manager";
  document.getElementById("mgr-submit-btn").textContent = "Save changes";
  document.getElementById("mgr-pw-wrap").style.display = "none";
  toggleMgrFields();
  openModal("mgr-modal");
}

async function submitManager() {
  _setError("mgr-error", "");
  const original = document.getElementById("mgr-edit-original-name").value;
  const isEdit = !!original;
  const name = document.getElementById("mgr-name").value.trim();
  const kind = document.getElementById("mgr-kind").value;
  const isLocal = kind === "docker" && document.getElementById("mgr-is-local").checked;
  const ip = document.getElementById("mgr-ip").value.trim();
  const user = document.getElementById("mgr-user").value.trim();
  const port = parseInt(document.getElementById("mgr-port").value || "22");
  const containerRaw = document.getElementById("mgr-container").value.trim();
  const serviceRaw = document.getElementById("mgr-service").value.trim();
  const pw = document.getElementById("mgr-pw").value;

  if (!name) return _setError("mgr-error", "Hostname is required");
  if (!isLocal && !ip) return _setError("mgr-error", "IP is required for remote managers");
  if (!isLocal && !user) return _setError("mgr-error", "SSH user is required for remote managers");

  const container = kind === "docker" ? (containerRaw || "wazuh.manager") : "";
  const service = kind === "docker" ? (serviceRaw || container) : "";
  const body = { name, ui_kind: kind, is_local: isLocal, ip, ansible_user: user, ansible_port: port, container, service };

  const doSave = async () => {
    if (!isEdit && pw) body.become_password = pw;
    try {
      const url = isEdit
        ? `/api/infrastructure/managers/${encodeURIComponent(original)}`
        : "/api/infrastructure/managers";
      await window.RADAR.radarFetch(url, { method: isEdit ? "PUT" : "POST", body: JSON.stringify(body) });
      closeModal(null, "mgr-modal");
      _toast(isEdit ? "Manager updated" : "Manager added", "ok");
      setTimeout(() => location.reload(), 400);
    } catch (e) {
      _setError("mgr-error", e.message);
    }
  };

  if (!isEdit && pw && !isLocal) {
    _ensureVault(doSave);
  } else {
    doSave();
  }
}

function toggleAgentFields() {
  const mode = document.getElementById("agent-mode").value;
  document.getElementById("agent-ssh-fields").style.display = mode === "ssh" ? "" : "none";
  document.getElementById("agent-container-fields").style.display = mode === "container" ? "" : "none";
  const hint = document.getElementById("agent-vault-hint");
  if (hint) hint.style.display = mode === "ssh" ? "" : "none";
}

function _resetAgentModal() {
  document.getElementById("agent-edit-original-name").value = "";
  document.getElementById("agent-name").value = "";
  document.getElementById("agent-name").disabled = false;
  document.getElementById("agent-mode").value = "ssh";
  document.getElementById("agent-ip").value = "";
  document.getElementById("agent-user").value = "";
  document.getElementById("agent-port").value = "22";
  document.getElementById("agent-container").value = "";
  document.getElementById("agent-pw").value = "";
  _setError("agent-error", "");
  document.getElementById("agent-modal-title").textContent = "Add Agent";
  document.getElementById("agent-submit-btn").textContent = "Add agent";
  document.getElementById("agent-pw-wrap").style.display = "";
  toggleAgentFields();
}

function openAddAgent() {
  _resetAgentModal();
  openModal("agent-modal");
}

function openEditAgent(name) {
  const card = document.querySelector(`[data-name="${CSS.escape(name)}"].infra-card--agent`);
  if (!card) { _toast("Card not found: " + name, "fail"); return; }
  _resetAgentModal();
  document.getElementById("agent-edit-original-name").value = name;
  document.getElementById("agent-name").value = name;
  document.getElementById("agent-name").disabled = true;
  document.getElementById("agent-mode").value = card.dataset.agentMode || "ssh";
  document.getElementById("agent-ip").value = card.dataset.ip || "";
  document.getElementById("agent-user").value = card.dataset.user || "";
  document.getElementById("agent-port").value = card.dataset.port || "22";
  document.getElementById("agent-container").value = card.dataset.container || "";
  document.getElementById("agent-modal-title").textContent = "Edit Agent";
  document.getElementById("agent-submit-btn").textContent = "Save changes";
  document.getElementById("agent-pw-wrap").style.display = "none";
  toggleAgentFields();
  openModal("agent-modal");
}

async function submitAgent() {
  _setError("agent-error", "");
  const original = document.getElementById("agent-edit-original-name").value;
  const isEdit = !!original;
  const name = document.getElementById("agent-name").value.trim();
  const mode = document.getElementById("agent-mode").value;
  const ip = document.getElementById("agent-ip").value.trim();
  const user = document.getElementById("agent-user").value.trim();
  const port = parseInt(document.getElementById("agent-port").value || "22");
  const container = document.getElementById("agent-container").value.trim() || name;
  const pw = document.getElementById("agent-pw").value;

  if (!name) return _setError("agent-error", "Hostname is required");
  if (mode === "ssh" && !ip) return _setError("agent-error", "IP is required for SSH agents");
  if (mode === "ssh" && !user) return _setError("agent-error", "SSH user is required for SSH agents");

  const body = { name, agent_mode: mode, ip, ansible_user: user, ansible_port: port, container };

  const doSave = async () => {
    if (!isEdit && pw) body.become_password = pw;
    try {
      const url = isEdit
        ? `/api/infrastructure/agents/${encodeURIComponent(original)}`
        : "/api/infrastructure/agents";
      await window.RADAR.radarFetch(url, { method: isEdit ? "PUT" : "POST", body: JSON.stringify(body) });
      closeModal(null, "agent-modal");
      _toast(isEdit ? "Agent updated" : "Agent added", "ok");
      setTimeout(() => location.reload(), 400);
    } catch (e) {
      _setError("agent-error", e.message);
    }
  };

  if (!isEdit && pw && mode === "ssh") {
    _ensureVault(doSave);
  } else {
    doSave();
  }
}

async function deleteNode(type, name) {
  if (!confirm(`Delete ${type} "${name}" from inventory.yaml?`)) return;
  const url = type === "manager"
    ? `/api/infrastructure/managers/${encodeURIComponent(name)}`
    : `/api/infrastructure/agents/${encodeURIComponent(name)}`;
  try {
    await window.RADAR.radarFetch(url, { method: "DELETE" });
    const safeId = name.replace(/\./g, "-");
    const card = document.getElementById(`card-${type === "manager" ? "mgr" : "agent"}-${safeId}`);
    if (card) card.remove();
    _toast(`${type} deleted`, "ok");
  } catch (e) {
    _toast(`Delete failed: ${e.message}`, "fail");
  }
}

function openCredModal(name, type, hasExisting) {
  document.getElementById("cred-node-name").value = name;
  document.getElementById("cred-node-type").value = type;
  document.getElementById("cred-modal-sub").textContent = `Node: ${name} (${type})`;
  document.getElementById("cred-pw").value = "";
  document.getElementById("cred-delete-btn").style.display = hasExisting ? "" : "none";
  _setError("cred-error", "");
  openModal("cred-modal");
}

async function saveCredential() {
  _setError("cred-error", "");
  const name = document.getElementById("cred-node-name").value;
  const type = document.getElementById("cred-node-type").value;
  const pw = document.getElementById("cred-pw").value;
  if (!pw) return _setError("cred-error", "Password cannot be empty");

  const doSave = async () => {
    const resource = type === "manager" ? "managers" : "agents";
    try {
      await window.RADAR.radarFetch(
        `/api/infrastructure/${resource}/${encodeURIComponent(name)}/credential`,
        { method: "POST", body: JSON.stringify({ become_password: pw }) }
      );
      closeModal(null, "cred-modal");
      _toast("Credential saved", "ok");
      setTimeout(() => location.reload(), 400);
    } catch (e) {
      _setError("cred-error", e.message);
    }
  };

  _ensureVault(doSave);
}

async function deleteCredential() {
  _setError("cred-error", "");
  const name = document.getElementById("cred-node-name").value;
  const type = document.getElementById("cred-node-type").value;
  if (!confirm(`Delete stored sudo password for ${name}?`)) return;
  const resource = type === "manager" ? "managers" : "agents";
  try {
    await window.RADAR.radarFetch(
      `/api/infrastructure/${resource}/${encodeURIComponent(name)}/credential`,
      { method: "DELETE" }
    );
    closeModal(null, "cred-modal");
    _toast("Credential removed", "ok");
    setTimeout(() => location.reload(), 400);
  } catch (e) {
    _setError("cred-error", e.message);
  }
}

function _statusIcon(status) {
  if (status === "ok") return '<span class="hc-icon hc-icon--ok">&#10003;</span>';
  if (status === "warn") return '<span class="hc-icon hc-icon--warn">&#9888;</span>';
  return '<span class="hc-icon hc-icon--fail">&#10007;</span>';
}

function _renderHealth(result) {
  const overall = result.overall || "fail";
  const cls = { ok: "hc-overall--ok", warn: "hc-overall--warn", fail: "hc-overall--fail" }[overall];
  const rows = (result.checks || []).map(c =>
    `<div class="hc-row hc-row--${c.status}">${_statusIcon(c.status)}<span class="hc-detail">${_esc(c.detail)}</span></div>`
  ).join("");
  return `<div class="hc-overall ${cls}">${result.ok ?? 0} OK &middot; ${result.warn ?? 0} WARN &middot; ${result.fail ?? 0} FAIL</div>
          <div class="hc-rows">${rows || '<div class="hc-row">No checks returned.</div>'}</div>`;
}

function _esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function runHealthCheck(type, name) {
  const safeId = name.replace(/\./g, "-");
  const panelId = `health-${type === "manager" ? "mgr" : "agent"}-${safeId}`;
  const panel = document.getElementById(panelId);
  if (!panel) return;
  panel.style.display = "";
  panel.innerHTML = '<div class="hc-loading">Running health checks...</div>';
  const url = type === "manager"
    ? `/api/infrastructure/health/manager/${encodeURIComponent(name)}`
    : `/api/infrastructure/health/agent/${encodeURIComponent(name)}`;
  try {
    const result = await window.RADAR.radarFetch(url, { method: "POST", body: "{}" });
    if (result.error) {
      panel.innerHTML = `<div class="hc-row hc-row--fail">${_statusIcon("fail")}<span class="hc-detail">${_esc(result.error)}</span></div>`;
      return;
    }
    panel.innerHTML = _renderHealth(result);
  } catch (e) {
    panel.innerHTML = `<div class="hc-row hc-row--fail">${_statusIcon("fail")}<span class="hc-detail">${_esc(e.message)}</span></div>`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  _initVaultBanner();
  if (document.getElementById("mgr-kind")) toggleMgrFields();
  if (document.getElementById("agent-mode")) toggleAgentFields();
});