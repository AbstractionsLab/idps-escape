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

function _esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function _statusIcon(status) {
  if (status === "ok") return '<span class="hc-icon hc-icon--ok">&#10003;</span>';
  if (status === "warn") return '<span class="hc-icon hc-icon--warn">&#9888;</span>';
  return '<span class="hc-icon hc-icon--fail">&#10007;</span>';
}

const _DEFAULT_PORTS = { indexer: 9200, manager: 55000, dashboard: 5601 };
const _DEFAULT_SCHEMES = { indexer: "https", manager: "https", dashboard: "https" };
const _DEFAULT_CONTAINERS = { indexer: "wazuh.indexer", manager: "wazuh.manager", dashboard: "wazuh.dashboard" };

async function detectComponentIp() {
  try {
    const data = await window.RADAR.radarFetch("/api/infra/detect-ip");
    if (!data.ok || !data.ips || !data.ips.length) {
      _toast("Could not detect an IP on this machine", "fail");
      return;
    }
    document.getElementById("component-host").value = data.ips[0];
    if (data.ips.length > 1) {
      _toast(`Detected ${data.ips.join(", ")} -- used the first one`, "ok");
    }
  } catch (e) {
    _toast(e.message, "fail");
  }
}

function _isMulti(type) {
  return type === "indexer" || type === "manager";
}

function _togglePrimaryRow(type) {
  document.getElementById("component-primary-row").style.display = _isMulti(type) ? "block" : "none";
}

function openComponentModal(type, nodeId) {
  _setError("component-error", "");
  const typeSelect = document.getElementById("component-type");
  document.getElementById("component-orig-type").value = type || "";
  document.getElementById("component-node-id").value = nodeId || "";
  const editing = !!type && (!_isMulti(type) || !!nodeId);
  document.getElementById("component-modal-title").textContent =
    editing ? `Edit container: ${type}` : "Add container";

  if (editing) {
    typeSelect.value = type;
    typeSelect.disabled = true;
    _togglePrimaryRow(type);
    if (_isMulti(type)) {
      window.RADAR.radarFetch(`/api/infra/nodes/${type}`).then((data) => {
        const node = (data.nodes || []).find((n) => n.id === nodeId) || {};
        document.getElementById("component-container").value = node.container_name || _DEFAULT_CONTAINERS[type];
        document.getElementById("component-host").value = node.host || "";
        document.getElementById("component-port").value = node.port || _DEFAULT_PORTS[type];
        document.getElementById("component-scheme").value = node.scheme || _DEFAULT_SCHEMES[type];
        document.getElementById("component-primary").checked = !!node.primary;
        document.getElementById("component-primary").disabled = !!node.primary;
      }).catch((e) => _setError("component-error", e.message));
    } else {
      window.RADAR.radarFetch("/api/infra/dashboard").then((data) => {
        const cfg = data.component || {};
        document.getElementById("component-container").value = cfg.container_name || _DEFAULT_CONTAINERS[type];
        document.getElementById("component-host").value = cfg.host || "";
        document.getElementById("component-port").value = cfg.port || _DEFAULT_PORTS[type];
        document.getElementById("component-scheme").value = cfg.scheme || _DEFAULT_SCHEMES[type];
      }).catch((e) => _setError("component-error", e.message));
    }
  } else {
    typeSelect.disabled = false;
    typeSelect.value = type || typeSelect.options[0].value;
    _applyDefaultsForType(typeSelect.value);
    typeSelect.onchange = () => _applyDefaultsForType(typeSelect.value);
  }

  openModal("component-modal");
}

function _applyDefaultsForType(type) {
  document.getElementById("component-container").value = _DEFAULT_CONTAINERS[type];
  document.getElementById("component-host").value = "";
  document.getElementById("component-port").value = _DEFAULT_PORTS[type];
  document.getElementById("component-scheme").value = _DEFAULT_SCHEMES[type];
  document.getElementById("component-primary").checked = false;
  document.getElementById("component-primary").disabled = false;
  _togglePrimaryRow(type);
}

async function saveComponent() {
  _setError("component-error", "");
  const type = document.getElementById("component-type").value;
  const nodeId = document.getElementById("component-node-id").value || null;
  const container = document.getElementById("component-container").value.trim();
  const host = document.getElementById("component-host").value.trim();
  const port = parseInt(document.getElementById("component-port").value, 10);
  const scheme = document.getElementById("component-scheme").value;
  const primary = document.getElementById("component-primary").checked;
  if (!container) { _setError("component-error", "Container name is required"); return; }

  try {
    if (_isMulti(type)) {
      const body = JSON.stringify({ container_name: container, host, port: port || undefined, scheme, primary });
      if (nodeId) {
        await window.RADAR.radarFetch(`/api/infra/nodes/${type}/${encodeURIComponent(nodeId)}`, { method: "PUT", body });
      } else {
        await window.RADAR.radarFetch(`/api/infra/nodes/${type}`, { method: "POST", body });
      }
    } else {
      await window.RADAR.radarFetch("/api/infra/dashboard", {
        method: "PUT",
        body: JSON.stringify({ container_name: container, host, port: port || undefined, scheme }),
      });
    }
    closeModal(null, "component-modal");
    _toast("Container saved", "ok");
    setTimeout(() => location.reload(), 300);
  } catch (e) {
    _setError("component-error", e.message);
  }
}

async function deleteComponent(type) {
  if (!confirm(`Remove '${type}' from infra.yaml?`)) return;
  try {
    await window.RADAR.radarFetch(`/api/infra/${type}`, { method: "DELETE" });
    _toast("Container removed", "ok");
    setTimeout(() => location.reload(), 300);
  } catch (e) {
    _toast(e.message, "fail");
  }
}

async function deleteNode(role, nodeId) {
  if (!confirm(`Remove ${role} node '${nodeId}'?`)) return;
  try {
    await window.RADAR.radarFetch(`/api/infra/nodes/${role}/${encodeURIComponent(nodeId)}`, { method: "DELETE" });
    _toast("Node removed", "ok");
    setTimeout(() => location.reload(), 300);
  } catch (e) {
    _toast(e.message, "fail");
  }
}

async function setPrimaryNode(role, nodeId) {
  try {
    await window.RADAR.radarFetch(`/api/infra/nodes/${role}/${encodeURIComponent(nodeId)}/set-primary`, { method: "POST" });
    _toast("Primary updated", "ok");
    setTimeout(() => location.reload(), 300);
  } catch (e) {
    _toast(e.message, "fail");
  }
}

async function testAllLinks() {
  const host = document.getElementById("all-links-status");
  const pairs = [["manager", "indexer"], ["indexer", "manager"]];
  host.innerHTML = '<div style="font-size:12px;color:var(--text-muted)">Testing...</div>';
  const lines = [];
  for (const [from, to] of pairs) {
    try {
      const r = await window.RADAR.radarFetch("/api/infra/test-link", {
        method: "POST",
        body: JSON.stringify({ from, to }),
      });
      if (r.ok) {
        lines.push(`<div style="font-size:12px">${_statusIcon("ok")} ${from} &rarr; ${to}: <span class="mono">${_esc(r.url)}</span> (HTTP ${r.http_status})</div>`);
      } else {
        lines.push(`<div style="font-size:12px">${_statusIcon("fail")} ${from} &rarr; ${to}: ${_esc(r.error || "failed")}</div>`);
      }
    } catch (e) {
      lines.push(`<div style="font-size:12px">${_statusIcon("fail")} ${from} &rarr; ${to}: ${_esc(e.message)}</div>`);
    }
  }
  host.innerHTML = lines.join("");
}