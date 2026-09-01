"use strict";

function _toast(msg, kind) {
  const host = document.getElementById("global-toast-host");
  if (!host) return;
  const el = document.createElement("div");
  el.className = "toast toast--" + (kind || "ok");
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => el.classList.add("toast--out"), 2400);
  setTimeout(() => el.remove(), 3000);
}

function _setStatus(id, state, text) {
  const el = document.getElementById("status-" + id);
  if (!el) return;
  const dot = el.querySelector(".status-dot");
  const label = el.querySelector(".status-text");
  const map = { ok: "status-dot--green", fail: "status-dot--red", testing: "status-dot--amber" };
  dot.className = "status-dot " + (map[state] || "status-dot--gray");
  label.textContent = text;
}

function _setResult(id, msg, ok) {
  const el = document.getElementById("result-" + id);
  if (!el) return;
  el.textContent = msg;
  el.className = "connector-result" + (ok ? " connector-result--ok" : " connector-result--fail");
}

function toggleSslCert(prefix) {
  const cb = document.getElementById(prefix + "-ssl-enabled");
  const wrap = document.getElementById(prefix + "-cert-wrap");
  if (wrap) { wrap.classList.toggle('cert-wrap--visible', cb.checked); }
}

async function revealPw(inputId, envKey, btn) {
  btn.disabled = true;
  btn.textContent = "...";
  try {
    const data = await window.RADAR.radarFetch("/api/connectors/reveal", {
      method: "POST",
      body: JSON.stringify({ key: envKey }),
    });
    if (data.ok && data.value) {
      const input = document.getElementById(inputId);
      if (input) {
        input.type = "text";
        input.value = data.value;
        btn.textContent = "Hide";
        btn.onclick = () => {
          input.type = "password";
          input.value = "";
          btn.textContent = "Show";
          btn.onclick = () => revealPw(inputId, envKey, btn);
          btn.disabled = false;
        };
        btn.disabled = false;
      }
    } else {
      btn.textContent = "Show";
      btn.disabled = false;
      _toast(data.error || "Could not reveal", "fail");
    }
  } catch (e) {
    btn.textContent = "Show";
    btn.disabled = false;
    _toast(e.message, "fail");
  }
}

async function _readCertFile(inputId) {
  const input = document.getElementById(inputId);
  if (!input || !input.files || !input.files[0]) return null;
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = e => resolve(e.target.result);
    reader.onerror = () => reject(new Error("file read error"));
    reader.readAsText(input.files[0]);
  });
}

async function saveConnector(name) {
  const card = document.getElementById("card-" + name);
  if (!card) return;

  const fields = {};
  card.querySelectorAll("input[id], select[id]").forEach(el => {
    if (el.type === "file" || el.type === "checkbox" || !el.id) return;
    if (el.type === "password" && !el.value) return;
    fields[el.id] = el.value;
  });

  const sslPrefixMap = {
    opensearch: "os",
    dashboard: "dashboard",
    decipher: "decipher",
  };
  const sslPrefix = sslPrefixMap[name];
  if (sslPrefix) {
    const sslEnabled = document.getElementById(sslPrefix + "-ssl-enabled")?.checked;
    if (!sslEnabled) {
      fields[sslPrefix + "-ssl-enabled"] = "false";
    } else {
      const certContent = await _readCertFile(sslPrefix + "-cert-file");
      if (certContent) fields[sslPrefix + "-cert-content"] = certContent;
      fields[sslPrefix + "-ssl-enabled"] = "true";
    }
  }

  try {
    const data = await window.RADAR.radarFetch(`/api/connectors/${encodeURIComponent(name)}`, {
      method: "PUT",
      body: JSON.stringify(fields),
    });
    _toast(data.ok ? "Saved" : (data.error || "Save failed"), data.ok ? "ok" : "fail");
  } catch (e) {
    _toast(e.message, "fail");
  }
}

async function testConnector(name) {
  _setStatus(name, "testing", "Testing...");
  _setResult(name, "", true);
  try {
    const data = await window.RADAR.radarFetch(`/api/connectors/${encodeURIComponent(name)}/test`, {
      method: "POST",
    });
    if (data.ok) {
      _setStatus(name, "ok", "Connected");
      _setResult(name, data.detail || "Connection successful", true);
    } else {
      _setStatus(name, "fail", "Failed");
      _setResult(name, data.error || "Test failed", false);
    }
  } catch (e) {
    _setStatus(name, "fail", "Error");
    _setResult(name, e.message, false);
  }
}

async function testAllConnectors() {
  const connectors = ["opensearch", "wazuh-api", "dashboard", "smtp", "decipher", "maxmind", "webhook"];
  for (const name of connectors) {
    await testConnector(name);
  }
}