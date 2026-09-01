"use strict";

let _currentReader = null;
let _currentAbortController = null;

function switchTab(tab) {
  document.querySelectorAll(".subnav__item").forEach(el => {
    el.classList.toggle("subnav__item--active", el.dataset.tab === tab);
  });
  ["build", "run", "health", "onboard", "groups", "teardown"].forEach(t => {
    const panel = document.getElementById(`tab-${t}`);
    if (panel) panel.style.display = t === tab ? "" : "none";
  });
  const logCard = document.getElementById("deploy-log-card");
  if (logCard) logCard.style.display = tab === "status" ? "none" : "";
}

function switchSubTab(parentTab, subtab) {
  const parent = document.getElementById(`tab-${parentTab}`);
  if (!parent) return;
  parent.querySelectorAll(".subtabs__item").forEach(el => {
    el.classList.toggle("subtabs__item--active", el.dataset.subtab === subtab);
  });
  parent.querySelectorAll(".subtab-panel").forEach(el => {
    el.style.display = el.id === `subtab-${parentTab}-${subtab}` ? "" : "none";
  });
}

function toggleCoreOnly() {
  const coreOnly = document.getElementById("b-core-only").checked;
  const scenarioGroup = document.getElementById("b-scenario-group");
  const scenarioSelect = document.getElementById("b-scenario");
  if (scenarioGroup) scenarioGroup.style.opacity = coreOnly ? "0.45" : "";
  if (scenarioSelect) scenarioSelect.disabled = coreOnly;
}

function _toast(msg, kind) {
  const host = document.getElementById("toast-host");
  if (!host) return;
  const el = document.createElement("div");
  el.className = "toast toast--" + (kind || "ok");
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => { el.classList.add("toast--out"); }, 2200);
  setTimeout(() => { el.remove(); }, 2800);
}

function _selectedAgents() {
  return Array.from(document.querySelectorAll(".agent-select-cb:checked"))
    .map(cb => cb.value);
}

function _collectSpec(action) {
  if (action === "build") {
    const coreOnly = document.getElementById("b-core-only").checked;
    return {
      action: "build",
      core_only: coreOnly,
      scenario: coreOnly ? "" : document.getElementById("b-scenario").value,
    };
  }
  if (action === "run") {
    return {
      action: "run",
      scenario: document.getElementById("r-scenario").value,
      ingest: document.getElementById("r-ingest").checked,
    };
  }
  if (action === "health") {
    const scenarioEl = document.getElementById("h-scenario");
    const agentNamesEl = document.getElementById("h-agent-names");
    return {
      action: "health",
      scenario: scenarioEl ? scenarioEl.value : "all",
      agent_names: agentNamesEl ? agentNamesEl.value.trim() : "",
    };
  }
  return {};
}

async function previewCmd(action) {
  const target = document.getElementById({
    build: "b-preview", run: "r-preview", health: "h-preview",
  }[action]);
  if (!target) return;
  target.textContent = "Resolving…";
  try {
    const res = await fetch("/api/deploy/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(_collectSpec(action)),
    });
    const data = await res.json();
    if (data.ok) {
      target.textContent = "$ " + data.cmd;
      target.classList.remove("deploy-preview--err");
    } else {
      target.textContent = data.error || "preview failed";
      target.classList.add("deploy-preview--err");
    }
  } catch (e) {
    target.textContent = e.message;
    target.classList.add("deploy-preview--err");
  }
}

async function previewUndoScenario() {
  const target = document.getElementById("ub-preview");
  const scenario = document.getElementById("ub-scenario").value;
  if (!target) return;
  target.textContent = "Resolving…";
  try {
    const res = await fetch("/api/deploy/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "undo-scenario", scenario }),
    });
    const data = await res.json();
    if (data.ok) {
      target.textContent = "$ " + data.cmd;
      target.classList.remove("deploy-preview--err");
    } else {
      target.textContent = data.error || "preview failed";
      target.classList.add("deploy-preview--err");
    }
  } catch (e) {
    target.textContent = e.message;
    target.classList.add("deploy-preview--err");
  }
}

async function undoScenario() {
  const scenario = document.getElementById("ub-scenario").value;
  if (!scenario) {
    _toast("Select a scenario first", "warn");
    return;
  }
  if (!confirm(`Undo the deploy for "${scenario}"? This resets its group config and removes its `
             + `active-response wiring. Shared files/blocks are left in place. Safe to re-run.`)) {
    return;
  }

  await _streamPost(
    "/api/deploy/undo-scenario",
    { scenario },
    "undoscenario",
    {
      startMsg: `Undoing deploy for '${scenario}'…`,
      doneToast: "Scenario undo complete",
      failToast: "Undo failed",
    }
  );
}

function _setRunning(action, running) {
  const runBtnIds = {
    build: "b-run-btn", run: "r-run-btn", health: "h-run-btn", onboard: "o-run-btn", assigngroup: "ga-run-btn",
    unassigngroup: "ga-unassign-btn", deregister: "dr-run-btn", undoscenario: "ub-run-btn", teardown: "td-run-btn",
    enrollmentwindow: ["ew-open-btn", "ew-close-btn"],
  }[action];
  const stopBtn = document.getElementById({
    build: "b-stop-btn", run: "r-stop-btn", health: "h-stop-btn", onboard: "o-stop-btn", assigngroup: "ga-stop-btn",
    unassigngroup: "ga-stop-btn", deregister: "dr-stop-btn", undoscenario: "ub-stop-btn", teardown: "td-stop-btn",
    enrollmentwindow: "ew-stop-btn",
  }[action]);
  (Array.isArray(runBtnIds) ? runBtnIds : [runBtnIds]).forEach(id => {
    const btn = id && document.getElementById(id);
    if (btn) btn.disabled = running;
  });
  if (stopBtn) stopBtn.style.display = running ? "" : "none";
  document.querySelectorAll(".subnav__item").forEach(el => {
    el.style.pointerEvents = running ? "none" : "";
    el.style.opacity = running ? "0.55" : "";
  });
}

function _copyText(text) {
  if (!text) {
    _toast("Nothing to copy", "warn");
    return;
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(
      () => _toast("Copied", "ok"),
      () => _fallbackCopy(text)
    );
  } else {
    // navigator.clipboard is only exposed in secure contexts (HTTPS, or
    // http://localhost). Plain HTTP on a LAN address -- a common way to
    // reach this GUI -- leaves navigator.clipboard undefined, and calling
    // .writeText on it throws synchronously, before any .then/.catch ever
    // runs. That's a silent failure from the user's point of view: no
    // toast, nothing copied. Fall back to the older selection-based copy.
    _fallbackCopy(text);
  }
}

function _fallbackCopy(text) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    _toast(ok ? "Copied" : "Copy failed -- select the text and copy manually", ok ? "ok" : "fail");
  } catch (e) {
    _toast("Copy failed -- select the text and copy manually", "fail");
  }
}

function clearLog() {
  const log = document.getElementById("deploy-log");
  if (log) log.textContent = "";
}

function copyLog() {
  const log = document.getElementById("deploy-log");
  if (!log) return;
  _copyText(log.textContent);
}

function stopStream() {
  if (_currentAbortController) {
    _currentAbortController.abort();
    _currentAbortController = null;
  }
}

function _appendLog(text) {
  const log = document.getElementById("deploy-log");
  if (!log) return;
  const wasAtBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 5;
  log.textContent += text;
  if (wasAtBottom) log.scrollTop = log.scrollHeight;
}

async function runAction(action) {
  const endpoint = {
    build: "/api/deploy/build",
    run: "/api/deploy/run",
    health: "/api/deploy/health",
  }[action];
  if (!endpoint) return;

  const spec = _collectSpec(action);
  clearLog();
  _appendLog(`[${new Date().toLocaleTimeString()}] Starting ${action}…\n\n`);

  _setRunning(action, true);
  _currentAbortController = new AbortController();

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(spec),
      signal: _currentAbortController.signal,
    });

    if (res.status === 403) {
      const body = await res.json().catch(() => ({}));
      if (body.need_sudo) {
        const ok = await window.RADAR.promptSudoPassword();
        if (ok) { _setRunning(action, false); runAction(action); return; }
        _appendLog("[cancelled — sudo password not set]\n");
        return;
      }
    }

    if (!res.ok || !res.body) {
      const txt = await res.text().catch(() => "");
      _appendLog(`[HTTP ${res.status}] ${txt}\n`);
      _toast("Request failed", "fail");
      return;
    }

    const reader = res.body.getReader();
    _currentReader = reader;
    const decoder = new TextDecoder("utf-8");
    let fullText = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value, { stream: true });
      fullText += chunk;
      _appendLog(chunk);
    }
    _appendLog(`\n[${new Date().toLocaleTimeString()}] Done.\n`);
    const failed = /\[ERROR\]|\[!\]/.test(fullText);
    _toast(failed ? `${action} failed` : `${action} finished`, failed ? "fail" : "ok");
  } catch (e) {
    if (e.name === "AbortError") {
      _appendLog("\n[stream aborted by user]\n");
      _toast("Stopped", "warn");
    } else {
      _appendLog(`\n[error] ${e.message}\n`);
      _toast(`${action} failed`, "fail");
    }
  } finally {
    _currentReader = null;
    _currentAbortController = null;
    _setRunning(action, false);
  }
}

async function _streamPost(url, body, runningKey, { startMsg, doneToast, failToast } = {}) {
  clearLog();
  _appendLog(`[${new Date().toLocaleTimeString()}] ${startMsg || "Working…"}\n\n`);
  _setRunning(runningKey, true);
  _currentAbortController = new AbortController();

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: _currentAbortController.signal,
    });

    if (!res.ok || !res.body) {
      const txt = await res.text().catch(() => "");
      _appendLog(`[HTTP ${res.status}] ${txt}\n`);
      _toast("Request failed", "fail");
      return;
    }

    const reader = res.body.getReader();
    _currentReader = reader;
    const decoder = new TextDecoder("utf-8");
    let fullText = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value, { stream: true });
      fullText += chunk;
      _appendLog(chunk);
    }
    _appendLog(`\n[${new Date().toLocaleTimeString()}] Done.\n`);

    // The backend can complete the HTTP request "successfully" while still
    // reporting that nothing actually happened (e.g. an agent name that
    // didn't resolve to anything on the manager) -- don't claim success
    // unless the content actually says so.
    const failed = /\[ERROR\]|\[!\]|"resolved":\s*false/.test(fullText);
    _toast(failed ? (failToast || "Failed") : (doneToast || "Done"), failed ? "fail" : "ok");
  } catch (e) {
    if (e.name === "AbortError") {
      _appendLog("\n[stream aborted by user]\n");
      _toast("Stopped", "warn");
    } else {
      _appendLog(`\n[error] ${e.message}\n`);
      _toast(failToast || "Failed", "fail");
    }
  } finally {
    _currentReader = null;
    _currentAbortController = null;
    _setRunning(runningKey, false);
  }
}

async function mintToken() {
  const scenarioSelect = document.getElementById("o-scenario");
  const scenario = scenarioSelect.value;
  const isShared = scenarioSelect.selectedOptions[0]?.dataset.shared === "true";
  const expiryMinutes = parseInt(document.getElementById("o-expiry").value, 10) || 60;
  const managerAddress = document.getElementById("o-manager-address").value.trim();

  let groups = `default,${scenario}`;
  if (isShared) {
    groups += ",radar_shared";
  }

  const copyWrap = document.getElementById("o-cmd-copy-wrap");
  if (copyWrap) copyWrap.style.display = "none";

  clearLog();
  _appendLog(`[${new Date().toLocaleTimeString()}] Minting enrollment token…\n\n`);
  _setRunning("onboard", true);
  _currentAbortController = new AbortController();

  try {
    const res = await fetch("/api/deploy/mint-token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ groups, expiry_minutes: expiryMinutes, manager_address: managerAddress }),
      signal: _currentAbortController.signal,
    });

    if (res.status === 403) {
      const body = await res.json().catch(() => ({}));
      if (body.need_sudo) {
        const ok = await window.RADAR.promptSudoPassword();
        if (ok) { _setRunning("onboard", false); mintToken(); return; }
        _appendLog("[cancelled — sudo password not set]\n");
        return;
      }
    }

    if (!res.ok || !res.body) {
      const txt = await res.text().catch(() => "");
      _appendLog(`[HTTP ${res.status}] ${txt}\n`);
      _toast("Request failed", "fail");
      return;
    }

    const reader = res.body.getReader();
    _currentReader = reader;
    const decoder = new TextDecoder("utf-8");
    let fullText = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value, { stream: true });
      fullText += chunk;
      _appendLog(chunk);
    }
    _appendLog(`\n[${new Date().toLocaleTimeString()}] Done.\n`);
    const failed = /\[ERROR\]|\[!\]/.test(fullText);
    _toast(failed ? "Mint token failed" : "Token minted", failed ? "fail" : "ok");
    _extractBootstrapCmd();
  } catch (e) {
    if (e.name === "AbortError") {
      _appendLog("\n[stream aborted by user]\n");
      _toast("Stopped", "warn");
    } else {
      _appendLog(`\n[error] ${e.message}\n`);
      _toast("Mint token failed", "fail");
    }
  } finally {
    _currentReader = null;
    _currentAbortController = null;
    _setRunning("onboard", false);
  }
}

function _extractBootstrapCmd() {
  const log = document.getElementById("deploy-log");
  const copyWrap = document.getElementById("o-cmd-copy-wrap");
  const copyText = document.getElementById("o-cmd-copy-text");
  if (!log || !copyWrap || !copyText) return;
  const match = log.textContent.match(/^\s*sudo\s+\.\/bootstrap-agent\.sh.*$/m);
  if (match) {
    const cmd = match[0].trim();
    copyText.textContent = cmd;
    copyWrap.style.display = "";
  } else {
    console.warn("[deploy] could not find the bootstrap-agent.sh line in mint-token output; showing full log only");
    copyWrap.style.display = "none";
  }
}

function copyBootstrapCmd() {
  const copyText = document.getElementById("o-cmd-copy-text");
  if (!copyText) return;
  _copyText(copyText.textContent);
}

async function assignAgentGroup() {
  const agentName = document.getElementById("ga-agent-name").value.trim();
  const scenario = document.getElementById("ga-scenario").value;
  const agentIp = document.getElementById("ga-agent-ip").value.trim();

  clearLog();
  _appendLog(`[${new Date().toLocaleTimeString()}] Assigning agent to groups…\n\n`);
  _setRunning("assigngroup", true);
  _currentAbortController = new AbortController();

  try {
    const res = await fetch("/api/deploy/assign-agent-group", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_name: agentName, scenario, agent_ip: agentIp }),
      signal: _currentAbortController.signal,
    });

    if (!res.ok || !res.body) {
      const txt = await res.text().catch(() => "");
      _appendLog(`[HTTP ${res.status}] ${txt}\n`);
      _toast("Request failed", "fail");
      return;
    }

    const reader = res.body.getReader();
    _currentReader = reader;
    const decoder = new TextDecoder("utf-8");
    let fullText = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value, { stream: true });
      fullText += chunk;
      _appendLog(chunk);
    }
    _appendLog(`\n[${new Date().toLocaleTimeString()}] Done.\n`);
    const failed = /\[ERROR\]|\[!\]|"resolved":\s*false/.test(fullText);
    _toast(failed ? "Assign group failed" : "Group assigned", failed ? "fail" : "ok");
  } catch (e) {
    if (e.name === "AbortError") {
      _appendLog("\n[stream aborted by user]\n");
      _toast("Stopped", "warn");
    } else {
      _appendLog(`\n[error] ${e.message}\n`);
      _toast("Assign group failed", "fail");
    }
  } finally {
    _currentReader = null;
    _currentAbortController = null;
    _setRunning("assigngroup", false);
  }
}

async function unassignAgentGroup() {
  const agentName = document.getElementById("ga-agent-name").value.trim();
  const scenario = document.getElementById("ga-scenario").value;
  const agentIp = document.getElementById("ga-agent-ip").value.trim();

  if (!agentName && !agentIp) {
    _toast("Enter an agent name or IP first", "warn");
    return;
  }
  if (!scenario) {
    _toast("Select a scenario first", "warn");
    return;
  }

  await _streamPost(
    "/api/deploy/unassign-agent-group",
    { agent_name: agentName, scenario, agent_ip: agentIp },
    "unassigngroup",
    {
      startMsg: "Removing agent from scenario groups…",
      doneToast: "Group unassigned",
      failToast: "Unassign group failed",
    }
  );
}

async function deregisterAgent() {
  const agentName = document.getElementById("dr-agent-name").value.trim();
  const agentIp = document.getElementById("dr-agent-ip").value.trim();
  const noPurge = document.getElementById("dr-no-purge").checked;

  if (!agentName) {
    _toast("Enter an agent name first", "warn");
    return;
  }
  if (!confirm(`Deregister agent "${agentName}" from the manager? This can be re-run safely if it's already gone.`)) {
    return;
  }

  await _streamPost(
    "/api/deploy/deregister-agent",
    { agent_name: agentName, agent_ip: agentIp, no_purge: noPurge },
    "deregister",
    {
      startMsg: "Deregistering agent…",
      doneToast: "Agent deregistered",
      failToast: "Deregister failed",
    }
  );
}

async function enrollmentWindowAction(action) {
  const minutes = parseInt(document.getElementById("ew-minutes").value, 10) || 30;
  const spec = { action, minutes };
  const labels = { open: "Opening", close: "Closing", status: "Checking" }[action];

  clearLog();
  _appendLog(`[${new Date().toLocaleTimeString()}] ${labels} enrollment window…\n\n`);
  _setRunning("enrollmentwindow", true);
  _currentAbortController = new AbortController();

  try {
    const res = await fetch("/api/deploy/enrollment-window", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(spec),
      signal: _currentAbortController.signal,
    });

    if (res.status === 403) {
      const body = await res.json().catch(() => ({}));
      if (body.need_sudo) {
        const ok = await window.RADAR.promptSudoPassword();
        if (ok) { _setRunning("enrollmentwindow", false); enrollmentWindowAction(action); return; }
        _appendLog("[cancelled — sudo password not set]\n");
        return;
      }
    }

    if (!res.ok || !res.body) {
      const txt = await res.text().catch(() => "");
      _appendLog(`[HTTP ${res.status}] ${txt}\n`);
      _toast("Request failed", "fail");
      return;
    }

    const reader = res.body.getReader();
    _currentReader = reader;
    const decoder = new TextDecoder("utf-8");
    let fullText = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value, { stream: true });
      fullText += chunk;
      _appendLog(chunk);
    }
    _appendLog(`\n[${new Date().toLocaleTimeString()}] Done.\n`);
    const failed = /\[ERROR\]|\[!\]|ERROR:/.test(fullText);
    _toast(failed ? "Failed" : "Done", failed ? "fail" : "ok");
  } catch (e) {
    if (e.name === "AbortError") {
      _appendLog("\n[stream aborted by user]\n");
      _toast("Stopped", "warn");
    } else {
      _appendLog(`\n[error] ${e.message}\n`);
      _toast("Failed", "fail");
    }
  } finally {
    _currentReader = null;
    _currentAbortController = null;
    _setRunning("enrollmentwindow", false);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const cb = document.getElementById("td-confirm");
  const btn = document.getElementById("td-run-btn");
  const removeDataCb = document.getElementById("td-remove-data");
  const label = document.getElementById("td-confirm-label");

  const syncConfirmLabel = () => {
    if (!label || !removeDataCb) return;
    label.textContent = removeDataCb.checked
      ? "I understand this permanently deletes all manager data and cannot be undone."
      : "I understand this stops the manager stack (data is kept on disk).";
  };

  if (cb && btn) {
    cb.addEventListener("change", () => { btn.disabled = !cb.checked; });
  }
  if (removeDataCb) {
    removeDataCb.addEventListener("change", () => {
      syncConfirmLabel();
      // Force re-confirmation any time the destructiveness of the action changes.
      if (cb) cb.checked = false;
      if (btn) btn.disabled = true;
    });
  }
  syncConfirmLabel();
});

async function teardownStack() {
  const confirmed = document.getElementById("td-confirm").checked;
  if (!confirmed) return;

  const removeData = document.getElementById("td-remove-data").checked;
  const warning = removeData
    ? "This permanently deletes all manager data (indices, dashboards, agent enrollment state, certs) and cannot be undone. Continue?"
    : "This stops and removes the manager containers. Data on disk is left in place. Continue?";
  if (!confirm(warning)) {
    return;
  }

  clearLog();
  _appendLog(`[${new Date().toLocaleTimeString()}] Tearing down the manager stack${removeData ? " (removing data)" : ""}…\n\n`);
  _setRunning("teardown", true);
  _currentAbortController = new AbortController();

  try {
    const res = await fetch("/api/deploy/teardown", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true, remove_data: removeData }),
      signal: _currentAbortController.signal,
    });

    if (res.status === 403) {
      const body = await res.json().catch(() => ({}));
      if (body.need_sudo) {
        const ok = await window.RADAR.promptSudoPassword();
        if (ok) { _setRunning("teardown", false); teardownStack(); return; }
        _appendLog("[cancelled — sudo password not set]\n");
        return;
      }
    }

    if (!res.ok || !res.body) {
      const txt = await res.text().catch(() => "");
      _appendLog(`[HTTP ${res.status}] ${txt}\n`);
      _toast("Request failed", "fail");
      return;
    }

    const reader = res.body.getReader();
    _currentReader = reader;
    const decoder = new TextDecoder("utf-8");

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      _appendLog(decoder.decode(value, { stream: true }));
    }
    _appendLog(`\n[${new Date().toLocaleTimeString()}] Done.\n`);
    _toast("Teardown complete", "ok");
  } catch (e) {
    if (e.name === "AbortError") {
      _appendLog("\n[stream aborted by user]\n");
      _toast("Stopped", "warn");
    } else {
      _appendLog(`\n[error] ${e.message}\n`);
      _toast("Teardown failed", "fail");
    }
  } finally {
    _currentReader = null;
    _currentAbortController = null;
    _setRunning("teardown", false);
    // _setRunning unconditionally re-enables the button; re-apply the
    // checkbox's own state so it doesn't become clickable again without
    // re-confirming.
    const cb = document.getElementById("td-confirm");
    const btn = document.getElementById("td-run-btn");
    if (cb && btn) btn.disabled = !cb.checked;
  }
}