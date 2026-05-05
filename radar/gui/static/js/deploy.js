"use strict";

let _currentReader = null;
let _currentAbortController = null;

function switchTab(tab) {
  document.querySelectorAll(".subnav__item").forEach(el => {
    el.classList.toggle("subnav__item--active", el.dataset.tab === tab);
  });
  ["build", "run", "health", "status"].forEach(t => {
    const panel = document.getElementById(`tab-${t}`);
    if (panel) panel.style.display = t === tab ? "" : "none";
  });
  const logCard = document.getElementById("deploy-log-card");
  if (logCard) logCard.style.display = tab === "status" ? "none" : "";
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
    const selected = _selectedAgents();
    return {
      action: "build",
      scenario: document.getElementById("b-scenario").value,
      agent_mode: document.getElementById("b-agent").value,
      manager_mode: document.getElementById("b-manager").value,
      manager_exists: document.getElementById("b-manager-exists").checked,
      ssh_key: document.getElementById("b-ssh-key").value.trim(),
      limit_agents: selected.length > 0 ? selected : null,
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
    return {
      action: "health",
      scenario: document.getElementById("h-scenario").value,
      agent_mode: document.getElementById("h-agent").value,
      manager_mode: document.getElementById("h-manager").value,
      ssh_key: document.getElementById("h-ssh-key").value.trim(),
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

function _setRunning(action, running) {
  const runBtn = document.getElementById({
    build: "b-run-btn", run: "r-run-btn", health: "h-run-btn",
  }[action]);
  const stopBtn = document.getElementById({
    build: "b-stop-btn", run: "r-stop-btn", health: "h-stop-btn",
  }[action]);
  if (runBtn) runBtn.disabled = running;
  if (stopBtn) stopBtn.style.display = running ? "" : "none";
  document.querySelectorAll(".subnav__item").forEach(el => {
    el.style.pointerEvents = running ? "none" : "";
    el.style.opacity = running ? "0.55" : "";
  });
}

function clearLog() {
  const log = document.getElementById("deploy-log");
  if (log) log.textContent = "";
}

function copyLog() {
  const log = document.getElementById("deploy-log");
  if (!log) return;
  navigator.clipboard.writeText(log.textContent).then(
    () => _toast("Copied", "ok"),
    () => _toast("Copy failed", "fail")
  );
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
      if (body.need_ssh) {
        const ok = await window.RADAR.promptSSHPassphrase();
        if (ok) { _setRunning(action, false); runAction(action); return; }
        _appendLog("[cancelled — SSH passphrase not set]\n");
        return;
      }
      if (body.need_vault) {
        const ok = await window.RADAR.promptVaultUnlock();
        if (ok) { _setRunning(action, false); runAction(action); return; }
        _appendLog("[cancelled — vault not unlocked]\n");
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
      const chunk = decoder.decode(value, { stream: true });
      _appendLog(chunk);
    }
    _appendLog(`\n[${new Date().toLocaleTimeString()}] Done.\n`);
    _toast(`${action} finished`, "ok");
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

function _overallIcon(overall) {
  if (overall === "ok") return '<span class="hc-icon hc-icon--ok">✓</span>';
  if (overall === "fail") return '<span class="hc-icon hc-icon--fail">✗</span>';
  if (overall === "warn") return '<span class="hc-icon hc-icon--warn">!</span>';
  return '<span class="hc-icon" style="color:var(--text-muted)">?</span>';
}

function _overallClass(overall) {
  if (overall === "ok") return "hc-overall--ok";
  if (overall === "fail") return "hc-overall--fail";
  return "hc-overall--warn";
}

function _checkIcon(status) {
  if (status === "ok") return '<span class="hc-icon hc-icon--ok">✓</span>';
  if (status === "fail") return '<span class="hc-icon hc-icon--fail">✗</span>';
  return '<span class="hc-icon hc-icon--warn">!</span>';
}

function _renderStatusResults(results, boundScenarios) {
  const body = document.getElementById("status-body");
  if (!results || results.length === 0) {
    body.innerHTML = '<div class="status-empty">No nodes found in inventory.</div>';
    return;
  }

  const managers = results.filter(r => r.type === "manager");
  const agents = results.filter(r => r.type === "agent");

  let html = "";

  if (managers.length > 0) {
    html += `<div class="status-section-label">Managers</div>`;
    for (const node of managers) {
      html += _renderStatusCard(node, boundScenarios);
    }
  }

  if (agents.length > 0) {
    html += `<div class="status-section-label" style="margin-top:18px">Agents</div>`;
    for (const node of agents) {
      html += _renderStatusCard(node, boundScenarios);
    }
  }

  body.innerHTML = html;
}

function _renderStatusCard(node, boundScenarios) {
  const overall = node.overall || "unknown";
  const checks = node.checks || [];
  const okCount = node.ok || 0;
  const warnCount = node.warn || 0;
  const failCount = node.fail || 0;

  const summaryBadges = [
    failCount > 0 ? `<span class="status-tally status-tally--fail">${failCount} fail</span>` : "",
    warnCount > 0 ? `<span class="status-tally status-tally--warn">${warnCount} warn</span>` : "",
    okCount > 0 ? `<span class="status-tally status-tally--ok">${okCount} ok</span>` : "",
  ].filter(Boolean).join("");

  const nodeIcon = node.type === "manager" ? "M" : "A";
  const nodeColor = node.type === "manager" ? "var(--blue)" : "var(--green)";

  let checksHtml = "";
  if (checks.length === 0) {
    checksHtml = `<div class="status-check-empty">No check data returned.</div>`;
  } else {
    for (const c of checks) {
      const detail = (c.detail || "").replace(/^(OK|WARN|FAIL)\s*[-–]?\s*/i, "");
      checksHtml += `
        <div class="status-check-row status-check-row--${c.status}">
          ${_checkIcon(c.status)}
          <span class="status-check-detail">${_escHtml(detail)}</span>
        </div>`;
    }
  }

  return `
    <div class="status-node-card status-node-card--${overall}">
      <div class="status-node-header">
        <div class="status-node-icon" style="background:${nodeColor}20;color:${nodeColor};border:1px solid ${nodeColor}40">${nodeIcon}</div>
        <div class="status-node-name mono">${_escHtml(node.name)}</div>
        <div class="hc-overall ${_overallClass(overall)}" style="margin-left:8px">${overall.toUpperCase()}</div>
        <div class="status-tally-row">${summaryBadges}</div>
      </div>
      <div class="status-checks">${checksHtml}</div>
    </div>`;
}

function _escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function refreshStatus() {
  const btn = document.getElementById("status-refresh-btn");
  const body = document.getElementById("status-body");
  if (btn) btn.disabled = true;
  body.innerHTML = '<div class="status-empty" style="color:var(--text-muted)">Checking nodes…</div>';

  try {
    const res = await fetch("/api/deploy/status", { credentials: "same-origin" });

    if (res.status === 403) {
      const b = await res.json().catch(() => ({}));
      if (b.need_ssh) {
        body.innerHTML = '<div class="status-empty">SSH passphrase required — set it using the key icon in the header, then refresh.</div>';
        await window.RADAR.promptSSHPassphrase();
        return;
      }
      if (b.need_vault) {
        body.innerHTML = '<div class="status-empty">Vault locked — unlock it using the lock icon in the header, then refresh.</div>';
        await window.RADAR.promptVaultUnlock();
        return;
      }
    }

    const data = await res.json();
    if (!data.ok) {
      body.innerHTML = `<div class="status-empty" style="color:var(--red-text)">${_escHtml(data.error || "Unknown error")}</div>`;
      return;
    }
    _renderStatusResults(data.results, data.bound_scenarios || []);
  } catch (e) {
    body.innerHTML = `<div class="status-empty" style="color:var(--red-text)">${_escHtml(e.message)}</div>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

/*document.addEventListener("DOMContentLoaded", () => {
  const agentMode = document.getElementById("b-agent");
  const agentSelectWrap = document.getElementById("b-agent-select-wrap");
  const agentListLocal = document.getElementById("b-agent-list-local");
  const agentListRemote = document.getElementById("b-agent-list-remote");
  if (agentMode && agentSelectWrap) {
    agentMode.addEventListener("change", () => {
      const isRemote = agentMode.value === "remote";
      const isLocal = agentMode.value === "local";
      agentSelectWrap.style.display = (isRemote || isLocal) ? "" : "none";
      if (agentListLocal) agentListLocal.style.display = isLocal ? "" : "none";
      if (agentListRemote) agentListRemote.style.display = isRemote ? "" : "none";
      document.querySelectorAll(".agent-select-cb").forEach(cb => { cb.checked = false; });
    });
  }
});*/