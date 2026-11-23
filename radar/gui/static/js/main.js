"use strict";

window.RADAR = {

  async radarFetch(url, options = {}) {
    const res = await fetch(url, {
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      ...options,
    });
    if (res.status === 403) {
      const body = await res.clone().json().catch(() => ({}));
      if (body && body.need_sudo) {
        const ok = await RADAR.promptSudoPassword();
        if (ok) return RADAR.radarFetch(url, options);
        throw new Error("sudo password cancelled");
      }
    }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  _promptModal(cfg) {
    return new Promise((resolve) => {
      let modal = document.getElementById(cfg.id);
      if (!modal) {
        modal = document.createElement("div");
        modal.id = cfg.id;
        modal.className = "modal-backdrop";
        modal.innerHTML = `
          <div class="modal-box" style="width:420px">
            <div class="modal-title">${cfg.title}</div>
            <div class="modal-sub">${cfg.sub}</div>
            <div class="form-group" style="margin-top:14px">
              <label class="form-label">${cfg.label}</label>
              <input class="form-input" id="${cfg.id}-input" type="password" autocomplete="off">
            </div>
            <div class="modal-actions">
              <button class="btn" id="${cfg.id}-cancel">Cancel</button>
              <button class="btn btn--primary" id="${cfg.id}-submit">${cfg.btn}</button>
            </div>
            <div class="modal-error" id="${cfg.id}-err"></div>
          </div>`;
        document.body.appendChild(modal);
      }
      const input = modal.querySelector(`#${cfg.id}-input`);
      const errEl = modal.querySelector(`#${cfg.id}-err`);
      const cancelBtn = modal.querySelector(`#${cfg.id}-cancel`);
      const submitBtn = modal.querySelector(`#${cfg.id}-submit`);
      errEl.textContent = "";
      input.value = "";
      submitBtn.disabled = false;
      modal.style.display = "flex";
      setTimeout(() => input.focus(), 50);

      const cleanup = () => {
        modal.style.display = "none";
        input.removeEventListener("keydown", onKey);
        submitBtn.removeEventListener("click", onSubmit);
        cancelBtn.removeEventListener("click", onCancel);
      };
      const onCancel = () => { cleanup(); resolve(false); };
      const onSubmit = async () => {
        submitBtn.disabled = true;
        errEl.textContent = "Verifying…";
        try {
          const res = await fetch(cfg.endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({ [cfg.field]: input.value }),
          });
          const body = await res.json().catch(() => ({}));
          if (!res.ok || !body.ok) {
            errEl.textContent = body.error || `HTTP ${res.status}`;
            submitBtn.disabled = false;
            return;
          }
          cleanup();
          if (cfg.onSuccess) cfg.onSuccess();
          resolve(true);
        } catch (e) {
          errEl.textContent = e.message;
          submitBtn.disabled = false;
        }
      };
      const onKey = (e) => { if (e.key === "Enter") onSubmit(); if (e.key === "Escape") onCancel(); };
      submitBtn.addEventListener("click", onSubmit);
      cancelBtn.addEventListener("click", onCancel);
      input.addEventListener("keydown", onKey);
    });
  },

  promptSudoPassword() {
    return RADAR._promptModal({
      id: "radar-sudo-modal",
      title: "Sudo Password",
      sub: "Bringing up the local manager stack needs <code>sudo</code> on this machine. Kept in memory only — used to feed <code>sudo -A</code> non-interactively, never logged.",
      label: "Sudo password",
      btn: "Set",
      endpoint: "/api/sudo/unlock",
      field: "password",
      onSuccess: () => RADAR._updateSudoBadge(true),
    });
  },

  _updateSudoBadge(unlocked) {
    const badge = document.getElementById("sudo-badge");
    if (!badge) return;
    badge.style.display = "";
    badge.dataset.set = unlocked ? "1" : "0";
    badge.innerHTML = unlocked
      ? "🛡️ Sudo password set &nbsp;<a href='#' id='sudo-clear-link'>clear</a>"
      : "🛡️ Sudo password &nbsp;<a href='#' id='sudo-set-link'>set</a>";
    const cl = badge.querySelector("#sudo-clear-link");
    const sl2 = badge.querySelector("#sudo-set-link");
    if (cl) cl.onclick = async (e) => {
      e.preventDefault();
      await fetch("/api/sudo/lock", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" } });
      RADAR._updateSudoBadge(false);
    };
    if (sl2) sl2.onclick = (e) => { e.preventDefault(); RADAR.promptSudoPassword(); };
  },

  _jobRunning() {
    return typeof _currentAbortController !== "undefined" && !!_currentAbortController;
  },

  confirmLogout() {
    return new Promise((resolve) => {
      let modal = document.getElementById("radar-logout-modal");
      if (!modal) {
        modal = document.createElement("div");
        modal.id = "radar-logout-modal";
        modal.className = "modal-backdrop";
        modal.innerHTML = `
          <div class="modal-box" style="width:440px">
            <div class="modal-title">Log out and stop the GUI?</div>
            <div class="modal-sub">This stops the RADAR GUI server, frees its port, and forgets the stored sudo password.
              Every open GUI tab stops working. To log in again, run <code>./radar.sh gui</code> and open the new login URL it prints.</div>
            <div class="modal-sub" id="radar-logout-job" style="margin-top:8px;color:var(--red-text)"></div>
            <div class="modal-actions">
              <button class="btn" id="radar-logout-cancel">Cancel</button>
              <button class="btn btn--danger" id="radar-logout-submit">Log out</button>
            </div>
            <div class="modal-error" id="radar-logout-err"></div>
          </div>`;
        document.body.appendChild(modal);
      }
      const jobEl = modal.querySelector("#radar-logout-job");
      const errEl = modal.querySelector("#radar-logout-err");
      const cancelBtn = modal.querySelector("#radar-logout-cancel");
      const submitBtn = modal.querySelector("#radar-logout-submit");
      jobEl.textContent = RADAR._jobRunning()
        ? "A job is still running on the Deployment page. Logging out stops it."
        : "Any job still running on the Deployment page is stopped.";
      errEl.textContent = "";
      submitBtn.disabled = false;
      modal.style.display = "flex";
      setTimeout(() => cancelBtn.focus(), 50);

      const cleanup = () => {
        modal.style.display = "none";
        submitBtn.removeEventListener("click", onSubmit);
        cancelBtn.removeEventListener("click", onCancel);
        document.removeEventListener("keydown", onKey);
      };
      const onCancel = () => { cleanup(); resolve(false); };
      const onSubmit = async () => {
        submitBtn.disabled = true;
        errEl.textContent = "Logging out…";
        try {
          const res = await fetch("/api/logout", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: "{}",
          });
          const body = await res.json().catch(() => ({}));
          if (!res.ok || !body.ok) {
            errEl.textContent = body.error || `HTTP ${res.status}`;
            submitBtn.disabled = false;
            return;
          }
          cleanup();
          RADAR._showLoggedOut(body);
          resolve(true);
        } catch (e) {
          errEl.textContent = e.message;
          submitBtn.disabled = false;
        }
      };
      const onKey = (e) => { if (e.key === "Escape") onCancel(); };
      submitBtn.addEventListener("click", onSubmit);
      cancelBtn.addEventListener("click", onCancel);
      document.addEventListener("keydown", onKey);
    });
  },

  _showLoggedOut(result) {
    const port = window.location.port || (window.location.protocol === "https:" ? "443" : "80");
    const n = result.stopped_jobs || 0;
    const jobs = n
      ? `<p class="modal-sub">${n === 1 ? "1 running job was" : `${n} running jobs were`} stopped.</p>` : "";
    const server = result.server_stopping
      ? `<p class="modal-sub">The RADAR GUI server has stopped and port ${port} is free.</p>`
      : `<p class="modal-sub">Your session has ended.</p>`;
    document.title = "Logged out - RADAR";
    document.body.innerHTML = `
      <div class="logged-out">
        <div class="modal-box logged-out__box">
          <div class="modal-title">You've been logged out</div>
          ${server}${jobs}
          <p class="modal-sub">To log in again, run <code>./radar.sh gui</code> on the RADAR host and open the new login URL it prints. You can close this tab.</p>
        </div>
      </div>`;
  },

  initLogout() {
    const btn = document.getElementById("logout-btn");
    if (btn) btn.addEventListener("click", () => RADAR.confirmLogout());
  },

  async initSudoBadge() {
    const badge = document.getElementById("sudo-badge");
    if (!badge) return;
    badge.style.display = "";
    const s = await fetch("/api/sudo/status", { credentials: "same-origin" })
      .then(r => r.json()).catch(() => ({ unlocked: false }));
    RADAR._updateSudoBadge(s.unlocked);
  },

};

document.addEventListener("DOMContentLoaded", () => {
  RADAR.initSudoBadge();
  RADAR.initLogout();
});