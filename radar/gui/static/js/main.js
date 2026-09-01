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
      await fetch("/api/sudo/lock", { method: "POST", credentials: "same-origin" });
      RADAR._updateSudoBadge(false);
    };
    if (sl2) sl2.onclick = (e) => { e.preventDefault(); RADAR.promptSudoPassword(); };
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
});