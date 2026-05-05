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
      if (body && body.need_vault) {
        const ok = await RADAR.promptVaultUnlock();
        if (ok) return RADAR.radarFetch(url, options);
        throw new Error("vault unlock cancelled");
      }
      if (body && body.need_ssh) {
        const ok = await RADAR.promptSSHPassphrase();
        if (ok) return RADAR.radarFetch(url, options);
        throw new Error("ssh passphrase cancelled");
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

  promptVaultUnlock() {
    return RADAR._promptModal({
      id: "radar-vault-modal",
      title: "Unlock Ansible Vault",
      sub: "Encrypted <code>host_vars/</code> files need the vault password. Kept in memory only.",
      label: "Vault password",
      btn: "Unlock",
      endpoint: "/api/vault/unlock",
      field: "password",
      onSuccess: () => RADAR._updateVaultBadge(true),
    });
  },

  promptSSHPassphrase() {
    return RADAR._promptModal({
      id: "radar-ssh-modal",
      title: "SSH Key Passphrase",
      sub: "Enter the passphrase for your SSH private key (<code>~/.ssh/id_ed25519</code>). Kept in memory only — used to load the key into a private ssh-agent for Ansible.",
      label: "Passphrase (leave blank if key has none)",
      btn: "Set",
      endpoint: "/api/ssh/set",
      field: "passphrase",
      onSuccess: () => RADAR._updateSSHBadge(true),
    });
  },

  _updateVaultBadge(unlocked) {
    const badge = document.getElementById("vault-badge");
    if (!badge) return;
    badge.dataset.unlocked = unlocked ? "1" : "0";
    badge.style.display = "";
    badge.innerHTML = unlocked
      ? "🔓 Vault unlocked &nbsp;<a href='#' id='vault-lock-link'>lock</a>"
      : "🔒 Vault locked &nbsp;<a href='#' id='vault-unlock-link'>unlock</a>";
    const ll = badge.querySelector("#vault-lock-link");
    const ul = badge.querySelector("#vault-unlock-link");
    if (ll) ll.onclick = async (e) => {
      e.preventDefault();
      await fetch("/api/vault/lock", { method: "POST", credentials: "same-origin" });
      RADAR._updateVaultBadge(false);
    };
    if (ul) ul.onclick = (e) => { e.preventDefault(); RADAR.promptVaultUnlock(); };
  },

  _updateSSHBadge(isSet) {
    const badge = document.getElementById("ssh-badge");
    if (!badge) return;
    badge.style.display = "";
    badge.dataset.set = isSet ? "1" : "0";
    badge.innerHTML = isSet
      ? "🔑 SSH passphrase set &nbsp;<a href='#' id='ssh-clear-link'>clear</a>"
      : "🔑 SSH passphrase &nbsp;<a href='#' id='ssh-set-link'>set</a>";
    const cl = badge.querySelector("#ssh-clear-link");
    const sl = badge.querySelector("#ssh-set-link");
    if (cl) cl.onclick = async (e) => {
      e.preventDefault();
      await fetch("/api/ssh/clear", { method: "POST", credentials: "same-origin" });
      RADAR._updateSSHBadge(false);
    };
    if (sl) sl.onclick = (e) => { e.preventDefault(); RADAR.promptSSHPassphrase(); };
  },

  async initVaultBadge() {
    const badge = document.getElementById("vault-badge");
    if (!badge) return;
    const s = await fetch("/api/vault/status", { credentials: "same-origin" })
      .then(r => r.json()).catch(() => ({ unlocked: false, any_encrypted: false }));
    if (!s.any_encrypted && !s.unlocked) { badge.style.display = "none"; return; }
    RADAR._updateVaultBadge(s.unlocked);
  },

  async initSSHBadge() {
    const badge = document.getElementById("ssh-badge");
    if (!badge) return;
    badge.style.display = "";
    const s = await fetch("/api/ssh/status", { credentials: "same-origin" })
      .then(r => r.json()).catch(() => ({ set: false }));
    RADAR._updateSSHBadge(s.set);
  },

};

document.addEventListener("DOMContentLoaded", () => {
  RADAR.initVaultBadge();
  RADAR.initSSHBadge();
});