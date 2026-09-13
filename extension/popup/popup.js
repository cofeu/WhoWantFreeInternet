// WWFI popup logic.
"use strict";

const el = (id) => document.getElementById(id);

function fmt(ts) {
  return new Date(ts).toLocaleTimeString();
}

async function render() {
  const s = await chrome.storage.local.get({
    enabled: true,
    gateway: "",
    registry: [],
    denyLog: [],
  });
  el("toggle").checked = !!s.enabled;
  el("gw").textContent = s.gateway || "—";
  el("state").textContent = s.enabled ? "on" : "off";
  el("state").className = "badge " + (s.enabled ? "on" : "off");

  try {
    const fp = await WWFIIdentity.fingerprint();
    el("fp").textContent = fp.slice(0, 24) + "…";
    el("fp").title = fp;
  } catch {
    el("fp").textContent = "unavailable";
  }

  const domains = el("domains");
  domains.innerHTML = "";
  if (!(s.registry || []).length) {
    domains.innerHTML = '<li class="muted">no registry yet</li>';
  } else {
    for (const d of s.registry) {
      const li = document.createElement("li");
      li.textContent = d.name || String(d);
      const known = document.createElement("span");
      known.textContent = d.backend ? "→ " + d.backend : "";
      known.className = "muted";
      li.appendChild(known);
      domains.appendChild(li);
    }
  }

  const deny = el("deny");
  deny.innerHTML = "";
  if (!(s.denyLog || []).length) {
    deny.innerHTML = '<li class="muted">none</li>';
  } else {
    for (const e of s.denyLog) {
      const li = document.createElement("li");
      li.textContent = e.host + " (" + e.reason + ")";
      const t = document.createElement("span");
      t.textContent = fmt(e.ts);
      t.className = "muted";
      li.appendChild(t);
      deny.appendChild(li);
    }
  }
}

el("toggle").addEventListener("change", async (e) => {
  await chrome.storage.local.set({ enabled: e.target.checked });
  render();
});

el("refresh").addEventListener("click", async (e) => {
  e.target.disabled = true;
  const r = await chrome.runtime.sendMessage({ type: "registry:refresh" });
  e.target.disabled = false;
  await render();
});

render();