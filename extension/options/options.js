// WWFI options logic.
"use strict";

const $ = (id) => document.getElementById(id);
const msg = $("msg");

function flash(text, ok) {
  msg.textContent = text;
  msg.className = ok ? "ok" : "muted";
  clearTimeout(flash._t);
  flash._t = setTimeout(() => (msg.textContent = ""), 2500);
}

async function load() {
  const s = await chrome.storage.local.get({
    enabled: true,
    gateway: "http://127.0.0.1:8123",
    token: "",
    enforcePolicy: true,
    pin: {},
  });
  $("enabled").checked = !!s.enabled;
  $("gateway").value = s.gateway || "";
  $("token").value = s.token || "";
  $("enforcePolicy").checked = !!s.enforcePolicy;
  $("pin").value = JSON.stringify(s.pin || {}, null, 2);
}

$("save").addEventListener("click", async () => {
  let pin = {};
  try {
    pin = $("pin").value.trim() ? JSON.parse($("pin").value) : {};
  } catch {
    flash("pin is not valid JSON", false);
    return;
  }
  await chrome.storage.local.set({
    enabled: $("enabled").checked,
    gateway: $("gateway").value.trim(),
    token: $("token").value.trim(),
    enforcePolicy: $("enforcePolicy").checked,
    pin,
  });
  flash("Saved ✓", true);
});

$("sync").addEventListener("click", async () => {
  const r = await chrome.runtime.sendMessage({ type: "registry:refresh" });
  flash(
    r && r.ok ? `Registry synced (${r.count} domains)` : ("Sync failed: " + (r && r.error)),
    r && r.ok
  );
});

$("reset").addEventListener("click", async () => {
  await chrome.storage.local.clear();
  await load();
  flash("Reset ✓", true);
});

load();