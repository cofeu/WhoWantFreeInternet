// WWFI Client — background service worker.
//
// 1. Generates the device identity (non-extractable key) on install.
// 2. Pulls the published-domain registry from the gateway (`/api/domains`).
// 3. Attaches identity headers to requests toward WWFI domains
//    (X-WWFI-Identity, X-WWFI-Token, X-WWFI-Host) so the gateway can make
//    per-request identity + policy decisions.
// 4. Enforces policy: unknown WWFI-ish hosts are blocked unless pinned.
"use strict";

importScripts("lib/config.js", "lib/identity.js");

const STATE = {
  enabled: true,
  enforcePolicy: true,
  fingerprint: null,
  token: "",
  pin: {},
  registry: [],
};

async function refreshState() {
  const s = await WWFIConfig.get();
  STATE.enabled = !!s.enabled;
  STATE.enforcePolicy = !!s.enforcePolicy;
  STATE.token = s.token || "";
  STATE.pin = s.pin || {};
  STATE.registry = s.registry || [];
  try {
    STATE.fingerprint = await WWFIIdentity.fingerprint();
  } catch (e) {
    console.warn("[wwfi] fingerprint unavailable:", e);
    STATE.fingerprint = null;
  }
}

async function refreshRegistry() {
  const s = await WWFIConfig.get();
  // The "gateway" is the local WWFI mesh node's control API (name plane):
  // GET /api/domains returns the domains this client can reach over the mesh.
  if (!s.gateway) return;
  try {
    const headers = {};
    if (s.token) headers.Authorization = "Bearer " + s.token;
    const resp = await fetch(new URL("/api/domains", s.gateway), { headers });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();
    const list = Array.isArray(data) ? data : data.domains || [];
    const registry = list.map((d) =>
      typeof d === "string" ? { name: d } : d
    );
    await WWFIConfig.set({ registry });
    return { ok: true, count: registry.length };
  } catch (e) {
    console.warn("[wwfi] registry refresh failed:", e);
    return { ok: false, error: String(e) };
  }
}

async function recordDeny(host, reason) {
  const s = await WWFIConfig.get();
  const denyLog = (s.denyLog || []).slice(0, 49);
  denyLog.unshift({ host, reason, ts: Date.now() });
  await WWFIConfig.set({ denyLog });
}

function authHeadersFor(host, details) {
  const headers = (details.requestHeaders || [])
    .filter((h) => h && h.name && !/^X-WWFI-/i.test(h.name))
    .map((h) => ({ name: h.name, value: h.value }));
  headers.push({ name: "X-WWFI-Client", value: "1" });
  if (STATE.fingerprint)
    headers.push({ name: "X-WWFI-Identity", value: STATE.fingerprint });
  if (STATE.token) headers.push({ name: "X-WWFI-Token", value: STATE.token });
  headers.push({ name: "X-WWFI-Host", value: host });
  return headers;
}

chrome.runtime.onInstalled.addListener(() => {
  WWFIIdentity.ensure()
    .then(() => refreshState())
    .then(() => refreshRegistry());
});

chrome.runtime.onStartup.addListener(() => {
  refreshState();
  refreshRegistry();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  refreshState();
  if (changes.gateway || changes.token) refreshRegistry();
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg !== "object") return;
  if (msg.type === "registry:refresh") {
    refreshRegistry().then(sendResponse);
    return true; // async response
  }
  if (msg.type === "denyLog:clear") {
    WWFIConfig.set({ denyLog: [] }).then(() => sendResponse({ ok: true }));
    return true;
  }
});

// --- identity header injection (synchronous, uses cached STATE) ---
const HEADER_TYPES = ["main_frame", "sub_frame", "xmlhttprequest", "other"];

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!STATE.enabled || !details || !details.url) return { requestHeaders: details.requestHeaders };
    if (WWFIRouter.isInternalUrl(details.url)) return { requestHeaders: details.requestHeaders };
    let host;
    try {
      host = new URL(details.url).hostname;
    } catch {
      return { requestHeaders: details.requestHeaders };
    }
    return { requestHeaders: authHeadersFor(host, details) };
  },
  { urls: ["http://*/*", "https://*/*"], types: HEADER_TYPES },
  ["requestHeaders", "extraHeaders"]
);

// --- policy enforcement: cancel unknown WWFI-ish hosts ---
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!STATE.enabled || !details || !details.url) return {};
    if (WWFIRouter.isInternalUrl(details.url)) return {};
    let host;
    try {
      host = new URL(details.url).hostname;
    } catch {
      return {};
    }
    const s = STATE; // synchronous snapshot for the blocking list then
    if (!WWFIRouter.isWwfiHost(host, s)) return {};
    if (!STATE.enforcePolicy) return {};
    if (!WWFIRouter.isKnownHost(host, s)) {
      recordDeny(host, "policy");
      console.warn("[wwfi] blocked by policy:", details.url);
      return { cancel: true };
    }
    return {};
  },
  { urls: ["http://*/*", "https://*/*"], types: HEADER_TYPES },
  ["blocking"]
);