// WWFI shared settings and request classification helpers.
//
// Settings live in chrome.storage.local. The registry is the published-domain
// list pulled from the WWFI gateway (/api/domains); policy decisions are taken
// against registry + explicit pin map.
//
// global: WWFIConfig, WWFIRouter
"use strict";

const WWFIConfig = {
  DEFAULTS: {
    enabled: true,
    gateway: "", // e.g. https://cofeu.org or http://192.168.1.50:8087
    token: "", // WWFI dashboard / API bearer token
    enforcePolicy: true, // deny requests to unknown WWFI-ish domains
    pin: {}, // domain -> {host?, port?, enabled} explicit routing pins
    registry: [], // [{ name, backend? }] from gateway /api/domains
    denyLog: [],
  },

  async get() {
    return chrome.storage.local.get(this.DEFAULTS);
  },

  async set(patch) {
    await chrome.storage.local.set(patch);
  },

  async reset() {
    await chrome.storage.local.clear();
  },
};

const WWFIRouter = {
  // Does the host look like a WWFI-managed domain?
  isWwfiHost(host, s) {
    if (!host) return false;
    if (host === "localhost" || host === "127.0.0.1") return false;
    const pin = s.pin || {};
    if (pin[host] && pin[host].enabled !== false) return true;
    if (host.endsWith(".local")) return true;
    return (s.registry || []).some((r) => r && r.name === host);
  },

  // Policy: allow only hosts we actually know about (pinned or published).
  isKnownHost(host, s) {
    const pin = s.pin || {};
    if (pin[host] && pin[host].enabled !== false) return true;
    return (s.registry || []).some((r) => r && r.name === host);
  },

  isInternalUrl(url) {
    return (
      url.startsWith("chrome-extension://") ||
      url.startsWith("chrome://") ||
      url.startsWith("about:")
    );
  },
};