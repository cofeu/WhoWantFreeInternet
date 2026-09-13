// WWFI device identity.
//
// A non-extractable WebCrypto keypair (ECDSA P-256) is generated once and stored
// in IndexedDB. The private key can never be exported, so the extension can sign
// handshake nonces / claims but nobody (not even the OS user via devtools) can
// exfiltrate it. The public fingerprint is attached to every WWFI request in the
// X-WWFI-Identity header.
//
// global: WWFIIdentity
"use strict";

const WWFIIdentity = (() => {
  const DB_NAME = "wwfi";
  const DB_VERSION = 1;
  const STORE = "keys";
  const KEY = "device";
  let cached = null;

  function open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function store(keyPair) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite").objectStore(STORE);
      const r = tx.put(keyPair, KEY);
      r.onsuccess = () => resolve();
      r.onerror = () => reject(r.error);
    });
  }

  async function load() {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly").objectStore(STORE);
      const r = tx.get(KEY);
      r.onsuccess = () => resolve(r.result || null);
      r.onerror = () => reject(r.error);
    });
  }

  async function ensure() {
    if (cached) return cached;
    const existing = await load();
    if (existing) {
      cached = existing;
      return cached;
    }
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
    await store(keyPair);
    cached = keyPair;
    return keyPair;
  }

  async function fingerprint() {
    const keyPair = await ensure();
    const pub = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const payload = JSON.stringify({
      kty: pub.kty,
      crv: pub.crv,
      x: pub.x,
      y: pub.y,
    });
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(payload)
    );
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  async function sign(data) {
    const keyPair = await ensure();
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.privateKey,
      new TextEncoder().encode(data)
    );
    const bytes = new Uint8Array(signature);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 8192) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
    }
    return btoa(binary);
  }

  return { ensure, fingerprint, sign };
})();