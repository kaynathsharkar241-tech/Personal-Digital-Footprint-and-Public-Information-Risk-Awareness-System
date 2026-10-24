/* ---- helpers ---- */
const $ = (id) => document.getElementById(id);

function b64uToBuf(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
}
function bufToB64u(buf) {
  let s = "";
  new Uint8Array(buf).forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function show(text, ok = false) {
  const m = $("msg");
  if (!m) return;
  m.textContent = text;
  m.className = "msg " + (ok ? "ok" : "err");
  m.hidden = false;
}

async function post(url, body = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch (_) {}
  if (!res.ok || data.ok === false) throw new Error(data.error || "Something went wrong.");
  return data;
}

function guessDeviceName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  if (/Android/.test(ua)) return "Android phone";
  if (/Mac/.test(ua)) return "Mac";
  if (/Windows/.test(ua)) return "Windows PC";
  return "This device";
}

function webauthnSupported() {
  return !!(window.PublicKeyCredential && navigator.credentials);
}

function friendlyWebAuthnError(err) {
  if (err && err.name === "NotAllowedError") return "Cancelled or timed out. Please try again.";
  if (err && err.name === "InvalidStateError") return "This device already has a passkey for this account.";
  return err.message || "Something went wrong.";
}

/* ---- WebAuthn ceremonies ---- */
async function createPasskey(optionsUrl, verifyUrl, optionsBody = {}) {
  const opts = await post(optionsUrl, optionsBody);
  opts.challenge = b64uToBuf(opts.challenge);
  opts.user.id = b64uToBuf(opts.user.id);
  (opts.excludeCredentials || []).forEach((c) => (c.id = b64uToBuf(c.id)));

  const cred = await navigator.credentials.create({ publicKey: opts });
  return post(verifyUrl, {
    device_name: guessDeviceName(),
    credential: {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
      clientExtensionResults: cred.getClientExtensionResults(),
    },
  });
}

async function loginWithPasskey() {
  const opts = await post("/api/login/options");
  opts.challenge = b64uToBuf(opts.challenge);
  (opts.allowCredentials || []).forEach((c) => (c.id = b64uToBuf(c.id)));

  const cred = await navigator.credentials.get({ publicKey: opts });
  return post("/api/login/verify", {
    credential: {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        authenticatorData: bufToB64u(cred.response.authenticatorData),
        signature: bufToB64u(cred.response.signature),
        userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null,
      },
      clientExtensionResults: cred.getClientExtensionResults(),
    },
  });
}

/* ---- page wiring ---- */
function on(id, handler) {
  const el = $(id);
  if (!el) return;
  el.addEventListener("click", async (e) => {
    e.preventDefault();
    el.disabled = true;
    try {
      const data = await handler();
      if (data && data.redirect) window.location = data.redirect;
    } catch (err) {
      show(friendlyWebAuthnError(err));
    } finally {
      el.disabled = false;
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  if (!webauthnSupported() && ($("signup-btn") || $("passkey-login-btn"))) {
    show("This browser doesn't support passkeys. Use a recovery code or PIN, or try Safari, Chrome or Edge.");
  }

  on("signup-btn", () => createPasskey("/api/register/options", "/api/register/verify",
                                       { nickname: $("nickname").value }));
  on("passkey-login-btn", loginWithPasskey);
  on("add-passkey-btn", () => createPasskey("/api/passkey/options", "/api/passkey/verify"));

  on("pin-login-btn", () => post("/api/pin/login", { nickname: $("pin-nickname").value, pin: $("pin").value }));
  on("recovery-btn", () => post("/api/recovery/login", { nickname: $("rec-nickname").value, code: $("rec-code").value }));

  on("set-pin-btn", async () => {
    await post("/api/pin/set", { pin: $("new-pin").value });
    window.location.reload();
  });
  on("remove-pin-btn", async () => { await post("/api/pin/remove"); window.location.reload(); });
  on("regen-btn", () => {
    if (!confirm("This cancels your old recovery codes. Continue?")) return Promise.resolve();
    return post("/api/recovery/regenerate");
  });

  document.querySelectorAll("[data-delete-passkey]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      if (!confirm("Remove this passkey?")) return;
      try {
        await post("/api/passkey/delete", { credential_id: btn.dataset.deletePasskey });
        window.location.reload();
      } catch (err) { show(err.message); }
    }));

  /* recovery-codes page */
  const codesEl = $("codes");
  if (codesEl) {
    const text = () => [...codesEl.querySelectorAll("li")].map((li) => li.textContent).join("\n");
    $("copy-codes").addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(text()); show("Copied.", true); }
      catch (_) { show("Couldn't copy. Select the codes manually."); }
    });
    $("download-codes").addEventListener("click", () => {
      const url = URL.createObjectURL(new Blob(["Privacy Monitor recovery codes\n\n" + text() + "\n"], { type: "text/plain" }));
      const a = Object.assign(document.createElement("a"), { href: url, download: "recovery-codes.txt" });
      a.click();
      URL.revokeObjectURL(url);
    });
    const link = $("continue-link");
    $("saved-check").addEventListener("change", (e) => {
      link.classList.toggle("disabled", !e.target.checked);
      link.setAttribute("aria-disabled", String(!e.target.checked));
    });
    link.addEventListener("click", (e) => { if (link.classList.contains("disabled")) e.preventDefault(); });
  }
});
