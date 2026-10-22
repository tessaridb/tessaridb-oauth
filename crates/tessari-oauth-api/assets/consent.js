"use strict";
(() => {
  // src/copy.ts
  var seconds = new Intl.PluralRules("en");
  function inSeconds(count) {
    return seconds.select(count) === "one" ? `${count} second` : `${count} seconds`;
  }
  function refusalText(refused) {
    switch (refused.kind) {
      case "rejected":
        return "That didn't match. Check it and try again.";
      case "expired":
        return "This sign-in has expired. Go back to the application and start again.";
      case "throttled":
        return refused.seconds === null ? "Too many attempts. Wait a moment, then try again." : `Too many attempts. Try again in ${inSeconds(refused.seconds)}.`;
      case "retry":
        return "Something went wrong on our side. Try again in a moment.";
    }
  }
  var SCOPES = {
    openid: "Confirmation that you signed in, and who you are to this application",
    profile: "Your name and basic profile details",
    email: "Your email address and whether it is verified",
    offline_access: "Access while you are signed out or not using it"
  };
  function describeScope(scope) {
    return Object.hasOwn(SCOPES, scope) ? SCOPES[scope] ?? scope : scope;
  }
  var TEXT = {
    starting: "Preparing your sign-in.",
    missing: "This page needs a sign-in to continue. Go back to the application and start again.",
    passkeyCancelled: "The passkey wasn't used. Try again, or sign in another way.",
    emailRequired: "Enter the email address you signed up with.",
    passwordRequired: "Enter your password.",
    codeRequired: "Enter the 6-digit code from your authenticator app.",
    recoveryRequired: "Enter one of your recovery codes.",
    continuing: "Signed in. Taking you back to the application.",
    consentLoading: "Checking what the application asks for.",
    consentNothing: "This application asks for nothing new.",
    allowed: "Access allowed. Taking you back to the application.",
    denied: "Access denied. Taking you back to the application."
  };

  // src/dom.ts
  function element(id, kind) {
    const found = document.getElementById(id);
    if (!(found instanceof kind)) {
      throw new Error(`the page has no ${kind.name} #${id}`);
    }
    return found;
  }
  async function call(method, path, body) {
    const init = {
      method,
      credentials: "same-origin",
      cache: "no-store",
      headers: { accept: "application/json", "content-type": "application/json" }
    };
    if (body !== void 0) {
      init.body = JSON.stringify(body);
    }
    try {
      const response = await fetch(path, init);
      const text = await response.text();
      let parsed = null;
      try {
        parsed = text === "" ? null : JSON.parse(text);
      } catch {
        parsed = null;
      }
      return { ok: response.ok, status: response.status, body: parsed, retryAfter: response.headers.get("retry-after") };
    } catch {
      return { ok: false, status: 0, body: null, retryAfter: null };
    }
  }
  function say(text) {
    element("status", HTMLParagraphElement).textContent = text;
  }

  // src/flow.ts
  function field(value, key) {
    if (typeof value !== "object" || value === null) {
      return void 0;
    }
    const fields = Object.entries(value);
    return fields.find(([name]) => name === key)?.[1];
  }
  function strings(value) {
    return Array.isArray(value) && value.every((item) => typeof item === "string") ? value : null;
  }
  function url(text) {
    if (typeof text !== "string") {
      return null;
    }
    try {
      return new URL(text);
    } catch {
      return null;
    }
  }
  function apiBase(pathname, page) {
    const suffix = `/${page}`;
    if (!pathname.endsWith(suffix)) {
      return null;
    }
    const tenant = pathname.slice(0, -suffix.length);
    return tenant.length > 1 ? `${tenant}/login/api` : null;
  }
  function readRedirect(answer) {
    const target = url(field(answer, "redirect"));
    if (target === null || ["javascript:", "data:", "vbscript:", "blob:", "file:"].includes(target.protocol)) {
      return null;
    }
    return target.href;
  }
  function readDelta(answer) {
    const clientId = field(answer, "client_id");
    const scopes = strings(field(answer, "scopes"));
    const resources = strings(field(answer, "resources"));
    if (typeof clientId !== "string" || scopes === null || resources === null) {
      return null;
    }
    return { clientId, scopes, resources };
  }
  function refusal(status, body, retryAfter) {
    const code = field(body, "code");
    if (status === 401 && code === "credentials_rejected") {
      return { kind: "rejected" };
    }
    if (status === 410 || code === "session_required") {
      return { kind: "expired" };
    }
    if (status === 429) {
      const seconds2 = retryAfter !== null && /^\d+$/.test(retryAfter) ? Number(retryAfter) : null;
      return { kind: "throttled", seconds: seconds2 };
    }
    return { kind: "retry" };
  }

  // src/consent.ts
  var request = element("request", HTMLDivElement);
  var allow = element("allow", HTMLButtonElement);
  var deny = element("deny", HTMLButtonElement);
  function list(id, items) {
    const target = element(id, HTMLUListElement);
    target.replaceChildren(
      ...items.map((item) => {
        const entry = document.createElement("li");
        entry.textContent = item;
        return entry;
      })
    );
  }
  async function decide(base, interaction, decision) {
    allow.disabled = true;
    deny.disabled = true;
    const answer = await call("POST", `${base}/consent`, { interaction, decision });
    const target = answer.ok ? readRedirect(answer.body) : null;
    if (target !== null) {
      request.hidden = true;
      say(decision === "allow" ? TEXT.allowed : TEXT.denied);
      location.assign(target);
      return;
    }
    allow.disabled = false;
    deny.disabled = false;
    const refused = answer.ok ? { kind: "retry" } : refusal(answer.status, answer.body, answer.retryAfter);
    if (refused.kind === "expired") {
      request.hidden = true;
    }
    say(refusalText(refused));
  }
  async function main() {
    const base = apiBase(location.pathname, "consent");
    const interaction = new URLSearchParams(location.search).get("interaction");
    if (base === null || interaction === null || interaction === "") {
      say(TEXT.missing);
      return;
    }
    const asked = await call("GET", `${base}/consent?${new URLSearchParams({ interaction }).toString()}`);
    const delta = asked.ok ? readDelta(asked.body) : null;
    if (delta === null) {
      say(refusalText(asked.ok ? { kind: "retry" } : refusal(asked.status, asked.body, asked.retryAfter)));
      return;
    }
    element("client", HTMLElement).textContent = delta.clientId;
    list("scopes", delta.scopes.length === 0 ? [TEXT.consentNothing] : delta.scopes.map(describeScope));
    list("resources", delta.resources);
    element("resources-block", HTMLDivElement).hidden = delta.resources.length === 0;
    allow.addEventListener("click", () => void decide(base, interaction, "allow"));
    deny.addEventListener("click", () => void decide(base, interaction, "deny"));
    request.hidden = false;
    say("");
    allow.focus();
  }
  void main();
})();
