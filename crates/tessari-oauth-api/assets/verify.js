"use strict";
(() => {
  // src/flow.ts
  function field(value, key) {
    if (typeof value !== "object" || value === null) {
      return void 0;
    }
    const fields = Object.entries(value);
    return fields.find(([name]) => name === key)?.[1];
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
      const seconds3 = retryAfter !== null && /^\d+$/.test(retryAfter) ? Number(retryAfter) : null;
      return { kind: "throttled", seconds: seconds3 };
    }
    return { kind: "retry" };
  }

  // src/brand-read.ts
  function text(value) {
    return typeof value === "string" && value !== "" ? value : null;
  }
  function link(value) {
    return typeof value === "string" && value.startsWith("https://") ? value : null;
  }
  function seconds(value) {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  function readBrand(body) {
    return {
      name: text(field(body, "name")),
      support: link(field(body, "support")),
      privacy: link(field(body, "privacy")),
      logo: seconds(field(body, "logo"))
    };
  }
  function logoAddress(uploaded, assets = "assets/") {
    return `${assets}logo.png?v=${uploaded}`;
  }

  // src/dom.ts
  function element(id, kind) {
    const found = document.getElementById(id);
    if (!(found instanceof kind)) {
      throw new Error(`the page has no ${kind.name} #${id}`);
    }
    return found;
  }
  async function call(method, path, body, extra) {
    const init = {
      method,
      credentials: "same-origin",
      cache: "no-store",
      headers: { accept: "application/json", "content-type": "application/json", ...extra }
    };
    if (body !== void 0) {
      init.body = JSON.stringify(body);
    }
    try {
      const response = await fetch(path, init);
      const text2 = await response.text();
      let parsed = null;
      try {
        parsed = text2 === "" ? null : JSON.parse(text2);
      } catch {
        parsed = null;
      }
      return { ok: response.ok, status: response.status, body: parsed, retryAfter: response.headers.get("retry-after") };
    } catch {
      return { ok: false, status: 0, body: null, retryAfter: null };
    }
  }
  function say(text2) {
    element("status", HTMLParagraphElement).textContent = text2;
  }

  // src/brand.ts
  function offer(id, address) {
    const anchor = element(id, HTMLAnchorElement);
    if (address !== null) {
      anchor.href = address;
    }
    anchor.hidden = address === null;
    return address !== null;
  }
  async function showBrand(assets = "assets/") {
    const answer = await call("GET", `${assets}brand.json`);
    if (!answer.ok) {
      return;
    }
    const brand = readBrand(answer.body);
    if (brand.name !== null) {
      element("brand-name", HTMLSpanElement).textContent = brand.name;
    }
    if (brand.logo !== null) {
      element("brand-logo", HTMLImageElement).src = logoAddress(brand.logo, assets);
    }
    const support = offer("brand-support", brand.support);
    const privacy = offer("brand-privacy", brand.privacy);
    element("brand-links", HTMLParagraphElement).hidden = !support && !privacy;
  }

  // src/copy.ts
  var seconds2 = new Intl.PluralRules("en");
  function inSeconds(count) {
    return seconds2.select(count) === "one" ? `${count} second` : `${count} seconds`;
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
  var VERIFY_TEXT = {
    confirming: "Confirming your email address.",
    confirmed: "Email address confirmed",
    confirmedNote: "Your account now shows this address as verified. You can close this page.",
    invalidLink: "This confirmation link isn't complete. Open the link from the email again.",
    spentLink: "This confirmation link has expired, was already used, or a newer one was sent. Ask for a new one on your account page.",
    sending: "Sending a verification link.",
    sent: "We sent a verification link to your address. It works for 24 hours.",
    unavailable: "Email verification isn't set up here. Ask your administrator."
  };

  // src/reset-read.ts
  var FRAGMENT = /^#token=([A-Za-z0-9_-]{43})$/;
  function readResetToken(hash) {
    return FRAGMENT.exec(hash)?.[1] ?? null;
  }

  // src/verify-read.ts
  function verifyApi(pathname) {
    const suffix = "/login/verify";
    if (!pathname.endsWith(suffix)) {
      return null;
    }
    const tenant = pathname.slice(0, -suffix.length);
    return tenant.length > 1 ? `${tenant}/login/api` : null;
  }
  function readVerifyToken(hash) {
    return readResetToken(hash);
  }
  function verifyOutcome(status, body, retryAfter) {
    if (status === 204) {
      return { kind: "verified" };
    }
    if (status === 400 && field(body, "code") === "code_rejected") {
      return { kind: "link" };
    }
    return status === 429 ? refusal(status, body, retryAfter) : { kind: "retry" };
  }

  // src/verify.ts
  async function confirm(base, token) {
    say(VERIFY_TEXT.confirming);
    const answer = await call("POST", `${base}/verify`, { token });
    const outcome = verifyOutcome(answer.status, answer.body, answer.retryAfter);
    switch (outcome.kind) {
      case "verified":
        element("title", HTMLHeadingElement).textContent = VERIFY_TEXT.confirmed;
        say(VERIFY_TEXT.confirmedNote);
        return;
      case "link":
        say(VERIFY_TEXT.spentLink);
        return;
      default:
        say(refusalText(outcome));
    }
  }
  function main() {
    const token = readVerifyToken(location.hash);
    history.replaceState(null, "", location.pathname);
    const base = verifyApi(location.pathname);
    if (base === null || token === null) {
      say(VERIFY_TEXT.invalidLink);
      return;
    }
    void confirm(base, token);
  }
  window.addEventListener("hashchange", () => {
    location.reload();
  });
  main();
  void showBrand("../assets/");
})();
