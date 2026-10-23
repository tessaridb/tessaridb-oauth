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
  var moment = /* @__PURE__ */ new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" });
  function when(unixSeconds) {
    return moment.format(new Date(unixSeconds * 1e3));
  }
  var EMAIL_TEXT = {
    confirming: "Confirming your new sign-in address.",
    confirmed: "New address confirmed",
    confirmedNote: (effectiveAt) => `Your account signs in with this address from ${when(effectiveAt)}, unless the change is cancelled from your current address. You can close this page.`,
    cancelPrompt: "Someone asked to change the address your account signs in with. If it wasn't you, keep your current address.",
    cancelling: "Cancelling the change.",
    cancelled: "Change cancelled",
    cancelledNote: "Your account keeps signing in with this address. If you didn't ask for the change, change your password too.",
    invalidLink: "This link isn't complete. Open the link from the email again.",
    spentLink: "This link no longer works: it was already used, a newer request replaced it, or the change already took effect.",
    hint: "We'll send a link to the new address. The change takes effect a day after you ask, and your current address can cancel it until then.",
    required: "Enter the new address.",
    invalid: "Enter an email address like name@example.com.",
    sending: "Sending a message to the new address.",
    sent: "We sent a message to the new address. Open its link within 24 hours to confirm the change.",
    same: "That's already the address you sign in with.",
    unavailable: "Changing your address isn't set up here. Ask your administrator."
  };

  // src/email-read.ts
  var FRAGMENT = /^#(confirm|cancel)=([A-Za-z0-9_-]{43})$/;
  function emailApi(pathname) {
    const suffix = "/login/email";
    if (!pathname.endsWith(suffix)) {
      return null;
    }
    const tenant = pathname.slice(0, -suffix.length);
    return tenant.length > 1 ? `${tenant}/login/api` : null;
  }
  function readEmailLink(hash) {
    const match = FRAGMENT.exec(hash);
    const [, kind, token] = match ?? [];
    if (kind !== "confirm" && kind !== "cancel" || token === void 0) {
      return null;
    }
    return { kind, token };
  }
  function confirmOutcome(status, body, retryAfter) {
    const effectiveAt = field(body, "effective_at");
    if (status === 202) {
      return typeof effectiveAt === "number" ? { kind: "confirmed", effectiveAt } : { kind: "retry" };
    }
    return spent(status, body, retryAfter);
  }
  function cancelOutcome(status, body, retryAfter) {
    return status === 204 ? { kind: "cancelled" } : spent(status, body, retryAfter);
  }
  function spent(status, body, retryAfter) {
    if (status === 400 && field(body, "code") === "code_rejected") {
      return { kind: "link" };
    }
    return status === 429 ? refusal(status, body, retryAfter) : { kind: "retry" };
  }

  // src/email.ts
  function title(text2) {
    element("title", HTMLHeadingElement).textContent = text2;
  }
  async function confirm(base, token) {
    say(EMAIL_TEXT.confirming);
    const answer = await call("POST", `${base}/email/confirm`, { token });
    const outcome = confirmOutcome(answer.status, answer.body, answer.retryAfter);
    switch (outcome.kind) {
      case "confirmed":
        title(EMAIL_TEXT.confirmed);
        say(EMAIL_TEXT.confirmedNote(outcome.effectiveAt));
        return;
      case "link":
        say(EMAIL_TEXT.spentLink);
        return;
      default:
        say(refusalText(outcome));
    }
  }
  function offerCancel(base, token) {
    const keep = element("keep", HTMLButtonElement);
    say(EMAIL_TEXT.cancelPrompt);
    keep.hidden = false;
    keep.addEventListener("click", () => {
      void (async () => {
        keep.disabled = true;
        say(EMAIL_TEXT.cancelling);
        const answer = await call("POST", `${base}/email/cancel`, { token });
        keep.disabled = false;
        const outcome = cancelOutcome(answer.status, answer.body, answer.retryAfter);
        switch (outcome.kind) {
          case "cancelled":
            keep.hidden = true;
            title(EMAIL_TEXT.cancelled);
            say(EMAIL_TEXT.cancelledNote);
            return;
          case "link":
            keep.hidden = true;
            say(EMAIL_TEXT.spentLink);
            return;
          default:
            say(refusalText(outcome));
        }
      })();
    });
  }
  function main() {
    const link2 = readEmailLink(location.hash);
    history.replaceState(null, "", location.pathname);
    const base = emailApi(location.pathname);
    if (base === null || link2 === null) {
      say(EMAIL_TEXT.invalidLink);
      return;
    }
    if (link2.kind === "confirm") {
      void confirm(base, link2.token);
    } else {
      offerCancel(base, link2.token);
    }
  }
  window.addEventListener("hashchange", () => {
    location.reload();
  });
  main();
  void showBrand("../assets/");
})();
