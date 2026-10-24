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

  // src/account-read.ts
  var PASSWORD_RULES = {
    "the password is too short": "too-short",
    "the password is too long": "too-long",
    "the password holds a character that is not printable": "not-printable",
    "the password is too easily guessed": "guessable"
  };
  function changeRefusal(status, body) {
    const code = field(body, "code");
    if (status === 401 && code === "reauthentication_required") {
      return "reauthenticate";
    }
    if (status === 401 && code === "session_required") {
      return "signed-out";
    }
    if (status === 400 && code === "password_rejected") {
      const message = field(body, "message");
      return typeof message === "string" && Object.hasOwn(PASSWORD_RULES, message) ? PASSWORD_RULES[message] ?? "rejected" : "rejected";
    }
    return "other";
  }

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
  var moment = /* @__PURE__ */ new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" });
  function when(unixSeconds) {
    return moment.format(new Date(unixSeconds * 1e3));
  }
  var ENROL_TEXT = {
    invalidLink: "This link isn't complete. Open the link from the email again.",
    spentLink: "This link has expired or was already used. Ask your administrator for a new one.",
    already: "This account already has a password. Sign in with it, or reset it from the sign-in page.",
    hint: "At least 15 characters. A few unrelated words work well.",
    passwordRequired: "Choose a password.",
    saving: "Saving your password.",
    set: "Your password is set. Sign in with it from the application you use, or from the sign-in page."
  };
  var ACCOUNT_TEXT = {
    loading: "Loading your account.",
    missing: "This page could not find its account. Check the address and try again.",
    unreadable: "Your account could not be loaded. Try again in a moment.",
    signedOut: "You're not signed in here. Sign in to see and manage your account.",
    verified: "Verified",
    unverified: "Not verified",
    set: "Set",
    notSet: "Not set",
    on: "On",
    off: "Off",
    noPasskeys: "No passkeys yet.",
    noSessions: "No other sessions.",
    noGrants: "No applications have access.",
    thisSession: "this session",
    ended: "Signed out on that session.",
    everywhereConfirm: "This signs you out on every device, this one included. Applications keep access only until their current tokens expire.",
    everywhereDone: "Signed out everywhere.",
    revoked: (client, endBy) => `Removed ${client}'s access. Anything it already holds stops working by ${when(endBy)}.`,
    notRevoked: "That access was already removed.",
    reauthenticate: "Changing how you sign in needs a sign-in from the last ten minutes. Sign in again, then try once more.",
    passwordHintAlone: "At least 15 characters. A few unrelated words work well.",
    passwordHintWithApp: "At least 8 characters, since you also use an authenticator app.",
    passwordRequired: "Enter a new password.",
    passwordTooShort: "That password is too short for this account.",
    passwordTooLong: "That password is too long. Use 64 characters or fewer.",
    passwordNotPrintable: "That password has a character that can't be typed. Remove it and try again.",
    passwordGuessable: "That password is too easy to guess. Don't use your email address.",
    passwordRejected: "That password can't be used. Choose a longer one that isn't your email address and isn't known from a breach.",
    passwordChanged: "Password changed. You were signed out on your other devices.",
    codesIssued: "New recovery codes are ready. Your old ones no longer work.",
    alreadyEnrolled: "This account already has an authenticator app.",
    appCodeRequired: "Enter the 6-digit code your app shows for this account.",
    appStartAgain: "That code didn't match, so the key was discarded. Set up the app again to get a new key.",
    appAdded: "Authenticator app turned on. You were signed out on your other devices.",
    lastMethod: "That's the last way to sign in to this account. Add another one before removing it.",
    appNotOffered: "Your organization doesn't use authenticator apps, so one can't be set up here.",
    keepOne: "Your organization requires a second way to confirm it's you. Add a passkey or an app before removing this one.",
    enrolDue: "Your organization requires a second way to confirm it's you. Add a passkey or an authenticator app to keep signing in to its applications.",
    appRemoved: "Authenticator app turned off. You were signed out on your other devices.",
    passkeyNotAccepted: "That passkey couldn't be added. Try again, or use a different device.",
    passkeyCancelled: "No passkey was added.",
    passkeyAdded: "Passkey added. You were signed out on your other devices.",
    passkeyRemoved: "Passkey removed. You were signed out on your other devices.",
    nameHint: "Applications you allow to see your name get these. Leave a field empty to clear it.",
    nameRejected: "A name can be up to 100 characters, with no line breaks or tabs. Shorten it and try again.",
    nameSaved: "Your name is saved. Applications see the change the next time they ask."
  };

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
  function fieldError(input2, text2) {
    const error = element(`${input2.id}-error`, HTMLParagraphElement);
    error.textContent = text2 ?? "";
    error.hidden = text2 === null;
    if (text2 === null) {
      input2.removeAttribute("aria-invalid");
    } else {
      input2.setAttribute("aria-invalid", "true");
      input2.focus();
    }
  }
  function say(text2) {
    element("status", HTMLParagraphElement).textContent = text2;
  }

  // src/account-factors.ts
  function passwordRuleText(why) {
    switch (why) {
      case "too-short":
        return ACCOUNT_TEXT.passwordTooShort;
      case "too-long":
        return ACCOUNT_TEXT.passwordTooLong;
      case "not-printable":
        return ACCOUNT_TEXT.passwordNotPrintable;
      case "guessable":
        return ACCOUNT_TEXT.passwordGuessable;
      default:
        return ACCOUNT_TEXT.passwordRejected;
    }
  }

  // src/brand-read.ts
  function text(value) {
    return typeof value === "string" && value !== "" ? value : null;
  }
  function link(value) {
    return typeof value === "string" && value.startsWith("https://") ? value : null;
  }
  function seconds2(value) {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  function readBrand(body) {
    return {
      name: text(field(body, "name")),
      support: link(field(body, "support")),
      privacy: link(field(body, "privacy")),
      logo: seconds2(field(body, "logo"))
    };
  }
  function logoAddress(uploaded, assets = "assets/") {
    return `${assets}logo.png?v=${uploaded}`;
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

  // src/enrol-read.ts
  var FRAGMENT = /^#code=([A-Za-z0-9_-]{43})$/;
  function enrolApi(pathname) {
    const suffix = "/login/enrol";
    if (!pathname.endsWith(suffix)) {
      return null;
    }
    const tenant = pathname.slice(0, -suffix.length);
    return tenant.length > 1 ? `${tenant}/login/api` : null;
  }
  function readEnrolCode(hash) {
    return FRAGMENT.exec(hash)?.[1] ?? null;
  }
  function enrolOutcome(status, body, retryAfter) {
    if (status === 204) {
      return { kind: "set" };
    }
    const code = field(body, "code");
    if (status === 400 && code === "code_rejected") {
      return { kind: "link" };
    }
    if (status === 409 && code === "already_enrolled") {
      return { kind: "already" };
    }
    if (status === 400 && code === "password_rejected") {
      return { kind: "password", why: changeRefusal(status, body) };
    }
    return status === 429 ? refusal(status, body, retryAfter) : { kind: "retry" };
  }

  // src/enrol.ts
  var form = element("enrol", HTMLFormElement);
  var input = element("new-password", HTMLInputElement);
  function busy(on) {
    for (const button of document.querySelectorAll("button")) {
      button.disabled = on;
    }
  }
  function finish(text2) {
    form.hidden = true;
    say(text2);
  }
  async function save(base, code) {
    const password = input.value;
    fieldError(input, password === "" ? ENROL_TEXT.passwordRequired : null);
    if (password === "") {
      return;
    }
    busy(true);
    say(ENROL_TEXT.saving);
    const answer = await call("POST", `${base}/enroll`, { code, password });
    busy(false);
    const outcome = enrolOutcome(answer.status, answer.body, answer.retryAfter);
    switch (outcome.kind) {
      case "set":
        input.value = "";
        finish(ENROL_TEXT.set);
        return;
      case "link":
        finish(ENROL_TEXT.spentLink);
        return;
      case "already":
        finish(ENROL_TEXT.already);
        return;
      case "password":
        say("");
        fieldError(input, passwordRuleText(outcome.why));
        return;
      default:
        say(refusalText(outcome));
    }
  }
  function main() {
    const code = readEnrolCode(location.hash);
    history.replaceState(null, "", location.pathname);
    const base = enrolApi(location.pathname);
    if (base === null || code === null) {
      say(ENROL_TEXT.invalidLink);
      return;
    }
    element("new-password-hint", HTMLParagraphElement).textContent = ENROL_TEXT.hint;
    const reveal = element("reveal", HTMLButtonElement);
    reveal.addEventListener("click", () => {
      const shown = input.type === "text";
      input.type = shown ? "password" : "text";
      reveal.setAttribute("aria-pressed", String(!shown));
      reveal.textContent = shown ? "Show" : "Hide";
    });
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void save(base, code);
    });
    form.hidden = false;
    input.focus();
  }
  window.addEventListener("hashchange", () => {
    location.reload();
  });
  main();
  void showBrand("../assets/");
})();
