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
  function fieldError(input, text) {
    const error = element(`${input.id}-error`, HTMLParagraphElement);
    error.textContent = text ?? "";
    error.hidden = text === null;
    if (text === null) {
      input.removeAttribute("aria-invalid");
    } else {
      input.setAttribute("aria-invalid", "true");
      input.focus();
    }
  }
  function say(text) {
    element("status", HTMLParagraphElement).textContent = text;
  }

  // src/flow.ts
  var STEPS = ["identify", "first_factor", "second_factor", "complete"];
  function field(value2, key) {
    if (typeof value2 !== "object" || value2 === null) {
      return void 0;
    }
    const fields = Object.entries(value2);
    return fields.find(([name]) => name === key)?.[1];
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
  function readNext(answer) {
    const next = field(answer, "next");
    return STEPS.find((step2) => step2 === next) ?? null;
  }
  function readCompleted(answer, origin) {
    if (readNext(answer) !== "complete") {
      return null;
    }
    const target = url(field(answer, "continue"));
    return target !== null && target.origin === origin ? target.href : null;
  }
  function refusal(status, body, retryAfter) {
    const code2 = field(body, "code");
    if (status === 401 && code2 === "credentials_rejected") {
      return { kind: "rejected" };
    }
    if (status === 410 || code2 === "session_required") {
      return { kind: "expired" };
    }
    if (status === 429) {
      const seconds2 = retryAfter !== null && /^\d+$/.test(retryAfter) ? Number(retryAfter) : null;
      return { kind: "throttled", seconds: seconds2 };
    }
    return { kind: "retry" };
  }
  var ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  function toBase64url(bytes) {
    let text = "";
    for (let at = 0; at < bytes.length; at += 3) {
      const chunk = bytes.subarray(at, at + 3);
      const bits = (chunk[0] ?? 0) << 16 | (chunk[1] ?? 0) << 8 | (chunk[2] ?? 0);
      const sextets = [bits >> 18, bits >> 12, bits >> 6, bits].map((value2) => ALPHABET[value2 & 63] ?? "");
      text += sextets.slice(0, chunk.length + 1).join("");
    }
    return text;
  }
  function fromBase64url(text) {
    if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
      return null;
    }
    const bytes = [];
    let bits = 0;
    let held = 0;
    for (const char of text) {
      bits = bits << 6 | ALPHABET.indexOf(char);
      held += 6;
      if (held >= 8) {
        held -= 8;
        bytes.push(bits >> held & 255);
      }
    }
    return Uint8Array.from(bytes);
  }
  function readPasskeyOptions(answer) {
    const challenge = field(answer, "challenge");
    const rpId = field(answer, "rp_id");
    const verification = field(answer, "user_verification");
    const timeout = field(answer, "timeout_ms");
    const bytes = typeof challenge === "string" ? fromBase64url(challenge) : null;
    if (bytes === null || bytes.length === 0 || typeof rpId !== "string" || typeof timeout !== "number") {
      return null;
    }
    if (verification !== "required" && verification !== "preferred") {
      return null;
    }
    return { challenge: bytes, rpId, userVerification: verification, timeout };
  }

  // src/login.ts
  var STEP_FORMS = ["identify", "first_factor", "second_factor"];
  var email = element("email", HTMLInputElement);
  var password = element("password", HTMLInputElement);
  var code = element("code", HTMLInputElement);
  var recovery = element("recovery", HTMLInputElement);
  var passkeyOption = element("passkey-option", HTMLDivElement);
  var passkeyButton = element("passkey", HTMLButtonElement);
  var passkeys = typeof window.PublicKeyCredential === "function";
  var usingRecovery = false;
  function busy(on) {
    for (const button of document.querySelectorAll("button")) {
      button.disabled = on;
    }
  }
  function hideSteps() {
    for (const step2 of STEP_FORMS) {
      element(step2, HTMLFormElement).hidden = true;
    }
    passkeyOption.hidden = true;
  }
  function show(step2) {
    hideSteps();
    if (step2 === "complete") {
      return;
    }
    element(step2, HTMLFormElement).hidden = false;
    passkeyOption.hidden = !passkeys;
    passkeyButton.textContent = step2 === "second_factor" ? "Use a passkey instead" : "Sign in with a passkey";
    say("");
    const first = step2 === "identify" ? email : step2 === "first_factor" ? password : usingRecovery ? recovery : code;
    first.focus();
  }
  function settle(answer, input) {
    if (answer.ok) {
      const next = readNext(answer.body);
      if (next === "complete") {
        const target = readCompleted(answer.body, location.origin);
        if (target === null) {
          say(refusalText({ kind: "retry" }));
          return;
        }
        hideSteps();
        say(TEXT.continuing);
        location.assign(target);
        return;
      }
      if (next === null) {
        say(refusalText({ kind: "retry" }));
        return;
      }
      show(next);
      return;
    }
    const refused = refusal(answer.status, answer.body, answer.retryAfter);
    if (refused.kind === "expired") {
      hideSteps();
    }
    if (refused.kind === "rejected" && input !== null) {
      fieldError(input, refusalText(refused));
      return;
    }
    say(refusalText(refused));
  }
  async function step(base, path, body, input) {
    busy(true);
    const answer = await call("POST", `${base}/${path}`, body);
    busy(false);
    settle(answer, input);
  }
  function value(input, missing) {
    const text = input.value.trim();
    fieldError(input, text === "" ? missing : null);
    return text === "" ? null : text;
  }
  async function passkey(base) {
    busy(true);
    const asked = await call("POST", `${base}/passkey/options`);
    const options = asked.ok ? readPasskeyOptions(asked.body) : null;
    if (options === null) {
      busy(false);
      if (asked.ok) {
        say(refusalText({ kind: "retry" }));
      } else {
        settle(asked, null);
      }
      return;
    }
    let credential = null;
    try {
      credential = await navigator.credentials.get({
        publicKey: {
          challenge: options.challenge,
          rpId: options.rpId,
          userVerification: options.userVerification,
          timeout: options.timeout,
          allowCredentials: []
        }
      });
    } catch {
      credential = null;
    }
    if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) {
      busy(false);
      say(TEXT.passkeyCancelled);
      return;
    }
    const response = credential.response;
    const bytes = (buffer) => toBase64url(new Uint8Array(buffer));
    await step(
      base,
      "passkey",
      {
        credential_id: bytes(credential.rawId),
        client_data_json: bytes(response.clientDataJSON),
        authenticator_data: bytes(response.authenticatorData),
        signature: bytes(response.signature)
      },
      null
    );
  }
  async function main() {
    const base = apiBase(location.pathname, "login");
    const interaction = new URLSearchParams(location.search).get("interaction");
    if (base === null || interaction === null || interaction === "") {
      say(TEXT.missing);
      return;
    }
    element("identify", HTMLFormElement).addEventListener("submit", (event) => {
      event.preventDefault();
      const address = value(email, TEXT.emailRequired);
      if (address !== null) {
        element("who", HTMLElement).textContent = address;
        void step(base, "identify", { email: address }, email);
      }
    });
    element("first_factor", HTMLFormElement).addEventListener("submit", (event) => {
      event.preventDefault();
      const typed = value(password, TEXT.passwordRequired);
      if (typed !== null) {
        void step(base, "password", { password: password.value }, password);
      }
    });
    element("second_factor", HTMLFormElement).addEventListener("submit", (event) => {
      event.preventDefault();
      const input = usingRecovery ? recovery : code;
      const typed = value(input, usingRecovery ? TEXT.recoveryRequired : TEXT.codeRequired);
      if (typed !== null) {
        void step(base, usingRecovery ? "recovery" : "totp", { code: typed }, input);
      }
    });
    const reveal = element("reveal", HTMLButtonElement);
    reveal.addEventListener("click", () => {
      const shown = password.type === "text";
      password.type = shown ? "password" : "text";
      reveal.setAttribute("aria-pressed", String(!shown));
      reveal.textContent = shown ? "Show" : "Hide";
    });
    const switcher = element("use-recovery", HTMLButtonElement);
    switcher.addEventListener("click", () => {
      usingRecovery = !usingRecovery;
      element("code-field", HTMLDivElement).hidden = usingRecovery;
      element("recovery-field", HTMLDivElement).hidden = !usingRecovery;
      switcher.textContent = usingRecovery ? "Use your authenticator app instead" : "Use a recovery code instead";
      (usingRecovery ? recovery : code).focus();
    });
    passkeyButton.addEventListener("click", () => {
      void passkey(base);
    });
    if (!passkeys) {
      passkeyOption.hidden = true;
    }
    say(TEXT.starting);
    const begun = await call("POST", `${base}/begin`, { interaction });
    settle(begun, null);
  }
  void main();
})();
