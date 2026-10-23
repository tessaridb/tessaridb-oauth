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
  function strings(value) {
    return Array.isArray(value) && value.every((item) => typeof item === "string") ? value : null;
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
  var ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  function toBase64url(bytes2) {
    let text3 = "";
    for (let at = 0; at < bytes2.length; at += 3) {
      const chunk = bytes2.subarray(at, at + 3);
      const bits = (chunk[0] ?? 0) << 16 | (chunk[1] ?? 0) << 8 | (chunk[2] ?? 0);
      const sextets = [bits >> 18, bits >> 12, bits >> 6, bits].map((value) => ALPHABET[value & 63] ?? "");
      text3 += sextets.slice(0, chunk.length + 1).join("");
    }
    return text3;
  }
  function fromBase64url(text3) {
    if (!/^[A-Za-z0-9_-]*$/.test(text3) || text3.length % 4 === 1) {
      return null;
    }
    const bytes2 = [];
    let bits = 0;
    let held = 0;
    for (const char of text3) {
      bits = bits << 6 | ALPHABET.indexOf(char);
      held += 6;
      if (held >= 8) {
        held -= 8;
        bytes2.push(bits >> held & 255);
      }
    }
    return Uint8Array.from(bytes2);
  }

  // src/account-read.ts
  function accountApi(pathname) {
    const suffix = "/account";
    if (!pathname.endsWith(suffix)) {
      return null;
    }
    const tenant = pathname.slice(0, -suffix.length);
    return tenant.length > 1 ? `${tenant}/account/api` : null;
  }
  function text(value) {
    return typeof value === "string" ? value : null;
  }
  function nameOrNull(value) {
    return typeof value === "string" || value === null ? value : void 0;
  }
  function readNames(value) {
    const name = nameOrNull(field(value, "name"));
    const givenName = nameOrNull(field(value, "given_name"));
    const familyName = nameOrNull(field(value, "family_name"));
    if (name === void 0 || givenName === void 0 || familyName === void 0) {
      return null;
    }
    return { name, givenName, familyName };
  }
  function flag(value) {
    return typeof value === "boolean" ? value : null;
  }
  function count(value) {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  function every(value, read) {
    if (!Array.isArray(value)) {
      return null;
    }
    const items = [];
    for (const item of value) {
      const readItem = read(item);
      if (readItem === null) {
        return null;
      }
      items.push(readItem);
    }
    return items;
  }
  function readPasskey(value) {
    const id = text(field(value, "id"));
    const createdAt = count(field(value, "created_at"));
    const synced = flag(field(value, "synced"));
    return id === null || createdAt === null || synced === null ? null : { id, createdAt, synced };
  }
  function readMe(answer) {
    const factors = field(answer, "factors");
    const email = text(field(answer, "email"));
    const emailVerified = flag(field(answer, "email_verified"));
    const password = flag(field(factors, "password"));
    const totp = flag(field(factors, "totp"));
    const recoveryCodes = count(field(factors, "recovery_codes"));
    const passkeys = every(field(factors, "passkeys"), readPasskey);
    const twoFactor = policy(field(answer, "two_factor"));
    const profile = readNames(field(answer, "profile"));
    if (email === null || emailVerified === null || password === null || totp === null || recoveryCodes === null || passkeys === null || twoFactor === null || profile === null) {
      return null;
    }
    return { email, emailVerified, password, totp, recoveryCodes, passkeys, twoFactor, profile };
  }
  function policy(value) {
    return value === "off" || value === "optional" || value === "required" ? value : null;
  }
  function appAsked(me) {
    return me.totp && me.twoFactor !== "off";
  }
  function enrolmentDue(me) {
    return me.twoFactor === "required" && !me.totp && me.passkeys.length === 0;
  }
  function readSession(value) {
    const sid = text(field(value, "sid"));
    const signedInAt = count(field(value, "signed_in_at"));
    const lastSeenAt = count(field(value, "last_seen_at"));
    const methods = strings(field(value, "methods"));
    const current = flag(field(value, "current"));
    if (sid === null || signedInAt === null || lastSeenAt === null || methods === null || current === null) {
      return null;
    }
    return { sid, signedInAt, lastSeenAt, methods, current };
  }
  function readSessions(answer) {
    return every(field(answer, "sessions"), readSession);
  }
  function readGrant(value) {
    const clientId = text(field(value, "client_id"));
    const scopes = strings(field(value, "scopes"));
    const resources = strings(field(value, "resources"));
    const grantedAt = count(field(value, "granted_at"));
    if (clientId === null || scopes === null || resources === null || grantedAt === null) {
      return null;
    }
    return { clientId, scopes, resources, grantedAt };
  }
  function readGrants(answer) {
    return every(field(answer, "grants"), readGrant);
  }
  function readEndBy(answer) {
    return count(field(answer, "access_tokens_end_by"));
  }
  function readSavedNames(answer) {
    return readNames(field(answer, "profile"));
  }
  function profileRefused(status, body) {
    return status === 400 && field(body, "code") === "profile_rejected";
  }
  function readIssuedCodes(answer) {
    const codes2 = strings(field(answer, "codes"));
    return codes2 === null || codes2.length === 0 ? null : codes2;
  }
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
  function inSeconds(count2) {
    return seconds.select(count2) === "one" ? `${count2} second` : `${count2} seconds`;
  }
  function refusalText(refused3) {
    switch (refused3.kind) {
      case "rejected":
        return "That didn't match. Check it and try again.";
      case "expired":
        return "This sign-in has expired. Go back to the application and start again.";
      case "throttled":
        return refused3.seconds === null ? "Too many attempts. Wait a moment, then try again." : `Too many attempts. Try again in ${inSeconds(refused3.seconds)}.`;
      case "retry":
        return "Something went wrong on our side. Try again in a moment.";
    }
  }
  var SCOPES = {
    openid: "Confirmation that you signed in, and who you are to this application",
    profile: "Your name: full, given and family",
    email: "Your email address and whether it is verified",
    offline_access: "Access while you are signed out or not using it",
    groups: "The groups you are in at this company, and the roles they give you"
  };
  function describeScope(scope) {
    return Object.hasOwn(SCOPES, scope) ? SCOPES[scope] ?? scope : scope;
  }
  var METHODS = {
    pwd: "Password",
    totp: "Authenticator app",
    recovery: "Recovery code",
    passkey: "Passkey",
    "passkey-uv": "Passkey"
  };
  function describeMethods(methods) {
    const named = methods.map((method) => Object.hasOwn(METHODS, method) ? METHODS[method] ?? method : method);
    return new Intl.ListFormat("en", { type: "conjunction" }).format([...new Set(named)]);
  }
  var moment = /* @__PURE__ */ new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" });
  function when(unixSeconds) {
    return moment.format(new Date(unixSeconds * 1e3));
  }
  var codes = /* @__PURE__ */ new Intl.PluralRules("en");
  function codesLeft(count2) {
    if (count2 === 0) {
      return "None left";
    }
    return codes.select(count2) === "one" ? "1 code left" : `${count2} codes left`;
  }
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
    passwordRejected: "That password can't be used. Choose a longer one that isn't your email address.",
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
      const text3 = await response.text();
      let parsed = null;
      try {
        parsed = text3 === "" ? null : JSON.parse(text3);
      } catch {
        parsed = null;
      }
      return { ok: response.ok, status: response.status, body: parsed, retryAfter: response.headers.get("retry-after") };
    } catch {
      return { ok: false, status: 0, body: null, retryAfter: null };
    }
  }
  function fieldError(input, text3) {
    const error = element(`${input.id}-error`, HTMLParagraphElement);
    error.textContent = text3 ?? "";
    error.hidden = text3 === null;
    if (text3 === null) {
      input.removeAttribute("aria-invalid");
    } else {
      input.setAttribute("aria-invalid", "true");
      input.focus();
    }
  }
  function say(text3) {
    element("status", HTMLParagraphElement).textContent = text3;
  }

  // src/account-factors.ts
  function offerSignIn() {
    element("sign-in", HTMLParagraphElement).hidden = false;
  }
  function refusedText(why, answer) {
    switch (why) {
      case "reauthenticate":
        offerSignIn();
        return ACCOUNT_TEXT.reauthenticate;
      case "too-short":
      case "too-long":
      case "not-printable":
      case "guessable":
      case "rejected":
        return null;
      case "signed-out":
      case "other":
        return refusalText(refusal(answer.status, answer.body, answer.retryAfter));
    }
  }
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
  function wirePassword(base, holdsApp, followups) {
    const open = element("password-open", HTMLButtonElement);
    const form = element("password-form", HTMLFormElement);
    const input = element("new-password", HTMLInputElement);
    const cancel = element("password-cancel", HTMLButtonElement);
    element("password-username", HTMLInputElement).value = element("email", HTMLElement).textContent ?? "";
    element("new-password-hint", HTMLParagraphElement).textContent = holdsApp ? ACCOUNT_TEXT.passwordHintWithApp : ACCOUNT_TEXT.passwordHintAlone;
    const close = () => {
      input.value = "";
      fieldError(input, null);
      form.hidden = true;
      open.hidden = false;
      open.focus();
    };
    open.addEventListener("click", () => {
      form.hidden = false;
      open.hidden = true;
      input.focus();
    });
    cancel.addEventListener("click", close);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void (async () => {
        if (input.value === "") {
          fieldError(input, ACCOUNT_TEXT.passwordRequired);
          return;
        }
        const submit = form.querySelector("button[type=submit]");
        if (submit instanceof HTMLButtonElement) {
          submit.disabled = true;
        }
        const answer = await call("POST", `${base}/password`, { password: input.value });
        if (submit instanceof HTMLButtonElement) {
          submit.disabled = false;
        }
        if (answer.ok) {
          close();
          say(ACCOUNT_TEXT.passwordChanged);
          await followups.changed();
          return;
        }
        const why = changeRefusal(answer.status, answer.body);
        if (why === "signed-out") {
          followups.signedOut();
          return;
        }
        const text3 = refusedText(why, answer);
        if (text3 === null) {
          fieldError(input, passwordRuleText(why));
        } else {
          say(text3);
        }
      })();
    });
  }
  function wireRecoveryCodes(base, followups) {
    const open = element("codes-open", HTMLButtonElement);
    const confirm2 = element("codes-confirm", HTMLDivElement);
    const yes = element("codes-yes", HTMLButtonElement);
    const no = element("codes-no", HTMLButtonElement);
    const shown = element("codes-shown", HTMLDivElement);
    const list = element("codes", HTMLUListElement);
    const saved = element("codes-saved", HTMLButtonElement);
    open.addEventListener("click", () => {
      confirm2.hidden = false;
      open.hidden = true;
      no.focus();
    });
    no.addEventListener("click", () => {
      confirm2.hidden = true;
      open.hidden = false;
      open.focus();
    });
    yes.addEventListener("click", () => {
      void (async () => {
        yes.disabled = true;
        const answer = await call("POST", `${base}/recovery-codes`, {});
        yes.disabled = false;
        const codes2 = answer.ok ? readIssuedCodes(answer.body) : null;
        if (codes2 === null) {
          const why = changeRefusal(answer.status, answer.body);
          if (why === "signed-out") {
            followups.signedOut();
            return;
          }
          say(refusedText(why, answer) ?? ACCOUNT_TEXT.unreadable);
          return;
        }
        list.replaceChildren(
          ...codes2.map((code) => {
            const item = document.createElement("li");
            const text3 = document.createElement("code");
            text3.textContent = code;
            item.append(text3);
            return item;
          })
        );
        confirm2.hidden = true;
        shown.hidden = false;
        say(ACCOUNT_TEXT.codesIssued);
        saved.focus();
        await followups.changed();
      })();
    });
    saved.addEventListener("click", () => {
      list.replaceChildren();
      shown.hidden = true;
      open.hidden = false;
      open.focus();
    });
  }

  // src/enrolment-read.ts
  function readAppSecret(answer) {
    const secret = field(answer, "secret");
    const uri = field(answer, "uri");
    if (typeof secret !== "string" || secret === "" || typeof uri !== "string" || !uri.startsWith("otpauth://totp/")) {
      return null;
    }
    return { secret, uri };
  }
  function bytes(value) {
    const decoded = typeof value === "string" ? fromBase64url(value) : null;
    return decoded === null || decoded.length === 0 ? null : decoded;
  }
  function readRegistration(answer) {
    const challenge = bytes(field(answer, "challenge"));
    const rpId = field(answer, "rp_id");
    const user = field(answer, "user");
    const userId = bytes(field(user, "id"));
    const userName = field(user, "name");
    const excludedIds = strings(field(answer, "exclude"));
    const exclude = excludedIds?.map(bytes) ?? null;
    const algorithms = field(answer, "algorithms");
    const verification = field(answer, "user_verification");
    const timeout = field(answer, "timeout_ms");
    if (challenge === null || typeof rpId !== "string" || userId === null || typeof userName !== "string" || exclude === null || !Array.isArray(algorithms) || algorithms.length === 0 || !algorithms.every((algorithm) => Number.isSafeInteger(algorithm)) || verification !== "required" && verification !== "preferred" || typeof timeout !== "number") {
      return null;
    }
    const excluded = exclude.filter((id) => id !== null);
    if (excluded.length !== exclude.length) {
      return null;
    }
    return {
      challenge,
      rpId,
      userId,
      userName,
      exclude: excluded,
      algorithms: algorithms.filter((algorithm) => typeof algorithm === "number"),
      userVerification: verification,
      timeout
    };
  }
  function enrolRefusal(status, body) {
    const code = field(body, "code");
    switch (code) {
      case "already_enrolled":
        return "already-enrolled";
      case "nothing_pending":
        return "start-again";
      case "code_rejected":
        return "code-rejected";
      case "last_sign_in_method":
        return "last-method";
      case "not_offered":
        return "not-offered";
      case "second_factor_required":
        return "keep-one";
      case "invalid_request":
        return "not-accepted";
      case "reauthentication_required":
        return status === 401 ? "reauthenticate" : "other";
      case "session_required":
        return status === 401 ? "signed-out" : "other";
      default:
        return "other";
    }
  }

  // src/account-enrol.ts
  function refused(answer, followups) {
    const why = enrolRefusal(answer.status, answer.body);
    switch (why) {
      case "signed-out":
        followups.signedOut();
        break;
      case "reauthenticate":
        offerSignIn();
        say(ACCOUNT_TEXT.reauthenticate);
        break;
      case "already-enrolled":
        say(ACCOUNT_TEXT.alreadyEnrolled);
        break;
      case "start-again":
      case "code-rejected":
        say(ACCOUNT_TEXT.appStartAgain);
        break;
      case "last-method":
        say(ACCOUNT_TEXT.lastMethod);
        break;
      case "not-offered":
        say(ACCOUNT_TEXT.appNotOffered);
        break;
      case "keep-one":
        say(ACCOUNT_TEXT.keepOne);
        break;
      case "not-accepted":
        say(ACCOUNT_TEXT.passkeyNotAccepted);
        break;
      case "other":
        say(refusalText(refusal(answer.status, answer.body, answer.retryAfter)));
        break;
    }
  }
  function wireApp(base, followups) {
    const open = element("app-open", HTMLButtonElement);
    const form = element("app-form", HTMLFormElement);
    const input = element("app-code", HTMLInputElement);
    const secret = element("app-secret", HTMLElement);
    const link2 = element("app-link", HTMLAnchorElement);
    const close = () => {
      input.value = "";
      secret.textContent = "";
      link2.removeAttribute("href");
      fieldError(input, null);
      form.hidden = true;
    };
    open.addEventListener("click", () => {
      void (async () => {
        open.disabled = true;
        const answer = await call("POST", `${base}/totp/begin`, {});
        open.disabled = false;
        const begun = answer.ok ? readAppSecret(answer.body) : null;
        if (begun === null) {
          refused(answer, followups);
          return;
        }
        secret.textContent = begun.secret;
        link2.href = begun.uri;
        form.hidden = false;
        open.hidden = true;
        input.focus();
      })();
    });
    element("app-cancel", HTMLButtonElement).addEventListener("click", () => {
      close();
      open.hidden = false;
      open.focus();
    });
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void (async () => {
        const code = input.value.replaceAll(" ", "");
        if (!/^\d{6}$/.test(code)) {
          fieldError(input, ACCOUNT_TEXT.appCodeRequired);
          return;
        }
        const answer = await call("POST", `${base}/totp/confirm`, { code });
        close();
        if (!answer.ok) {
          refused(answer, followups);
          open.hidden = false;
          open.focus();
          return;
        }
        say(ACCOUNT_TEXT.appAdded);
        await followups.changed();
      })();
    });
  }
  function wireAppOff(base, followups) {
    const off = element("app-off", HTMLButtonElement);
    const confirm2 = element("app-off-confirm", HTMLDivElement);
    const yes = element("app-off-yes", HTMLButtonElement);
    const no = element("app-off-no", HTMLButtonElement);
    off.addEventListener("click", () => {
      confirm2.hidden = false;
      off.hidden = true;
      no.focus();
    });
    no.addEventListener("click", () => {
      confirm2.hidden = true;
      off.hidden = false;
      off.focus();
    });
    yes.addEventListener("click", () => {
      void (async () => {
        yes.disabled = true;
        const answer = await call("POST", `${base}/totp/remove`, {});
        yes.disabled = false;
        confirm2.hidden = true;
        if (!answer.ok) {
          off.hidden = false;
          refused(answer, followups);
          return;
        }
        say(ACCOUNT_TEXT.appRemoved);
        await followups.changed();
      })();
    });
  }
  function wirePasskeyAdd(base, followups) {
    const add = element("passkey-add", HTMLButtonElement);
    add.hidden = typeof window.PublicKeyCredential !== "function";
    add.addEventListener("click", () => {
      void (async () => {
        add.disabled = true;
        try {
          await addPasskey(base, followups);
        } finally {
          add.disabled = false;
        }
      })();
    });
  }
  async function addPasskey(base, followups) {
    const asked = await call("POST", `${base}/passkeys/options`, {});
    const options = asked.ok ? readRegistration(asked.body) : null;
    if (options === null) {
      refused(asked, followups);
      return;
    }
    let created;
    try {
      created = await navigator.credentials.create({
        publicKey: {
          challenge: options.challenge,
          rp: { id: options.rpId, name: "TessariDB OAuth" },
          user: { id: options.userId, name: options.userName, displayName: options.userName },
          pubKeyCredParams: options.algorithms.map((alg) => ({ type: "public-key", alg })),
          excludeCredentials: options.exclude.map((id) => ({ type: "public-key", id })),
          authenticatorSelection: { residentKey: "required", userVerification: options.userVerification },
          attestation: "none",
          timeout: options.timeout
        }
      });
    } catch {
      created = null;
    }
    if (!(created instanceof PublicKeyCredential) || !(created.response instanceof AuthenticatorAttestationResponse)) {
      say(ACCOUNT_TEXT.passkeyCancelled);
      return;
    }
    const answer = await call("POST", `${base}/passkeys/register`, {
      client_data_json: toBase64url(new Uint8Array(created.response.clientDataJSON)),
      attestation_object: toBase64url(new Uint8Array(created.response.attestationObject))
    });
    if (!answer.ok) {
      refused(answer, followups);
      return;
    }
    say(ACCOUNT_TEXT.passkeyAdded);
    await followups.changed();
  }
  async function removePasskey(base, id, pressed, followups) {
    pressed.disabled = true;
    const answer = await call("POST", `${base}/passkeys/remove`, { id });
    pressed.disabled = false;
    if (!answer.ok) {
      refused(answer, followups);
      return;
    }
    say(ACCOUNT_TEXT.passkeyRemoved);
    await followups.changed();
  }

  // src/account-profile.ts
  var FIELDS = [
    { id: "name-full", key: "name" },
    { id: "name-given", key: "givenName" },
    { id: "name-family", key: "familyName" }
  ];
  function showNames(names) {
    for (const { id, key } of FIELDS) {
      element(`${id}-shown`, HTMLElement).textContent = names[key] ?? ACCOUNT_TEXT.notSet;
    }
  }
  function formError(inputs, text3) {
    const error = element("names-error", HTMLParagraphElement);
    error.textContent = text3 ?? "";
    error.hidden = text3 === null;
    for (const input of inputs) {
      if (text3 === null) {
        input.removeAttribute("aria-invalid");
      } else {
        input.setAttribute("aria-invalid", "true");
      }
    }
    if (text3 !== null) {
      inputs[0]?.focus();
    }
  }
  function wireProfile(base, kept, followups) {
    let names = kept;
    const open = element("names-open", HTMLButtonElement);
    const form = element("names-form", HTMLFormElement);
    const cancel = element("names-cancel", HTMLButtonElement);
    const inputs = FIELDS.map(({ id }) => element(id, HTMLInputElement));
    element("names-hint", HTMLParagraphElement).textContent = ACCOUNT_TEXT.nameHint;
    const close = () => {
      formError(inputs, null);
      form.hidden = true;
      open.hidden = false;
      open.focus();
    };
    open.addEventListener("click", () => {
      FIELDS.forEach(({ key }, at) => {
        const input = inputs[at];
        if (input !== void 0) {
          input.value = names[key] ?? "";
        }
      });
      form.hidden = false;
      open.hidden = true;
      inputs[0]?.focus();
    });
    cancel.addEventListener("click", close);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void (async () => {
        const [full, given, family] = inputs;
        say("");
        const submit = form.querySelector("button[type=submit]");
        if (submit instanceof HTMLButtonElement) {
          submit.disabled = true;
        }
        const answer = await call("POST", `${base}/profile`, {
          name: full?.value ?? "",
          given_name: given?.value ?? "",
          family_name: family?.value ?? ""
        });
        if (submit instanceof HTMLButtonElement) {
          submit.disabled = false;
        }
        const saved = answer.ok ? readSavedNames(answer.body) : null;
        if (saved !== null) {
          names = saved;
          showNames(saved);
          close();
          say(ACCOUNT_TEXT.nameSaved);
          return;
        }
        if (profileRefused(answer.status, answer.body)) {
          formError(inputs, ACCOUNT_TEXT.nameRejected);
          return;
        }
        if (changeRefusal(answer.status, answer.body) === "signed-out") {
          followups.signedOut();
          return;
        }
        say(answer.ok ? ACCOUNT_TEXT.unreadable : refusalText(refusal(answer.status, answer.body, answer.retryAfter)));
      })();
    });
  }

  // src/brand-read.ts
  function text2(value) {
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
      name: text2(field(body, "name")),
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

  // src/account.ts
  var account = element("account", HTMLDivElement);
  var everywhere = element("everywhere", HTMLButtonElement);
  var confirm = element("everywhere-confirm", HTMLDivElement);
  var everywhereYes = element("everywhere-yes", HTMLButtonElement);
  var everywhereNo = element("everywhere-no", HTMLButtonElement);
  function signedOutBy(answer) {
    return answer.status === 401 && field(answer.body, "code") === "session_required";
  }
  function signedOut(text3) {
    account.hidden = true;
    element("sign-in", HTMLParagraphElement).hidden = false;
    say(text3);
    element("title", HTMLHeadingElement).focus();
  }
  function refused2(answer) {
    if (signedOutBy(answer)) {
      signedOut(ACCOUNT_TEXT.signedOut);
      return;
    }
    say(refusalText(refusal(answer.status, answer.body, answer.retryAfter)));
  }
  function row(main2, detail, action) {
    const item = document.createElement("li");
    const words = document.createElement("div");
    const title = document.createElement("p");
    title.className = "row-main";
    title.textContent = main2;
    const meta = document.createElement("p");
    meta.className = "row-detail";
    meta.textContent = detail;
    words.append(title, meta);
    item.append(words);
    if (action !== void 0) {
      item.append(action);
    }
    return item;
  }
  function button(label, name, onPress) {
    const pressed = document.createElement("button");
    pressed.type = "button";
    pressed.className = "secondary";
    pressed.textContent = label;
    pressed.setAttribute("aria-label", name);
    pressed.addEventListener("click", () => onPress(pressed));
    return pressed;
  }
  function fill(list, rows, empty) {
    if (rows.length === 0) {
      const none = document.createElement("li");
      none.className = "row-empty";
      none.textContent = empty;
      rows.push(none);
    }
    list.replaceChildren(...rows);
  }
  function showMe(base, me, followups) {
    element("email", HTMLElement).textContent = me.email;
    const verified = element("verified", HTMLSpanElement);
    verified.textContent = me.emailVerified ? ACCOUNT_TEXT.verified : ACCOUNT_TEXT.unverified;
    verified.dataset["state"] = me.emailVerified ? "ok" : "warn";
    element("method-password", HTMLElement).textContent = me.password ? ACCOUNT_TEXT.set : ACCOUNT_TEXT.notSet;
    element("method-totp", HTMLElement).textContent = me.totp ? ACCOUNT_TEXT.on : ACCOUNT_TEXT.off;
    element("method-recovery", HTMLElement).textContent = codesLeft(me.recoveryCodes);
    const due = element("enrol-due", HTMLParagraphElement);
    due.textContent = ACCOUNT_TEXT.enrolDue;
    due.hidden = !enrolmentDue(me);
    element("app-open", HTMLButtonElement).hidden = me.totp || me.twoFactor === "off";
    element("app-off", HTMLButtonElement).hidden = !me.totp;
    fill(
      element("passkeys", HTMLUListElement),
      me.passkeys.map((passkey) => {
        const added = when(passkey.createdAt);
        const remove = button("Remove", `Remove the passkey added ${added}`, (pressed) => {
          void removePasskey(base, passkey.id, pressed, followups);
        });
        return row(passkey.synced ? "Synced passkey" : "Passkey on one device", `Added ${added}`, remove);
      }),
      ACCOUNT_TEXT.noPasskeys
    );
  }
  function showSessions(base, sessions) {
    const ordered = [...sessions].sort((left, right) => Number(right.current) - Number(left.current));
    fill(
      element("sessions", HTMLUListElement),
      ordered.map((session) => {
        const detail = `Signed in ${when(session.signedInAt)}, last active ${when(session.lastSeenAt)}`;
        const main2 = describeMethods(session.methods);
        if (session.current) {
          return row(`${main2} (${ACCOUNT_TEXT.thisSession})`, detail);
        }
        const end = button("Sign out", `Sign out the session signed in ${when(session.signedInAt)}`, (pressed) => {
          void endSession(base, session.sid, pressed);
        });
        return row(main2, detail, end);
      }),
      ACCOUNT_TEXT.noSessions
    );
  }
  function showGrants(base, grants) {
    fill(
      element("grants", HTMLUListElement),
      grants.map((grant) => {
        const remove = button("Remove access", `Remove access for ${grant.clientId}`, (pressed) => {
          void revoke(base, grant.clientId, pressed);
        });
        const asks = grant.scopes.map(describeScope).join("; ");
        return row(grant.clientId, `Allowed ${when(grant.grantedAt)}${asks === "" ? "" : `: ${asks}`}`, remove);
      }),
      ACCOUNT_TEXT.noGrants
    );
  }
  async function endSession(base, sid, pressed) {
    pressed.disabled = true;
    const answer = await call("POST", `${base}/sessions/end`, { sid });
    if (!answer.ok) {
      pressed.disabled = false;
      refused2(answer);
      return;
    }
    say(ACCOUNT_TEXT.ended);
    await refreshSessions(base);
    element("sessions-title", HTMLHeadingElement).focus();
  }
  async function revoke(base, clientId, pressed) {
    pressed.disabled = true;
    const answer = await call("POST", `${base}/grants/revoke`, { client_id: clientId });
    if (!answer.ok) {
      pressed.disabled = false;
      refused2(answer);
      return;
    }
    const endBy = readEndBy(answer.body);
    const revoked = field(answer.body, "revoked") === true && endBy !== null;
    say(revoked ? ACCOUNT_TEXT.revoked(clientId, endBy) : ACCOUNT_TEXT.notRevoked);
    const listed = await call("GET", `${base}/grants`);
    const grants = listed.ok ? readGrants(listed.body) : null;
    if (grants === null) {
      refused2(listed);
      return;
    }
    showGrants(base, grants);
    element("grants-title", HTMLHeadingElement).focus();
  }
  async function refreshSessions(base) {
    const listed = await call("GET", `${base}/sessions`);
    const sessions = listed.ok ? readSessions(listed.body) : null;
    if (sessions === null) {
      refused2(listed);
      return;
    }
    showSessions(base, sessions);
  }
  async function refreshAccount(base, followups) {
    const answer = await call("GET", `${base}/me`);
    const me = answer.ok ? readMe(answer.body) : null;
    if (me === null) {
      refused2(answer);
      return;
    }
    showMe(base, me, followups);
    await refreshSessions(base);
  }
  async function signOutEverywhere(base) {
    everywhereYes.disabled = true;
    const answer = await call("POST", `${base}/sessions/end-all`, {});
    everywhereYes.disabled = false;
    if (!answer.ok) {
      refused2(answer);
      return;
    }
    signedOut(ACCOUNT_TEXT.everywhereDone);
  }
  async function main() {
    const base = accountApi(location.pathname);
    if (base === null) {
      say(ACCOUNT_TEXT.missing);
      return;
    }
    const [meAnswer, sessionsAnswer, grantsAnswer] = await Promise.all([
      call("GET", `${base}/me`),
      call("GET", `${base}/sessions`),
      call("GET", `${base}/grants`)
    ]);
    const failed = [meAnswer, sessionsAnswer, grantsAnswer].find((answer) => !answer.ok);
    if (failed !== void 0) {
      refused2(failed);
      return;
    }
    const me = readMe(meAnswer.body);
    const sessions = readSessions(sessionsAnswer.body);
    const grants = readGrants(grantsAnswer.body);
    if (me === null || sessions === null || grants === null) {
      say(ACCOUNT_TEXT.unreadable);
      return;
    }
    const followups = {
      changed: () => refreshAccount(base, followups),
      signedOut: () => signedOut(ACCOUNT_TEXT.signedOut)
    };
    showMe(base, me, followups);
    showNames(me.profile);
    showSessions(base, sessions);
    showGrants(base, grants);
    element("everywhere-warning", HTMLParagraphElement).textContent = ACCOUNT_TEXT.everywhereConfirm;
    everywhere.addEventListener("click", () => {
      confirm.hidden = false;
      everywhere.hidden = true;
      everywhereNo.focus();
    });
    everywhereNo.addEventListener("click", () => {
      confirm.hidden = true;
      everywhere.hidden = false;
      everywhere.focus();
    });
    everywhereYes.addEventListener("click", () => void signOutEverywhere(base));
    wirePassword(base, appAsked(me), followups);
    wireRecoveryCodes(base, followups);
    wireApp(base, followups);
    wireAppOff(base, followups);
    wirePasskeyAdd(base, followups);
    wireProfile(base, me.profile, followups);
    account.hidden = false;
    say("");
  }
  void showBrand();
  void main();
})();
