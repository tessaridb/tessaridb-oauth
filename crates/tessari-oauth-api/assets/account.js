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
      const seconds2 = retryAfter !== null && /^\d+$/.test(retryAfter) ? Number(retryAfter) : null;
      return { kind: "throttled", seconds: seconds2 };
    }
    return { kind: "retry" };
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
    if (email === null || emailVerified === null || password === null || totp === null || recoveryCodes === null || passkeys === null) {
      return null;
    }
    return { email, emailVerified, password, totp, recoveryCodes, passkeys };
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
  function refusalText(refused2) {
    switch (refused2.kind) {
      case "rejected":
        return "That didn't match. Check it and try again.";
      case "expired":
        return "This sign-in has expired. Go back to the application and start again.";
      case "throttled":
        return refused2.seconds === null ? "Too many attempts. Wait a moment, then try again." : `Too many attempts. Try again in ${inSeconds(refused2.seconds)}.`;
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
    signedOut: "You're not signed in here. Sign in to an application that uses this account, then come back.",
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
    reauthenticate: "Changing how you sign in needs a sign-in from the last ten minutes. Sign in again through an application, then come back.",
    passwordHintAlone: "At least 15 characters. A few unrelated words work well.",
    passwordHintWithApp: "At least 8 characters, since you also use an authenticator app.",
    passwordRequired: "Enter a new password.",
    passwordTooShort: "That password is too short for this account.",
    passwordTooLong: "That password is too long. Use 64 characters or fewer.",
    passwordNotPrintable: "That password has a character that can't be typed. Remove it and try again.",
    passwordGuessable: "That password is too easy to guess. Don't use your email address.",
    passwordRejected: "That password can't be used. Choose a longer one that isn't your email address.",
    passwordChanged: "Password changed. You were signed out on your other devices.",
    codesIssued: "New recovery codes are ready. Your old ones no longer work."
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
  function fieldError(input, text2) {
    const error = element(`${input.id}-error`, HTMLParagraphElement);
    error.textContent = text2 ?? "";
    error.hidden = text2 === null;
    if (text2 === null) {
      input.removeAttribute("aria-invalid");
    } else {
      input.setAttribute("aria-invalid", "true");
      input.focus();
    }
  }
  function say(text2) {
    element("status", HTMLParagraphElement).textContent = text2;
  }

  // src/account-factors.ts
  function refusedText(why, answer) {
    switch (why) {
      case "reauthenticate":
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
        const text2 = refusedText(why, answer);
        if (text2 === null) {
          fieldError(input, passwordRuleText(why));
        } else {
          say(text2);
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
            const text2 = document.createElement("code");
            text2.textContent = code;
            item.append(text2);
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

  // src/account.ts
  var account = element("account", HTMLDivElement);
  var everywhere = element("everywhere", HTMLButtonElement);
  var confirm = element("everywhere-confirm", HTMLDivElement);
  var everywhereYes = element("everywhere-yes", HTMLButtonElement);
  var everywhereNo = element("everywhere-no", HTMLButtonElement);
  function signedOutBy(answer) {
    return answer.status === 401 && field(answer.body, "code") === "session_required";
  }
  function signedOut(text2) {
    account.hidden = true;
    say(text2);
    element("title", HTMLHeadingElement).focus();
  }
  function refused(answer) {
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
  function showMe(me) {
    element("email", HTMLElement).textContent = me.email;
    const verified = element("verified", HTMLSpanElement);
    verified.textContent = me.emailVerified ? ACCOUNT_TEXT.verified : ACCOUNT_TEXT.unverified;
    verified.dataset["state"] = me.emailVerified ? "ok" : "warn";
    element("method-password", HTMLElement).textContent = me.password ? ACCOUNT_TEXT.set : ACCOUNT_TEXT.notSet;
    element("method-totp", HTMLElement).textContent = me.totp ? ACCOUNT_TEXT.on : ACCOUNT_TEXT.off;
    element("method-recovery", HTMLElement).textContent = codesLeft(me.recoveryCodes);
    fill(
      element("passkeys", HTMLUListElement),
      me.passkeys.map(
        (passkey) => row(passkey.synced ? "Synced passkey" : "Passkey on one device", `Added ${when(passkey.createdAt)}`)
      ),
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
      refused(answer);
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
      refused(answer);
      return;
    }
    const endBy = readEndBy(answer.body);
    const revoked = field(answer.body, "revoked") === true && endBy !== null;
    say(revoked ? ACCOUNT_TEXT.revoked(clientId, endBy) : ACCOUNT_TEXT.notRevoked);
    const listed = await call("GET", `${base}/grants`);
    const grants = listed.ok ? readGrants(listed.body) : null;
    if (grants === null) {
      refused(listed);
      return;
    }
    showGrants(base, grants);
    element("grants-title", HTMLHeadingElement).focus();
  }
  async function refreshSessions(base) {
    const listed = await call("GET", `${base}/sessions`);
    const sessions = listed.ok ? readSessions(listed.body) : null;
    if (sessions === null) {
      refused(listed);
      return;
    }
    showSessions(base, sessions);
  }
  async function refreshAccount(base) {
    const answer = await call("GET", `${base}/me`);
    const me = answer.ok ? readMe(answer.body) : null;
    if (me === null) {
      refused(answer);
      return;
    }
    showMe(me);
    await refreshSessions(base);
  }
  async function signOutEverywhere(base) {
    everywhereYes.disabled = true;
    const answer = await call("POST", `${base}/sessions/end-all`, {});
    everywhereYes.disabled = false;
    if (!answer.ok) {
      refused(answer);
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
      refused(failed);
      return;
    }
    const me = readMe(meAnswer.body);
    const sessions = readSessions(sessionsAnswer.body);
    const grants = readGrants(grantsAnswer.body);
    if (me === null || sessions === null || grants === null) {
      say(ACCOUNT_TEXT.unreadable);
      return;
    }
    showMe(me);
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
    const followups = {
      changed: () => refreshAccount(base),
      signedOut: () => signedOut(ACCOUNT_TEXT.signedOut)
    };
    wirePassword(base, me.totp, followups);
    wireRecoveryCodes(base, followups);
    account.hidden = false;
    say("");
  }
  void main();
})();
