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
    notRevoked: "That access was already removed."
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
  function say(text2) {
    element("status", HTMLParagraphElement).textContent = text2;
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
    account.hidden = false;
    say("");
  }
  void main();
})();
