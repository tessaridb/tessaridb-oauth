// The account page. It asks the account API who is signed in, how the account signs in, where it is signed in and
// which applications hold access, and lets the user end a session, sign out everywhere or take an application's
// access back. Without a session it says how to get one; nothing is shown that the API did not answer.

import {
  type ListedGrant,
  type ListedSession,
  type Me,
  accountApi,
  appAsked,
  enrolmentDue,
  readEndBy,
  readGrants,
  readMe,
  readSessions,
} from "./account-read.ts";
import { removePasskey, wireApp, wireAppOff, wirePasskeyAdd } from "./account-enrol.ts";
import { type Followups, wirePassword, wireRecoveryCodes } from "./account-factors.ts";
import { showBrand } from "./brand.ts";
import { ACCOUNT_TEXT, codesLeft, describeMethods, describeScope, refusalText, when } from "./copy.ts";
import { type Answer, call, element, say } from "./dom.ts";
import { field, refusal } from "./flow.ts";

const account = element("account", HTMLDivElement);
const everywhere = element("everywhere", HTMLButtonElement);
const confirm = element("everywhere-confirm", HTMLDivElement);
const everywhereYes = element("everywhere-yes", HTMLButtonElement);
const everywhereNo = element("everywhere-no", HTMLButtonElement);

/** An answer that means the browser holds no session here. */
function signedOutBy(answer: Answer): boolean {
  return answer.status === 401 && field(answer.body, "code") === "session_required";
}

/** Show the signed-out state with `text`. */
function signedOut(text: string): void {
  account.hidden = true;
  element("sign-in", HTMLParagraphElement).hidden = false;
  say(text);
  element("title", HTMLHeadingElement).focus();
}

/** Say why `answer` was refused, or move to the signed-out state when it was for want of a session. */
function refused(answer: Answer): void {
  if (signedOutBy(answer)) {
    signedOut(ACCOUNT_TEXT.signedOut);
    return;
  }
  say(refusalText(refusal(answer.status, answer.body, answer.retryAfter)));
}

/** A list row: its main line, its detail line and, when given, its action. */
function row(main: string, detail: string, action?: HTMLButtonElement): HTMLLIElement {
  const item = document.createElement("li");
  const words = document.createElement("div");
  const title = document.createElement("p");
  title.className = "row-main";
  title.textContent = main;
  const meta = document.createElement("p");
  meta.className = "row-detail";
  meta.textContent = detail;
  words.append(title, meta);
  item.append(words);
  if (action !== undefined) {
    item.append(action);
  }
  return item;
}

function button(label: string, name: string, onPress: (pressed: HTMLButtonElement) => void): HTMLButtonElement {
  const pressed = document.createElement("button");
  pressed.type = "button";
  pressed.className = "secondary";
  pressed.textContent = label;
  pressed.setAttribute("aria-label", name);
  pressed.addEventListener("click", () => onPress(pressed));
  return pressed;
}

/** Fill `list` with `rows`, or with one row saying `empty` when there are none. */
function fill(list: HTMLUListElement, rows: HTMLLIElement[], empty: string): void {
  if (rows.length === 0) {
    const none = document.createElement("li");
    none.className = "row-empty";
    none.textContent = empty;
    rows.push(none);
  }
  list.replaceChildren(...rows);
}

/** Show the account; `followups` wires each passkey's removal. */
function showMe(base: string, me: Me, followups: Followups): void {
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
  // The app is offered where the policy uses one and none is held; a held app may always be turned off.
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
    ACCOUNT_TEXT.noPasskeys,
  );
}

function showSessions(base: string, sessions: ListedSession[]): void {
  const ordered = [...sessions].sort((left, right) => Number(right.current) - Number(left.current));
  fill(
    element("sessions", HTMLUListElement),
    ordered.map((session) => {
      const detail = `Signed in ${when(session.signedInAt)}, last active ${when(session.lastSeenAt)}`;
      const main = describeMethods(session.methods);
      if (session.current) {
        return row(`${main} (${ACCOUNT_TEXT.thisSession})`, detail);
      }
      const end = button("Sign out", `Sign out the session signed in ${when(session.signedInAt)}`, (pressed) => {
        void endSession(base, session.sid, pressed);
      });
      return row(main, detail, end);
    }),
    ACCOUNT_TEXT.noSessions,
  );
}

function showGrants(base: string, grants: ListedGrant[]): void {
  fill(
    element("grants", HTMLUListElement),
    grants.map((grant) => {
      const remove = button("Remove access", `Remove access for ${grant.clientId}`, (pressed) => {
        void revoke(base, grant.clientId, pressed);
      });
      const asks = grant.scopes.map(describeScope).join("; ");
      return row(grant.clientId, `Allowed ${when(grant.grantedAt)}${asks === "" ? "" : `: ${asks}`}`, remove);
    }),
    ACCOUNT_TEXT.noGrants,
  );
}

async function endSession(base: string, sid: string, pressed: HTMLButtonElement): Promise<void> {
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

async function revoke(base: string, clientId: string, pressed: HTMLButtonElement): Promise<void> {
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

async function refreshSessions(base: string): Promise<void> {
  const listed = await call("GET", `${base}/sessions`);
  const sessions = listed.ok ? readSessions(listed.body) : null;
  if (sessions === null) {
    refused(listed);
    return;
  }
  showSessions(base, sessions);
}

/** Show the account and the sessions again, after a change that ended other sessions or used up codes. */
async function refreshAccount(base: string, followups: Followups): Promise<void> {
  const answer = await call("GET", `${base}/me`);
  const me = answer.ok ? readMe(answer.body) : null;
  if (me === null) {
    refused(answer);
    return;
  }
  showMe(base, me, followups);
  await refreshSessions(base);
}

async function signOutEverywhere(base: string): Promise<void> {
  everywhereYes.disabled = true;
  const answer = await call("POST", `${base}/sessions/end-all`, {});
  everywhereYes.disabled = false;
  if (!answer.ok) {
    refused(answer);
    return;
  }
  signedOut(ACCOUNT_TEXT.everywhereDone);
}

async function main(): Promise<void> {
  const base = accountApi(location.pathname);
  if (base === null) {
    say(ACCOUNT_TEXT.missing);
    return;
  }
  const [meAnswer, sessionsAnswer, grantsAnswer] = await Promise.all([
    call("GET", `${base}/me`),
    call("GET", `${base}/sessions`),
    call("GET", `${base}/grants`),
  ]);
  const failed = [meAnswer, sessionsAnswer, grantsAnswer].find((answer) => !answer.ok);
  if (failed !== undefined) {
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
  const followups: Followups = {
    changed: () => refreshAccount(base, followups),
    signedOut: () => signedOut(ACCOUNT_TEXT.signedOut),
  };
  showMe(base, me, followups);
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
  account.hidden = false;
  say("");
}

void showBrand();
void main();
