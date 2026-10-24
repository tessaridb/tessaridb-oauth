// The account page's changes to how the account signs in: a new password, and a new set of recovery codes shown
// once. Each needs a recent sign-in; the server says when one is missing and the page explains what to do.

import { type ChangeRefusal, changeRefusal, readIssuedCodes } from "./account-read.ts";
import { ACCOUNT_TEXT, refusalText } from "./copy.ts";
import { type Answer, call, element, fieldError, say } from "./dom.ts";
import { refusal } from "./flow.ts";

/** What the page does after a change ended the user's other sessions, and when the session itself is gone. */
export interface Followups {
  changed: () => Promise<void>;
  signedOut: () => void;
}

/** Offer the sign-in that a change needing a recent one asks for. */
export function offerSignIn(): void {
  element("sign-in", HTMLParagraphElement).hidden = false;
}

/** The page's words for a refused change, or null when the refusal is the field's own (shown beside it). */
function refusedText(why: ChangeRefusal, answer: Answer): string | null {
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

export function passwordRuleText(why: ChangeRefusal): string {
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

/** Wire the password form for an account that `holdsApp` (which allows a shorter password). */
export function wirePassword(base: string, holdsApp: boolean, followups: Followups): void {
  const open = element("password-open", HTMLButtonElement);
  const form = element("password-form", HTMLFormElement);
  const input = element("new-password", HTMLInputElement);
  const cancel = element("password-cancel", HTMLButtonElement);
  // The account the new password belongs to, for a password manager saving it.
  element("password-username", HTMLInputElement).value = element("email", HTMLElement).textContent ?? "";
  element("new-password-hint", HTMLParagraphElement).textContent = holdsApp
    ? ACCOUNT_TEXT.passwordHintWithApp
    : ACCOUNT_TEXT.passwordHintAlone;
  const close = (): void => {
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
      const text = refusedText(why, answer);
      if (text === null) {
        fieldError(input, passwordRuleText(why));
      } else {
        say(text);
      }
    })();
  });
}

/** Wire the recovery codes: confirm, issue, show once, and forget them from the page once saved. */
export function wireRecoveryCodes(base: string, followups: Followups): void {
  const open = element("codes-open", HTMLButtonElement);
  const confirm = element("codes-confirm", HTMLDivElement);
  const yes = element("codes-yes", HTMLButtonElement);
  const no = element("codes-no", HTMLButtonElement);
  const shown = element("codes-shown", HTMLDivElement);
  const list = element("codes", HTMLUListElement);
  const saved = element("codes-saved", HTMLButtonElement);
  open.addEventListener("click", () => {
    confirm.hidden = false;
    open.hidden = true;
    no.focus();
  });
  no.addEventListener("click", () => {
    confirm.hidden = true;
    open.hidden = false;
    open.focus();
  });
  yes.addEventListener("click", () => {
    void (async () => {
      yes.disabled = true;
      const answer = await call("POST", `${base}/recovery-codes`, {});
      yes.disabled = false;
      const codes = answer.ok ? readIssuedCodes(answer.body) : null;
      if (codes === null) {
        const why = changeRefusal(answer.status, answer.body);
        if (why === "signed-out") {
          followups.signedOut();
          return;
        }
        say(refusedText(why, answer) ?? ACCOUNT_TEXT.unreadable);
        return;
      }
      list.replaceChildren(
        ...codes.map((code) => {
          const item = document.createElement("li");
          const text = document.createElement("code");
          text.textContent = code;
          item.append(text);
          return item;
        }),
      );
      confirm.hidden = true;
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
