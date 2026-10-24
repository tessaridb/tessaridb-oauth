// The account page's change of sign-in address: it needs a recent sign-in, mails a link to the new address and a
// cancellation to the current one, and takes effect a day later. The answer is the same whether or not another
// account uses the new address, so the page never says which.

import { offerSignIn, type Followups } from "./account-factors.ts";
import { ACCOUNT_TEXT, EMAIL_TEXT, refusalText } from "./copy.ts";
import { call, element, fieldError, say } from "./dom.ts";
import { askOutcome } from "./email-read.ts";

/** Wire the "Change your sign-in address" form. */
export function wireEmail(base: string, followups: Followups): void {
  const open = element("email-open", HTMLButtonElement);
  const form = element("email-form", HTMLFormElement);
  const input = element("new-email", HTMLInputElement);
  const cancel = element("email-cancel", HTMLButtonElement);
  element("new-email-hint", HTMLParagraphElement).textContent = EMAIL_TEXT.hint;
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
      const address = input.value.trim();
      if (address === "") {
        fieldError(input, EMAIL_TEXT.required);
        return;
      }
      const submit = form.querySelector("button[type=submit]");
      if (submit instanceof HTMLButtonElement) {
        submit.disabled = true;
      }
      say(EMAIL_TEXT.sending);
      const answer = await call("POST", `${base}/me/email`, { email: address });
      if (submit instanceof HTMLButtonElement) {
        submit.disabled = false;
      }
      const outcome = askOutcome(answer.status, answer.body, answer.retryAfter);
      switch (outcome.kind) {
        case "sent":
          close();
          say(EMAIL_TEXT.sent);
          return;
        case "same":
          say("");
          fieldError(input, EMAIL_TEXT.same);
          return;
        case "invalid":
          say("");
          fieldError(input, EMAIL_TEXT.invalid);
          return;
        case "reauthenticate":
          offerSignIn();
          say(ACCOUNT_TEXT.reauthenticate);
          return;
        case "unavailable":
          say(EMAIL_TEXT.unavailable);
          return;
        case "signed-out":
          followups.signedOut();
          return;
        default:
          say(refusalText(outcome));
      }
    })();
  });
}
