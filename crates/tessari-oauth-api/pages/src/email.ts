// The page the two mails of an address change open. Each link carries its token in the fragment, which reaches
// neither the server's logs nor a Referer; the page takes it out of the address before it sends anything. The new
// address's link confirms at once, since opening it is the proof that the user reads that mailbox. The old address's
// link cancels only when the user says so, so that a mail filter which opens links cannot cancel a change for them.

import { showBrand } from "./brand.ts";
import { EMAIL_TEXT, refusalText } from "./copy.ts";
import { call, element, say } from "./dom.ts";
import { cancelOutcome, confirmOutcome, emailApi, readEmailLink } from "./email-read.ts";

function title(text: string): void {
  element("title", HTMLHeadingElement).textContent = text;
}

async function confirm(base: string, token: string): Promise<void> {
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

function offerCancel(base: string, token: string): void {
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

function main(): void {
  const link = readEmailLink(location.hash);
  // Out of the address bar, the history and anything that later reads the location, before any request is made.
  history.replaceState(null, "", location.pathname);
  const base = emailApi(location.pathname);
  if (base === null || link === null) {
    say(EMAIL_TEXT.invalidLink);
    return;
  }
  if (link.kind === "confirm") {
    void confirm(base, link.token);
  } else {
    offerCancel(base, link.token);
  }
}

// A link opened on a tab that already shows this page changes only the fragment, which runs nothing: start again, so
// the new token is read and taken out of the address like the first.
window.addEventListener("hashchange", () => {
  location.reload();
});
main();
void showBrand("../assets/");
