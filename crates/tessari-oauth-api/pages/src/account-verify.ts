// The account page's request for a verification link: offered while the address the account signs in with is not
// verified, it mails one link there, and a newer request replaces the older link.

import type { Followups } from "./account-factors.ts";
import { VERIFY_TEXT, refusalText } from "./copy.ts";
import { call, element, say } from "./dom.ts";
import { sendOutcome } from "./verify-read.ts";

/** Wire the "Send a verification link" button. */
export function wireVerify(base: string, followups: Followups): void {
  const send = element("verify-send", HTMLButtonElement);
  send.addEventListener("click", () => {
    void (async () => {
      send.disabled = true;
      say(VERIFY_TEXT.sending);
      const answer = await call("POST", `${base}/me/verify`, {});
      send.disabled = false;
      const outcome = sendOutcome(answer.status, answer.body, answer.retryAfter);
      switch (outcome.kind) {
        case "sent":
          say(VERIFY_TEXT.sent);
          return;
        case "verified":
          say("");
          await followups.changed();
          return;
        case "unavailable":
          say(VERIFY_TEXT.unavailable);
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
