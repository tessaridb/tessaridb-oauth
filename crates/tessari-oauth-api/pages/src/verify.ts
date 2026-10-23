// The page a verification link opens. The link carries its token in the fragment, which reaches neither the server's
// logs nor a Referer; the page takes it out of the address before it sends anything, then confirms the address at
// once. There is nothing to fill in: opening the link is the proof that the user reads that mailbox.

import { showBrand } from "./brand.ts";
import { VERIFY_TEXT, refusalText } from "./copy.ts";
import { call, element, say } from "./dom.ts";
import { readVerifyToken, verifyApi, verifyOutcome } from "./verify-read.ts";

async function confirm(base: string, token: string): Promise<void> {
  say(VERIFY_TEXT.confirming);
  const answer = await call("POST", `${base}/verify`, { token });
  const outcome = verifyOutcome(answer.status, answer.body, answer.retryAfter);
  switch (outcome.kind) {
    case "verified":
      element("title", HTMLHeadingElement).textContent = VERIFY_TEXT.confirmed;
      say(VERIFY_TEXT.confirmedNote);
      return;
    case "link":
      say(VERIFY_TEXT.spentLink);
      return;
    default:
      say(refusalText(outcome));
  }
}

function main(): void {
  const token = readVerifyToken(location.hash);
  // Out of the address bar, the history and anything that later reads the location, before any request is made.
  history.replaceState(null, "", location.pathname);
  const base = verifyApi(location.pathname);
  if (base === null || token === null) {
    say(VERIFY_TEXT.invalidLink);
    return;
  }
  void confirm(base, token);
}

// A link opened on a tab that already shows this page changes only the fragment, which runs nothing: start again, so
// the new token is read and taken out of the address like the first.
window.addEventListener("hashchange", () => {
  location.reload();
});
main();
void showBrand("../assets/");
