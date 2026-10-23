// The page a password-reset link opens. The link carries its token in the fragment, which reaches neither the
// server's logs nor a Referer; the page takes it out of the address before it sends anything, then asks for a new
// password. Only the password changes: the second factor and passkeys stay as they are.

import { passwordRuleText } from "./account-factors.ts";
import { showBrand } from "./brand.ts";
import { RESET_TEXT, refusalText } from "./copy.ts";
import { call, element, fieldError, say } from "./dom.ts";
import { completeOutcome, readResetToken, resetApi } from "./reset-read.ts";

const form = element("reset", HTMLFormElement);
const input = element("new-password", HTMLInputElement);

/** Disable or enable every button while the password is on its way, so a double press sends nothing twice. */
function busy(on: boolean): void {
  for (const button of document.querySelectorAll("button")) {
    button.disabled = on;
  }
}

/** Close the form and say `text`: the link has done what it can. */
function finish(text: string): void {
  form.hidden = true;
  say(text);
}

async function save(base: string, token: string): Promise<void> {
  const password = input.value;
  fieldError(input, password === "" ? RESET_TEXT.passwordRequired : null);
  if (password === "") {
    return;
  }
  busy(true);
  say(RESET_TEXT.saving);
  const answer = await call("POST", `${base}/reset/complete`, { token, password });
  busy(false);
  const outcome = completeOutcome(answer.status, answer.body, answer.retryAfter);
  switch (outcome.kind) {
    case "changed":
      input.value = "";
      finish(RESET_TEXT.changed);
      return;
    case "link":
      finish(RESET_TEXT.spentLink);
      return;
    case "password":
      say("");
      fieldError(input, passwordRuleText(outcome.why));
      return;
    default:
      say(refusalText(outcome));
  }
}

function main(): void {
  const token = readResetToken(location.hash);
  // Out of the address bar, the history and anything that later reads the location, before any request is made.
  history.replaceState(null, "", location.pathname);
  const base = resetApi(location.pathname);
  if (base === null || token === null) {
    say(RESET_TEXT.invalidLink);
    return;
  }
  element("new-password-hint", HTMLParagraphElement).textContent = RESET_TEXT.hint;
  const reveal = element("reveal", HTMLButtonElement);
  reveal.addEventListener("click", () => {
    const shown = input.type === "text";
    input.type = shown ? "password" : "text";
    reveal.setAttribute("aria-pressed", String(!shown));
    reveal.textContent = shown ? "Show" : "Hide";
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void save(base, token);
  });
  form.hidden = false;
  input.focus();
}

// A link opened on a tab that already shows this page changes only the fragment, which runs nothing: start again, so
// the new token is read and taken out of the address like the first.
window.addEventListener("hashchange", () => {
  location.reload();
});
main();
void showBrand("../assets/");
