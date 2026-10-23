// The page an enrolment link opens. An operator had the link mailed to a new account's address; the link carries its
// code in the fragment, which reaches neither the server's logs nor a Referer. The page takes the code out of the
// address before it sends anything, then asks for the account's first password.

import { passwordRuleText } from "./account-factors.ts";
import { showBrand } from "./brand.ts";
import { ENROL_TEXT, refusalText } from "./copy.ts";
import { call, element, fieldError, say } from "./dom.ts";
import { enrolApi, enrolOutcome, readEnrolCode } from "./enrol-read.ts";

const form = element("enrol", HTMLFormElement);
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

async function save(base: string, code: string): Promise<void> {
  const password = input.value;
  fieldError(input, password === "" ? ENROL_TEXT.passwordRequired : null);
  if (password === "") {
    return;
  }
  busy(true);
  say(ENROL_TEXT.saving);
  const answer = await call("POST", `${base}/enroll`, { code, password });
  busy(false);
  const outcome = enrolOutcome(answer.status, answer.body, answer.retryAfter);
  switch (outcome.kind) {
    case "set":
      input.value = "";
      finish(ENROL_TEXT.set);
      return;
    case "link":
      finish(ENROL_TEXT.spentLink);
      return;
    case "already":
      finish(ENROL_TEXT.already);
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
  const code = readEnrolCode(location.hash);
  // Out of the address bar, the history and anything that later reads the location, before any request is made.
  history.replaceState(null, "", location.pathname);
  const base = enrolApi(location.pathname);
  if (base === null || code === null) {
    say(ENROL_TEXT.invalidLink);
    return;
  }
  element("new-password-hint", HTMLParagraphElement).textContent = ENROL_TEXT.hint;
  const reveal = element("reveal", HTMLButtonElement);
  reveal.addEventListener("click", () => {
    const shown = input.type === "text";
    input.type = shown ? "password" : "text";
    reveal.setAttribute("aria-pressed", String(!shown));
    reveal.textContent = shown ? "Show" : "Hide";
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void save(base, code);
  });
  form.hidden = false;
  input.focus();
}

// A link opened on a tab that already shows this page changes only the fragment, which runs nothing: start again, so
// the new code is read and taken out of the address like the first.
window.addEventListener("hashchange", () => {
  location.reload();
});
main();
void showBrand("../assets/");
