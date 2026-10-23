// The account page's names: the full, given and family name the account keeps, which applications allowed to see
// the user's name read from UserInfo. All three are sent and replaced together; an empty field clears its name.

import { type Names, changeRefusal, profileRefused, readSavedNames } from "./account-read.ts";
import type { Followups } from "./account-factors.ts";
import { ACCOUNT_TEXT, refusalText } from "./copy.ts";
import { call, element, say } from "./dom.ts";
import { refusal } from "./flow.ts";

const FIELDS = [
  { id: "name-full", key: "name" },
  { id: "name-given", key: "givenName" },
  { id: "name-family", key: "familyName" },
] as const;

/** Show the names the account keeps, each "Not set" until the user sets it. */
export function showNames(names: Names): void {
  for (const { id, key } of FIELDS) {
    element(`${id}-shown`, HTMLElement).textContent = names[key] ?? ACCOUNT_TEXT.notSet;
  }
}

/** Show `text` as the form's error, beside the fields and announced with them, or clear it when null. */
function formError(inputs: HTMLInputElement[], text: string | null): void {
  const error = element("names-error", HTMLParagraphElement);
  error.textContent = text ?? "";
  error.hidden = text === null;
  for (const input of inputs) {
    if (text === null) {
      input.removeAttribute("aria-invalid");
    } else {
      input.setAttribute("aria-invalid", "true");
    }
  }
  if (text !== null) {
    inputs[0]?.focus();
  }
}

/** Wire the names form, opened on the names the account keeps now. */
export function wireProfile(base: string, kept: Names, followups: Followups): void {
  let names = kept;
  const open = element("names-open", HTMLButtonElement);
  const form = element("names-form", HTMLFormElement);
  const cancel = element("names-cancel", HTMLButtonElement);
  const inputs = FIELDS.map(({ id }) => element(id, HTMLInputElement));
  element("names-hint", HTMLParagraphElement).textContent = ACCOUNT_TEXT.nameHint;
  const close = (): void => {
    formError(inputs, null);
    form.hidden = true;
    open.hidden = false;
    open.focus();
  };
  open.addEventListener("click", () => {
    FIELDS.forEach(({ key }, at) => {
      const input = inputs[at];
      if (input !== undefined) {
        input.value = names[key] ?? "";
      }
    });
    form.hidden = false;
    open.hidden = true;
    inputs[0]?.focus();
  });
  cancel.addEventListener("click", close);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void (async () => {
      const [full, given, family] = inputs;
      // An earlier outcome would stand beside this one's error.
      say("");
      const submit = form.querySelector("button[type=submit]");
      if (submit instanceof HTMLButtonElement) {
        submit.disabled = true;
      }
      const answer = await call("POST", `${base}/profile`, {
        name: full?.value ?? "",
        given_name: given?.value ?? "",
        family_name: family?.value ?? "",
      });
      if (submit instanceof HTMLButtonElement) {
        submit.disabled = false;
      }
      const saved = answer.ok ? readSavedNames(answer.body) : null;
      if (saved !== null) {
        names = saved;
        showNames(saved);
        close();
        say(ACCOUNT_TEXT.nameSaved);
        return;
      }
      if (profileRefused(answer.status, answer.body)) {
        formError(inputs, ACCOUNT_TEXT.nameRejected);
        return;
      }
      if (changeRefusal(answer.status, answer.body) === "signed-out") {
        followups.signedOut();
        return;
      }
      say(answer.ok ? ACCOUNT_TEXT.unreadable : refusalText(refusal(answer.status, answer.body, answer.retryAfter)));
    })();
  });
}
