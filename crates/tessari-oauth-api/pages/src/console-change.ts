// What every view in the console shares when it asks the server for something: a reason the server records with a
// change, an Idempotency-Key per distinct body so a double press is one change, and what a refusal or an unreadable
// answer says. The server decides; these only ask.

import { readRefusal } from "./console-read.ts";
import { changeRefusalText, refusalText } from "./console-copy.ts";
import { type Screen, heading, labelled, make, show } from "./console-dom.ts";
import { type Answer, call, say } from "./dom.ts";
import { keyring, reasonOf } from "./users-change.ts";

/** A form's keyring: one key per distinct body sent. */
export function keys(): (body: Record<string, unknown>) => string {
  return keyring(() => crypto.randomUUID());
}

/**
 * Send the change `body` to `path` (POST unless `method` says PUT) under the key `keyFor` gives that path and body
 * together, so one form changing different records never sends two of them under one key.
 */
export function change(
  path: string,
  keyFor: (request: Record<string, unknown>) => string,
  body: Record<string, unknown>,
  method: "POST" | "PUT" = "POST",
): Promise<Answer> {
  return call(method, path, body, { "idempotency-key": keyFor({ ...body, "@path": path }) });
}

/**
 * The words for a refused change `answer`, from `words` for a refusal code and naming `what` when nothing was found;
 * null when the session has ended and `screen` signs out instead.
 */
export function refusedText(
  screen: Screen,
  answer: Answer,
  what: string,
  words: (code: string) => string = changeRefusalText,
): string | null {
  const refusal = readRefusal(answer.status, answer.body, answer.retryAfter);
  if (refusal.kind === "signed_out") {
    screen.signedOut();
    return null;
  }
  return refusal.kind === "refused" ? words(refusal.code) : refusalText(refusal, what);
}

/** The reason field of a change form. */
export function reasonField(id: string): { input: HTMLInputElement; row: HTMLDivElement } {
  const input = make("input", "");
  input.type = "text";
  input.required = true;
  input.maxLength = 500;
  input.autocomplete = "off";
  return { input, row: labelled(id, "Reason (recorded with the change)", input) };
}

/** The reason typed into `input`, or null after saying what is missing in `notice`. */
export function reasonIn(input: HTMLInputElement, notice: HTMLParagraphElement): string | null {
  const reason = reasonOf(input.value);
  if (reason === null) {
    notice.textContent = changeRefusalText("reason_required");
    notice.hidden = false;
    input.setAttribute("aria-invalid", "true");
    input.focus();
    return null;
  }
  input.removeAttribute("aria-invalid");
  return reason;
}

/** A notice paragraph, hidden until it has something to say. */
export function notice(): HTMLParagraphElement {
  const made = make("p", "notice");
  made.setAttribute("role", "alert");
  made.hidden = true;
  return made;
}

/** Draw `answer`'s refusal on `screen`, or hand over to signing in when the session has ended. */
export function refusedOn(screen: Screen, title: string, answer: Answer, what: string): void {
  const refusal = readRefusal(answer.status, answer.body, answer.retryAfter);
  if (refusal.kind === "signed_out") {
    screen.signedOut();
    return;
  }
  show(screen.view, heading(title), make("p", "notice", refusalText(refusal, what)));
  say("");
}

/** Say on `screen` that the server answered in a shape the console cannot read. */
export function unreadable(screen: Screen, title: string): void {
  show(screen.view, heading(title), make("p", "notice", "The server answered in a shape the console cannot read."));
  say("");
}
