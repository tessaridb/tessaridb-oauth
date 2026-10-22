// What the user changes decide, kept apart from the document: the reason every change carries, and what each change
// answered. An enrolment code is kept only from the one answer the server marks as showing it.

import { field } from "./flow.ts";

/** The most characters a reason may have, as the server counts them. */
const REASON_MAX_CHARS = 500;

/** `typed` trimmed when it is a reason the server accepts (1 to 500 characters), else null. */
export function reasonOf(typed: string): string | null {
  const reason = typed.trim();
  const length = [...reason].length;
  return length >= 1 && length <= REASON_MAX_CHARS ? reason : null;
}

/** A natural number field of `body`, or null. */
function count(body: unknown, key: string): number | null {
  const value = field(body, key);
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/** An account opened: its id and its address, masked as given. */
export function readOpened(body: unknown): { user: string; email: string } | null {
  const user = field(body, "user");
  const email = field(body, "email");
  return typeof user === "string" && user !== "" && typeof email === "string" ? { user, email } : null;
}

/** What ended with a disabled account, and when the access tokens it already holds stop working. */
export function readDisabled(body: unknown): { sessions: number; families: number; accessTokensEndBy: number } | null {
  const sessions = count(body, "sessions");
  const families = count(body, "families");
  const accessTokensEndBy = count(body, "access_tokens_end_by");
  if (sessions === null || families === null || accessTokensEndBy === null) {
    return null;
  }
  return { sessions, families, accessTokensEndBy };
}

/** An address shown whole. */
export function readRevealed(body: unknown): { email: string } | null {
  const email = field(body, "email");
  return typeof email === "string" && email !== "" ? { email } : null;
}

/** An enrolment code, only from the answer that shows it, and how many hours it enrols for. */
export function readIssued(body: unknown): { code: string; validHours: number } | null {
  const code = field(body, "code");
  const validSecs = count(body, "valid_secs");
  if (field(body, "shown_once") !== true || typeof code !== "string" || code === "" || validSecs === null) {
    return null;
  }
  return { code, validHours: Math.floor(validSecs / 3600) };
}

/**
 * A source of Idempotency-Keys for one form: the same key while the same body is sent again (a double press, a retry
 * after a lost answer), a new one from `fresh` as soon as what is sent changes, because the server answers a key with
 * what it answered the first time and refuses it with a different body.
 */
export function keyring(fresh: () => string): (body: Record<string, unknown>) => string {
  let last: { sent: string; key: string } | null = null;
  return (body) => {
    const sent = JSON.stringify(body);
    if (last === null || last.sent !== sent) {
      last = { sent, key: fresh() };
    }
    return last.key;
  };
}
